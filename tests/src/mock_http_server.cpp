#include "mock/mock_http_server.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <vector>

#include "databento/constants.hpp"
#include "databento/dbn.hpp"
#include "databento/dbn_encoder.hpp"
#include "databento/detail/buffer.hpp"
#include "databento/detail/zstd_stream.hpp"
#include "databento/file_stream.hpp"
#include "databento/record.hpp"

#ifdef DATABENTO_HTTP_BACKEND_ASIO
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
#endif

using databento::tests::mock::MockHttpServer;

// Common helper functions

std::string MockHttpServer::UrlDecode(const std::string& str) {
  std::string result;
  result.reserve(str.size());

  for (std::size_t i = 0; i < str.size(); ++i) {
    if (str[i] == '%' && i + 2 < str.size()) {
      int hex_val = 0;
      std::istringstream iss{str.substr(i + 1, 2)};
      iss >> std::hex >> hex_val;
      result += static_cast<char>(hex_val);
      i += 2;
    } else if (str[i] == '+') {
      result += ' ';
    } else {
      result += str[i];
    }
  }
  return result;
}

std::map<std::string, std::string> MockHttpServer::ParseQueryParams(const std::string& query) {
  std::map<std::string, std::string> params;
  if (query.empty()) {
    return params;
  }

  std::istringstream stream{query};
  std::string pair;
  while (std::getline(stream, pair, '&')) {
    auto eq_pos = pair.find('=');
    if (eq_pos != std::string::npos) {
      std::string key = UrlDecode(pair.substr(0, eq_pos));
      std::string value = UrlDecode(pair.substr(eq_pos + 1));
      params[key] = value;
    }
  }
  return params;
}

std::map<std::string, std::string> MockHttpServer::ParseFormParams(const std::string& body) {
  return ParseQueryParams(body);
}

void MockHttpServer::CheckParams(const std::map<std::string, std::string>& expected,
                                 const std::map<std::string, std::string>& actual) {
  for (const auto& [key, value] : expected) {
    auto it = actual.find(key);
    if (it == actual.end()) {
      EXPECT_NE(it, actual.end()) << "Missing param " << key;
    } else {
      EXPECT_EQ(it->second, value)
          << "Incorrect param value for " << key << ". Expected " << value << ", found "
          << it->second;
    }
  }
}

MockHttpServer::SharedConstBuffer MockHttpServer::EncodeToBuffer(const std::string& dbn_path) {
  detail::Buffer buffer{};
  InFileStream input_file{dbn_path};
  while (auto read_size = input_file.ReadSome(buffer.WriteBegin(), buffer.WriteCapacity())) {
    buffer.Fill(read_size);
    if (buffer.WriteCapacity() < 1024) {
      buffer.Reserve(buffer.Capacity() * 2);
    }
  }
  return std::make_shared<const databento::detail::Buffer>(std::move(buffer));
}

#ifdef DATABENTO_HTTP_BACKEND_ASIO
// ============================================================================
// Boost.Asio/Beast implementation
// ============================================================================

MockHttpServer::MockHttpServer(std::string api_key)
    : acceptor_{io_context_}, api_key_{std::move(api_key)} {
  // Bind to any available port. Use IPv4 any address.
  tcp::endpoint endpoint{tcp::v4(), 0};
  acceptor_.open(endpoint.protocol());
  acceptor_.set_option(net::socket_base::reuse_address(true));
  acceptor_.bind(endpoint);
  acceptor_.listen();
  port_ = static_cast<int>(acceptor_.local_endpoint().port());
}

MockHttpServer::~MockHttpServer() { Stop(); }

int MockHttpServer::ListenOnThread() {
  running_ = true;
  listen_thread_ = detail::ScopedThread{[this] { this->RunServer(); }};
  return port_;
}

void MockHttpServer::Stop() {
  if (!running_) {
    return;  // Already stopped
  }
  running_ = false;

  // Connect to ourselves to unblock the accept() call
  beast::error_code ec;
  try {
    net::io_context tmp_io;
    tcp::socket tmp_socket{tmp_io};
    tcp::endpoint endpoint{net::ip::address_v4::loopback(), static_cast<unsigned short>(port_)};
    tmp_socket.connect(endpoint, ec);
    // Don't care if it fails - the point is to unblock accept()
  } catch (...) {
    // Ignore
  }

  acceptor_.close(ec);
  io_context_.stop();
}

void MockHttpServer::RunServer() {
  while (running_) {
    beast::error_code ec;
    tcp::socket socket{io_context_};
    acceptor_.accept(socket, ec);
    if (ec) {
      if (ec == net::error::operation_aborted || !running_) {
        break;
      }
      continue;
    }
    if (!running_) {
      break;  // Stop was called
    }
    try {
      HandleConnection(std::move(socket));
    } catch (const std::exception&) {
      // Ignore exceptions in handler
    }
  }
}

void MockHttpServer::HandleConnection(tcp::socket socket) {
  beast::error_code ec;
  beast::flat_buffer buffer;

  // Set linger option to avoid TIME_WAIT on socket close
  socket.set_option(net::socket_base::linger(true, 0), ec);

  // Read the request
  http::request<http::string_body> req;
  http::read(socket, buffer, req, ec);
  if (ec) {
    return;
  }

  // Prepare response
  http::response<http::string_body> res;
  res.version(req.version());
  res.keep_alive(false);

  // Extract path and query string
  std::string target{req.target()};
  std::string path = target;
  std::string query_string;
  auto query_pos = target.find('?');
  if (query_pos != std::string::npos) {
    path = target.substr(0, query_pos);
    query_string = target.substr(query_pos + 1);
  }

  // Find matching route
  RouteHandler::Method method =
      (req.method() == http::verb::get) ? RouteHandler::Method::Get : RouteHandler::Method::Post;

  std::function<void(const http::request<http::string_body>&,
                     http::response<http::string_body>&)>
      handler;
  {
    std::lock_guard<std::mutex> lock{routes_mutex_};
    for (const auto& route : routes_) {
      if (route.method == method && route.path == path) {
        handler = route.handler;
        break;
      }
    }
  }

  if (handler) {
    handler(req, res);
  } else {
    res.result(http::status::not_found);
    res.body() = "Not found";
  }

  res.prepare_payload();
  res.set(http::field::connection, "close");
  http::write(socket, res, ec);

  // Gracefully shutdown the socket
  socket.shutdown(tcp::socket::shutdown_both, ec);
}

void MockHttpServer::MockBadPostRequest(const std::string& path, const nlohmann::json& json) {
  std::lock_guard<std::mutex> lock{routes_mutex_};
  routes_.push_back(
      {RouteHandler::Method::Post, path,
       [json](const http::request<http::string_body>&, http::response<http::string_body>& res) {
         res.result(http::status::bad_request);
         res.body() = json.dump();
         res.set(http::field::content_type, "application/json");
       }});
}

void MockHttpServer::MockGetJson(const std::string& path, const nlohmann::json& json) {
  MockGetJson(path, {}, json);
}

void MockHttpServer::MockGetJson(const std::string& path,
                                 const std::map<std::string, std::string>& params,
                                 const nlohmann::json& json) {
  MockGetJson(path, params, json, {});
}

void MockHttpServer::MockGetJson(const std::string& path,
                                 const std::map<std::string, std::string>& params,
                                 const nlohmann::json& json, const nlohmann::json& warnings) {
  std::lock_guard<std::mutex> lock{routes_mutex_};
  routes_.push_back(
      {RouteHandler::Method::Get, path,
       [json, params, warnings](const http::request<http::string_body>& req,
                                http::response<http::string_body>& res) {
         // Check authorization
         auto auth_it = req.find(http::field::authorization);
         if (auth_it == req.end()) {
           res.result(http::status::unauthorized);
           return;
         }

         // Parse and check query params
         std::string target{req.target()};
         std::string query_string;
         auto query_pos = target.find('?');
         if (query_pos != std::string::npos) {
           query_string = target.substr(query_pos + 1);
         }
         auto actual_params = ParseQueryParams(query_string);
         CheckParams(params, actual_params);

         // Set warnings header if provided
         if (!warnings.empty()) {
           res.set("X-Warning", warnings.dump());
         }

         res.result(http::status::ok);
         res.body() = json.dump();
         res.set(http::field::content_type, "application/json");
       }});
}

void MockHttpServer::MockPostJson(const std::string& path,
                                  const std::map<std::string, std::string>& form_params,
                                  const nlohmann::json& json) {
  std::lock_guard<std::mutex> lock{routes_mutex_};
  routes_.push_back(
      {RouteHandler::Method::Post, path,
       [json, form_params](const http::request<http::string_body>& req,
                           http::response<http::string_body>& res) {
         // Check authorization
         auto auth_it = req.find(http::field::authorization);
         if (auth_it == req.end()) {
           res.result(http::status::unauthorized);
           return;
         }

         // Parse and check form params
         auto actual_params = ParseFormParams(req.body());
         CheckParams(form_params, actual_params);

         res.result(http::status::ok);
         res.body() = json.dump();
         res.set(http::field::content_type, "application/json");
       }});
}

void MockHttpServer::MockPostDbn(const std::string& path,
                                 const std::map<std::string, std::string>& params,
                                 const std::string& dbn_path) {
  auto buffer = EncodeToBuffer(dbn_path);

  std::lock_guard<std::mutex> lock{routes_mutex_};
  routes_.push_back(
      {RouteHandler::Method::Post, path,
       [buffer, params](const http::request<http::string_body>& req,
                        http::response<http::string_body>& res) {
         // Check authorization
         auto auth_it = req.find(http::field::authorization);
         if (auth_it == req.end()) {
           res.result(http::status::unauthorized);
           return;
         }

         // Parse and check form params (from query string for POST with body)
         auto actual_params = ParseFormParams(req.body());
         CheckParams(params, actual_params);

         res.result(http::status::ok);
         res.set(http::field::content_type, "application/octet-stream");
         res.set(http::field::content_disposition, "attachment; filename=test.dbn.zst");
         res.body() = std::string{reinterpret_cast<const char*>(buffer->ReadBegin()),
                                  buffer->ReadCapacity()};
       }});
}

void MockHttpServer::MockPostDbn(const std::string& path,
                                 const std::map<std::string, std::string>& params, Record record,
                                 std::size_t count, std::size_t chunk_size) {
  MockPostDbn(path, params, record, count, 0, chunk_size);
}

void MockHttpServer::MockPostDbn(const std::string& path,
                                 const std::map<std::string, std::string>& params, Record record,
                                 std::size_t count, std::size_t extra_bytes,
                                 std::size_t chunk_size) {
  // Create buffer with encoded DBN data
  auto buffer = std::make_shared<detail::Buffer>();
  {
    detail::ZstdCompressStream zstd_stream{buffer.get()};
    DbnEncoder encoder{
        Metadata{
            kDbnVersion,
            ToString(Dataset::IfusImpact),
            {Schema::Mbp1},
        },
        &zstd_stream};
    for (std::size_t i = 0; i < count; ++i) {
      encoder.EncodeRecord(record);
    }
    if (extra_bytes > sizeof(RecordHeader)) {
      std::vector<std::byte> empty(extra_bytes - sizeof(RecordHeader));
      // write the header so it looks like the start of a valid record
      zstd_stream.WriteAll(reinterpret_cast<const std::byte*>(&record.Header()),
                           sizeof(RecordHeader));
      zstd_stream.WriteAll(empty.data(), empty.size());
    }
  }

  auto shared_buffer = std::make_shared<const detail::Buffer>(std::move(*buffer));

  std::lock_guard<std::mutex> lock{routes_mutex_};
  routes_.push_back(
      {RouteHandler::Method::Post, path,
       [shared_buffer, params](const http::request<http::string_body>& req,
                               http::response<http::string_body>& res) {
         // Check authorization
         auto auth_it = req.find(http::field::authorization);
         if (auth_it == req.end()) {
           res.result(http::status::unauthorized);
           return;
         }

         // Parse and check form params
         auto actual_params = ParseFormParams(req.body());
         CheckParams(params, actual_params);

         res.result(http::status::ok);
         res.set(http::field::content_type, "application/octet-stream");
         res.set(http::field::content_disposition, "attachment; filename=test.dbn.zst");
         res.body() = std::string{reinterpret_cast<const char*>(shared_buffer->ReadBegin()),
                                  shared_buffer->ReadCapacity()};
       }});
}

void MockHttpServer::MockGetDbnFile(const std::string& path, const std::string& dbn_path) {
  auto buffer = EncodeToBuffer(dbn_path);

  std::lock_guard<std::mutex> lock{routes_mutex_};
  routes_.push_back(
      {RouteHandler::Method::Get, path,
       [buffer](const http::request<http::string_body>& req,
                http::response<http::string_body>& res) {
         // Check authorization
         auto auth_it = req.find(http::field::authorization);
         if (auth_it == req.end()) {
           res.result(http::status::unauthorized);
           return;
         }

         // Check for Range header for resume support
         auto range_it = req.find(http::field::range);
         std::size_t start_offset = 0;
         if (range_it != req.end()) {
           std::string range_str{range_it->value()};
           // Parse "bytes=N-" format
           if (range_str.substr(0, 6) == "bytes=") {
             auto dash_pos = range_str.find('-', 6);
             if (dash_pos != std::string::npos) {
               start_offset = std::stoull(range_str.substr(6, dash_pos - 6));
             }
           }
         }

         const auto total_size = buffer->ReadCapacity();
         res.result(start_offset > 0 ? http::status::partial_content : http::status::ok);
         res.set(http::field::content_type, "application/octet-stream");

         if (start_offset < total_size) {
           const auto content_length = total_size - start_offset;
           res.body() = std::string{
               reinterpret_cast<const char*>(buffer->ReadBegin() + start_offset),
               content_length};
         }
       }});
}

#else
// ============================================================================
// cpp-httplib implementation
// ============================================================================

MockHttpServer::MockHttpServer(std::string api_key) : api_key_{std::move(api_key)} {}

MockHttpServer::~MockHttpServer() { server_.stop(); }

int MockHttpServer::ListenOnThread() {
  const auto port = server_.bind_to_any_port("localhost");
  listen_thread_ = detail::ScopedThread{[this] { server_.listen_after_bind(); }};
  return port;
}

void MockHttpServer::MockBadPostRequest(const std::string& path, const nlohmann::json& json) {
  server_.Post(path, [json](const httplib::Request& /*req*/, httplib::Response& res) {
    res.status = 400;
    res.body = json.dump();
    res.set_header("Content-Type", "application/json");
  });
}

void MockHttpServer::MockGetJson(const std::string& path, const nlohmann::json& json) {
  MockGetJson(path, {}, json);
}

void MockHttpServer::MockGetJson(const std::string& path,
                                 const std::map<std::string, std::string>& params,
                                 const nlohmann::json& json) {
  MockGetJson(path, params, json, {});
}

void MockHttpServer::MockGetJson(const std::string& path,
                                 const std::map<std::string, std::string>& params,
                                 const nlohmann::json& json, const nlohmann::json& warnings) {
  server_.Get(path, [json, params, warnings](const httplib::Request& req, httplib::Response& res) {
    if (!req.has_header("Authorization")) {
      res.status = 401;
      return;
    }
    // Convert httplib's multimap params to a map
    std::map<std::string, std::string> actual_params;
    for (const auto& [key, value] : req.params) {
      actual_params[key] = value;
    }
    CheckParams(params, actual_params);
    if (!warnings.empty()) {
      res.set_header("X-Warning", warnings.dump());
    }
    res.status = 200;
    res.body = json.dump();
    res.set_header("Content-Type", "application/json");
  });
}

void MockHttpServer::MockPostJson(const std::string& path,
                                  const std::map<std::string, std::string>& form_params,
                                  const nlohmann::json& json) {
  server_.Post(path, [json, form_params](const httplib::Request& req, httplib::Response& res) {
    if (!req.has_header("Authorization")) {
      res.status = 401;
      return;
    }
    auto actual_params = ParseFormParams(req.body);
    CheckParams(form_params, actual_params);
    res.status = 200;
    res.body = json.dump();
    res.set_header("Content-Type", "application/json");
  });
}

void MockHttpServer::MockPostDbn(const std::string& path,
                                 const std::map<std::string, std::string>& params,
                                 const std::string& dbn_path) {
  auto buffer = EncodeToBuffer(dbn_path);

  server_.Post(path, [buffer, params](const httplib::Request& req, httplib::Response& res) {
    if (!req.has_header("Authorization")) {
      res.status = 401;
      return;
    }
    auto actual_params = ParseFormParams(req.body);
    CheckParams(params, actual_params);
    res.status = 200;
    res.set_header("Content-Type", "application/octet-stream");
    res.set_header("Content-Disposition", "attachment; filename=test.dbn.zst");
    res.body = std::string{reinterpret_cast<const char*>(buffer->ReadBegin()),
                           buffer->ReadCapacity()};
  });
}

void MockHttpServer::MockPostDbn(const std::string& path,
                                 const std::map<std::string, std::string>& params, Record record,
                                 std::size_t count, std::size_t chunk_size) {
  MockPostDbn(path, params, record, count, 0, chunk_size);
}

void MockHttpServer::MockPostDbn(const std::string& path,
                                 const std::map<std::string, std::string>& params, Record record,
                                 std::size_t count, std::size_t extra_bytes,
                                 std::size_t chunk_size) {
  // Create buffer with encoded DBN data
  auto buffer = std::make_shared<detail::Buffer>();
  {
    detail::ZstdCompressStream zstd_stream{buffer.get()};
    DbnEncoder encoder{
        Metadata{
            kDbnVersion,
            ToString(Dataset::IfusImpact),
            {Schema::Mbp1},
        },
        &zstd_stream};
    for (std::size_t i = 0; i < count; ++i) {
      encoder.EncodeRecord(record);
    }
    if (extra_bytes > sizeof(RecordHeader)) {
      std::vector<std::byte> empty(extra_bytes - sizeof(RecordHeader));
      // write the header so it looks like the start of a valid record
      zstd_stream.WriteAll(reinterpret_cast<const std::byte*>(&record.Header()),
                           sizeof(RecordHeader));
      zstd_stream.WriteAll(empty.data(), empty.size());
    }
  }

  auto shared_buffer = std::make_shared<const detail::Buffer>(std::move(*buffer));

  server_.Post(path, [shared_buffer, params](const httplib::Request& req, httplib::Response& res) {
    if (!req.has_header("Authorization")) {
      res.status = 401;
      return;
    }
    auto actual_params = ParseFormParams(req.body);
    CheckParams(params, actual_params);
    res.status = 200;
    res.set_header("Content-Type", "application/octet-stream");
    res.set_header("Content-Disposition", "attachment; filename=test.dbn.zst");
    res.body = std::string{reinterpret_cast<const char*>(shared_buffer->ReadBegin()),
                           shared_buffer->ReadCapacity()};
  });
}

void MockHttpServer::MockGetDbnFile(const std::string& path, const std::string& dbn_path) {
  auto buffer = EncodeToBuffer(dbn_path);

  server_.Get(path, [buffer](const httplib::Request& req, httplib::Response& res) {
    if (!req.has_header("Authorization")) {
      res.status = 401;
      return;
    }

    // Check for Range header for resume support
    std::size_t start_offset = 0;
    if (req.has_header("Range")) {
      std::string range_str = req.get_header_value("Range");
      // Parse "bytes=N-" format
      if (range_str.substr(0, 6) == "bytes=") {
        auto dash_pos = range_str.find('-', 6);
        if (dash_pos != std::string::npos) {
          start_offset = std::stoull(range_str.substr(6, dash_pos - 6));
        }
      }
    }

    const auto total_size = buffer->ReadCapacity();

    if (start_offset >= total_size) {
      // Invalid range - return 416
      res.status = 416;
      res.set_header("Content-Range", "bytes */" + std::to_string(total_size));
      return;
    }

    res.status = start_offset > 0 ? 206 : 200;
    res.set_header("Content-Type", "application/octet-stream");

    const auto content_length = total_size - start_offset;
    res.set_header("Content-Length", std::to_string(content_length));

    if (start_offset > 0) {
      // Set Content-Range header for partial content
      res.set_header("Content-Range", "bytes " + std::to_string(start_offset) + "-" +
                                          std::to_string(total_size - 1) + "/" +
                                          std::to_string(total_size));
    }

    res.body = std::string{reinterpret_cast<const char*>(buffer->ReadBegin() + start_offset),
                           content_length};
  });
}

#endif  // DATABENTO_HTTP_BACKEND_ASIO
