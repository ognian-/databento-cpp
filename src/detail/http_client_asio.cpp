#include "databento/detail/http_client_asio.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/version.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

#include "databento/constants.hpp"   // kUserAgent
#include "databento/exceptions.hpp"  // HttpResponseError, HttpRequestError, JsonResponseError
#include "databento/log.hpp"         // ILogReceiver, LogLevel

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;

using databento::detail::HttpClient;

namespace {
// Base64 encode for Basic auth
std::string Base64Encode(const std::string& input) {
  static const char kBase64Chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string result;
  result.reserve(((input.size() + 2) / 3) * 4);

  std::size_t i = 0;
  while (i < input.size()) {
    std::uint32_t octet_a = static_cast<unsigned char>(input[i++]);
    std::uint32_t octet_b = i < input.size() ? static_cast<unsigned char>(input[i++]) : 0;
    std::uint32_t octet_c = i < input.size() ? static_cast<unsigned char>(input[i++]) : 0;

    std::uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    result += kBase64Chars[(triple >> 18) & 0x3F];
    result += kBase64Chars[(triple >> 12) & 0x3F];
    result += (i > input.size() + 1) ? '=' : kBase64Chars[(triple >> 6) & 0x3F];
    result += (i > input.size()) ? '=' : kBase64Chars[triple & 0x3F];
  }

  return result;
}
}  // namespace

HttpClient::HttpClient(databento::ILogReceiver* log_receiver,
                       const std::string& key, const std::string& gateway)
    : HttpClient{log_receiver, key, gateway, 443} {}

HttpClient::HttpClient(databento::ILogReceiver* log_receiver,
                       const std::string& key, const std::string& gateway,
                       std::uint16_t port)
    : log_receiver_{log_receiver},
      host_{gateway},
      port_str_{std::to_string(port)},
      use_ssl_{port == 443},
      ssl_context_{ssl::context::tlsv12_client} {
  // Set up SSL context (even if not using SSL, to avoid issues)
  ssl_context_.set_default_verify_paths();
  ssl_context_.set_verify_mode(ssl::verify_peer);

  // Build Basic auth header
  auth_header_ = "Basic " + Base64Encode(key + ":");

  // Set default headers
  default_headers_.emplace("Accept", "application/json");
  default_headers_.emplace("User-Agent", kUserAgent);
}

HttpClient::~HttpClient() {
  if (connected_) {
    try {
      Disconnect();
    } catch (...) {
      // Ignore errors during destruction
    }
  }
}

std::string HttpClient::UrlEncode(const std::string& str) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (const char c : str) {
    // Keep alphanumeric and other safe characters
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ||
        c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << std::uppercase;
      escaped << '%' << std::setw(2)
              << static_cast<int>(static_cast<unsigned char>(c));
      escaped << std::nouppercase;
    }
  }

  return escaped.str();
}

std::string HttpClient::EncodeParams(const HttpParams& params) {
  std::ostringstream result;
  bool first = true;
  for (const auto& [key, value] : params) {
    if (!first) {
      result << '&';
    }
    first = false;
    result << UrlEncode(key) << '=' << UrlEncode(value);
  }
  return result.str();
}

void HttpClient::Connect() {
  if (connected_) {
    return;
  }

  beast::error_code ec;

  // Look up the domain name
  tcp::resolver resolver{io_context_};
  auto const results = resolver.resolve(host_, port_str_, ec);
  if (ec) {
    throw HttpRequestError{"resolve", ToHttpError(ec)};
  }

  if (use_ssl_) {
    // Create SSL stream
    ssl_stream_ = std::make_unique<ssl_stream>(io_context_, ssl_context_);

    // Set SNI hostname
    if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(), host_.c_str())) {
      ec = beast::error_code{static_cast<int>(::ERR_get_error()),
                             net::error::get_ssl_category()};
      throw HttpRequestError{"connect", ToHttpError(ec)};
    }

    // Set timeout and connect
    beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
    beast::get_lowest_layer(*ssl_stream_).connect(results, ec);
    if (ec) {
      throw HttpRequestError{"connect", ToHttpError(ec)};
    }

    // Perform SSL handshake
    beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
    ssl_stream_->handshake(ssl::stream_base::client, ec);
    if (ec) {
      throw HttpRequestError{"ssl_handshake", ToHttpError(ec)};
    }
  } else {
    // Create plain TCP stream
    tcp_stream_ = std::make_unique<tcp_stream>(io_context_);

    // Set timeout and connect
    tcp_stream_->expires_after(timeout_);
    tcp_stream_->connect(results, ec);
    if (ec) {
      throw HttpRequestError{"connect", ToHttpError(ec)};
    }
  }

  connected_ = true;
}

void HttpClient::Disconnect() {
  if (!connected_) {
    return;
  }

  beast::error_code ec;

  if (use_ssl_ && ssl_stream_) {
    // Set timeout for shutdown
    beast::get_lowest_layer(*ssl_stream_).expires_after(std::chrono::seconds{5});

    // Perform SSL shutdown
    ssl_stream_->shutdown(ec);

    // These errors are expected during shutdown
    if (ec && ec != net::error::eof && ec != ssl::error::stream_truncated &&
        ec != beast::error::timeout) {
      // Log but don't throw during disconnect
    }
    ssl_stream_.reset();
  } else if (tcp_stream_) {
    // Close TCP connection
    tcp_stream_->socket().shutdown(tcp::socket::shutdown_both, ec);
    tcp_stream_->close();
    tcp_stream_.reset();
  }

  connected_ = false;
}

bool HttpClient::IsConnected() const {
  if (!connected_) {
    return false;
  }
  return use_ssl_ ? (ssl_stream_ != nullptr) : (tcp_stream_ != nullptr);
}

databento::detail::HttpResult HttpClient::DoRequest(
    http::verb method, const std::string& path, const std::string& body,
    const std::string& content_type, const HttpHeaders& extra_headers) {
  // Ensure we're connected
  if (!IsConnected()) {
    Connect();
  }

  beast::error_code ec;

  // Set up request
  http::request<http::string_body> req{method, path, 11};
  req.set(http::field::host, host_);
  req.set(http::field::authorization, auth_header_);

  // Add default headers
  for (const auto& [key, value] : default_headers_) {
    req.set(key, value);
  }

  // Add extra headers
  for (const auto& [key, value] : extra_headers) {
    req.set(key, value);
  }

  // Set body if provided
  if (!body.empty()) {
    req.set(http::field::content_type, content_type);
    req.body() = body;
    req.prepare_payload();
  }

  // Receive buffer and response
  beast::flat_buffer buffer;
  http::response<http::string_body> res;

  if (use_ssl_) {
    beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
    http::write(*ssl_stream_, req, ec);
    if (ec) {
      Disconnect();
      throw HttpRequestError{path, ToHttpError(ec)};
    }

    beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
    http::read(*ssl_stream_, buffer, res, ec);
  } else {
    tcp_stream_->expires_after(timeout_);
    http::write(*tcp_stream_, req, ec);
    if (ec) {
      Disconnect();
      throw HttpRequestError{path, ToHttpError(ec)};
    }

    tcp_stream_->expires_after(timeout_);
    http::read(*tcp_stream_, buffer, res, ec);
  }

  if (ec) {
    Disconnect();
    throw HttpRequestError{path, ToHttpError(ec)};
  }

  // Check if server wants to close connection
  if (!res.keep_alive()) {
    Disconnect();
  }

  // Convert to HttpResult
  HttpResult result;
  result.error = HttpError::Success;
  result.response = HttpResponse{};
  result.response->status_code = static_cast<int>(res.result_int());
  result.response->body = std::move(res.body());

  // Copy headers
  for (const auto& field : res) {
    result.response->headers.emplace(std::string{field.name_string()},
                                     std::string{field.value()});
  }

  return result;
}

void HttpClient::DoStreamRequest(http::verb method, const std::string& path,
                                 const std::string& body,
                                 const std::string& content_type,
                                 const HttpHeaders& extra_headers,
                                 const ContentReceiver& callback) {
  // Ensure we're connected
  if (!IsConnected()) {
    Connect();
  }

  beast::error_code ec;

  // Set up request
  http::request<http::string_body> req{method, path, 11};
  req.set(http::field::host, host_);
  req.set(http::field::authorization, auth_header_);

  // Add default headers
  for (const auto& [key, value] : default_headers_) {
    req.set(key, value);
  }

  // Add extra headers
  for (const auto& [key, value] : extra_headers) {
    req.set(key, value);
  }

  // Set body if provided
  if (!body.empty()) {
    req.set(http::field::content_type, content_type);
    req.body() = body;
    req.prepare_payload();
  }

  // Read buffer and parser
  beast::flat_buffer buffer;
  http::response_parser<http::string_body> parser;
  parser.body_limit(boost::none);  // No body limit for streaming

  if (use_ssl_) {
    beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
    http::write(*ssl_stream_, req, ec);
    if (ec) {
      Disconnect();
      throw HttpRequestError{path, ToHttpError(ec)};
    }

    beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
    http::read_header(*ssl_stream_, buffer, parser, ec);
  } else {
    tcp_stream_->expires_after(timeout_);
    http::write(*tcp_stream_, req, ec);
    if (ec) {
      Disconnect();
      throw HttpRequestError{path, ToHttpError(ec)};
    }

    tcp_stream_->expires_after(timeout_);
    http::read_header(*tcp_stream_, buffer, parser, ec);
  }

  if (ec) {
    Disconnect();
    throw HttpRequestError{path, ToHttpError(ec)};
  }

  const auto& header = parser.get();
  const int status_code = static_cast<int>(header.result_int());

  // Check for error status
  if (IsErrorStatus(status_code)) {
    // Read the full body for error message
    if (use_ssl_) {
      http::read(*ssl_stream_, buffer, parser, ec);
    } else {
      http::read(*tcp_stream_, buffer, parser, ec);
    }
    if (ec && ec != http::error::need_buffer) {
      Disconnect();
      throw HttpRequestError{path, ToHttpError(ec)};
    }
    throw HttpResponseError{path, status_code, parser.get().body()};
  }

  // Check warnings
  HttpHeaders response_headers;
  for (const auto& field : header) {
    response_headers.emplace(std::string{field.name_string()},
                             std::string{field.value()});
  }
  CheckWarnings(response_headers);

  // Read body in chunks and call callback
  while (!parser.is_done()) {
    if (use_ssl_) {
      beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_);
      http::read_some(*ssl_stream_, buffer, parser, ec);
    } else {
      tcp_stream_->expires_after(timeout_);
      http::read_some(*tcp_stream_, buffer, parser, ec);
    }

    if (ec && ec != http::error::need_buffer) {
      if (ec == http::error::end_of_stream) {
        // Server closed connection, mark as disconnected
        Disconnect();
        break;
      }
      Disconnect();
      throw HttpRequestError{path, ToHttpError(ec)};
    }

    const auto& chunk = parser.get().body();
    if (!chunk.empty()) {
      if (!callback(chunk.data(), chunk.size())) {
        // User cancelled
        Disconnect();
        return;
      }
      // Clear the body for next chunk
      parser.get().body().clear();
    }
  }

  // Disconnect after streaming completes to ensure fresh connection for next request
  Disconnect();
}

nlohmann::json HttpClient::GetJson(const std::string& path,
                                   const HttpParams& params) {
  std::string target = path;
  if (!params.empty()) {
    target += '?' + EncodeParams(params);
  }

  auto result = DoRequest(http::verb::get, target, "", "");
  return CheckAndParseResponse(path, std::move(result));
}

nlohmann::json HttpClient::PostJson(const std::string& path,
                                    const HttpParams& form_params) {
  const std::string body = EncodeParams(form_params);
  auto result =
      DoRequest(http::verb::post, path, body, "application/x-www-form-urlencoded");
  return CheckAndParseResponse(path, std::move(result));
}

void HttpClient::GetRawStream(const std::string& path,
                              const HttpHeaders& headers,
                              const ContentReceiver& callback) {
  DoStreamRequest(http::verb::get, path, "", "", headers, callback);
}

void HttpClient::PostRawStream(const std::string& path,
                               const HttpParams& form_params,
                               const ContentReceiver& callback) {
  const std::string body = EncodeParams(form_params);
  DoStreamRequest(http::verb::post, path, body, "application/x-www-form-urlencoded",
                  {}, callback);
}

nlohmann::json HttpClient::CheckAndParseResponse(const std::string& path,
                                                 HttpResult&& result) const {
  if (result.error != HttpError::Success) {
    throw HttpRequestError{path, result.error};
  }

  auto& response = result.response.value();
  const int status_code = response.status_code;

  if (IsErrorStatus(status_code)) {
    throw HttpResponseError{path, status_code, std::move(response.body)};
  }

  CheckWarnings(response.headers);

  try {
    return nlohmann::json::parse(std::move(response.body));
  } catch (const nlohmann::json::parse_error& parse_err) {
    throw JsonResponseError::ParseError(path, parse_err);
  }
}

void HttpClient::CheckWarnings(const HttpHeaders& headers) const {
  // Look for X-Warning header (case-insensitive)
  std::string raw;
  for (const auto& [key, value] : headers) {
    if (key.size() == 9) {  // "X-Warning"
      bool match = true;
      const char* expected = "x-warning";
      for (std::size_t i = 0; i < 9; ++i) {
        if (std::tolower(static_cast<unsigned char>(key[i])) != expected[i]) {
          match = false;
          break;
        }
      }
      if (match) {
        raw = value;
        break;
      }
    }
  }

  if (!raw.empty()) {
    try {
      const auto json = nlohmann::json::parse(raw);
      if (json.is_array()) {
        for (const auto& warning_json : json.items()) {
          const std::string warning = warning_json.value();
          std::ostringstream msg;
          msg << "[HttpClient::CheckWarnings] Server " << warning;
          log_receiver_->Receive(LogLevel::Warning, msg.str());
        }
        return;
      }
    } catch (const std::exception& exc) {
      std::ostringstream msg;
      msg << "[HttpClient::CheckWarnings] Failed to parse warnings from HTTP "
             "header: "
          << exc.what() << ". Raw contents: " << raw;
      log_receiver_->Receive(LogLevel::Warning, msg.str());
      return;
    }
    std::ostringstream msg;
    msg << "[HttpClient::CheckWarnings] Failed to parse warnings from HTTP "
           "header. Raw contents: "
        << raw;
    log_receiver_->Receive(LogLevel::Warning, msg.str());
  }
}

bool HttpClient::IsErrorStatus(int status_code) { return status_code >= 400; }

databento::detail::HttpError HttpClient::ToHttpError(beast::error_code ec) {
  if (!ec) {
    return HttpError::Success;
  }

  // Check for specific error categories
  if (ec.category() == net::error::get_ssl_category()) {
    return HttpError::SSLConnection;
  }

  if (ec == net::error::connection_refused ||
      ec == net::error::host_unreachable ||
      ec == net::error::network_unreachable ||
      ec == net::error::connection_reset ||
      ec == net::error::broken_pipe) {
    return HttpError::Connection;
  }

  if (ec == net::error::timed_out || ec == beast::error::timeout) {
    return HttpError::ConnectionTimeout;
  }

  if (ec == net::error::operation_aborted) {
    return HttpError::Canceled;
  }

  if (ec == http::error::body_limit) {
    return HttpError::Read;
  }

  if (ec == net::error::eof || ec == http::error::end_of_stream) {
    return HttpError::Connection;
  }

  return HttpError::Unknown;
}
