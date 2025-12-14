#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "databento/detail/buffer.hpp"
#include "databento/detail/scoped_thread.hpp"
#include "databento/record.hpp"

#ifdef DATABENTO_HTTP_BACKEND_ASIO
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#else
#include <httplib.h>
#endif

namespace databento::tests::mock {

class MockHttpServer {
 public:
  explicit MockHttpServer(std::string api_key);
  MockHttpServer(MockHttpServer&&) = delete;
  MockHttpServer& operator=(MockHttpServer&&) = delete;
  MockHttpServer(const MockHttpServer&) = delete;
  MockHttpServer& operator=(const MockHttpServer&) = delete;
  ~MockHttpServer();

  int ListenOnThread();
  void MockBadPostRequest(const std::string& path, const nlohmann::json& json);
  void MockGetJson(const std::string& path, const nlohmann::json& json);
  void MockGetJson(const std::string& path,
                   const std::map<std::string, std::string>& params,
                   const nlohmann::json& json);
  void MockGetJson(const std::string& path,
                   const std::map<std::string, std::string>& params,
                   const nlohmann::json& json, const nlohmann::json& warnings);
  void MockPostJson(const std::string& path,
                    const std::map<std::string, std::string>& params,
                    const nlohmann::json& json);
  void MockPostDbn(const std::string& path,
                   const std::map<std::string, std::string>& params,
                   const std::string& dbn_path);
  void MockPostDbn(const std::string& path,
                   const std::map<std::string, std::string>& params, Record record,
                   std::size_t count, std::size_t chunk_size);
  void MockPostDbn(const std::string& path,
                   const std::map<std::string, std::string>& params, Record record,
                   std::size_t count, std::size_t extra_bytes, std::size_t chunk_size);
  void MockGetDbnFile(const std::string& path, const std::string& dbn_path);

 private:
  using SharedConstBuffer = std::shared_ptr<const detail::Buffer>;

  static std::string UrlDecode(const std::string& str);
  static std::map<std::string, std::string> ParseQueryParams(const std::string& query);
  static std::map<std::string, std::string> ParseFormParams(const std::string& body);
  static void CheckParams(const std::map<std::string, std::string>& expected,
                          const std::map<std::string, std::string>& actual);
  static SharedConstBuffer EncodeToBuffer(const std::string& dbn_path);

#ifdef DATABENTO_HTTP_BACKEND_ASIO
  using tcp = boost::asio::ip::tcp;

  struct RouteHandler {
    enum class Method { Get, Post };
    Method method;
    std::string path;
    std::function<void(const boost::beast::http::request<boost::beast::http::string_body>&,
                       boost::beast::http::response<boost::beast::http::string_body>&)>
        handler;
  };

  void RunServer();
  void HandleConnection(tcp::socket socket);
  void Stop();

  boost::asio::io_context io_context_;
  tcp::acceptor acceptor_;
  int port_{0};
  std::string api_key_;
  std::vector<RouteHandler> routes_;
  std::mutex routes_mutex_;
  detail::ScopedThread listen_thread_;
  std::atomic<bool> running_{false};
#else
  httplib::Server server_;
  std::string api_key_;
  detail::ScopedThread listen_thread_;
#endif
};

}  // namespace databento::tests::mock
