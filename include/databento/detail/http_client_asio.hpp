#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "databento/detail/http_types.hpp"  // HttpError, HttpRange

namespace databento {
class ILogReceiver;
namespace detail {

// Type definitions for Asio backend
using HttpParams = std::multimap<std::string, std::string>;
using HttpHeaders = std::multimap<std::string, std::string>;
using ContentReceiver = std::function<bool(const char*, std::size_t)>;

// HTTP response data (Asio backend internal use)
struct HttpResponse {
  int status_code{0};
  HttpHeaders headers;
  std::string body;
};

// Result type for HTTP operations (Asio backend internal use)
struct HttpResult {
  std::optional<HttpResponse> response;
  HttpError error{HttpError::Success};

  explicit operator bool() const {
    return error == HttpError::Success && response.has_value();
  }
  HttpResponse& value() { return *response; }
  const HttpResponse& value() const { return *response; }
};

class HttpClient {
 public:
  HttpClient(ILogReceiver* log_receiver, const std::string& key,
             const std::string& gateway);
  HttpClient(ILogReceiver* log_receiver, const std::string& key,
             const std::string& gateway, std::uint16_t port);
  ~HttpClient();

  // Non-copyable, non-movable due to io_context
  HttpClient(const HttpClient&) = delete;
  HttpClient& operator=(const HttpClient&) = delete;
  HttpClient(HttpClient&&) = delete;
  HttpClient& operator=(HttpClient&&) = delete;

  nlohmann::json GetJson(const std::string& path, const HttpParams& params);
  nlohmann::json PostJson(const std::string& path,
                          const HttpParams& form_params);
  void GetRawStream(const std::string& path, const HttpHeaders& headers,
                    const ContentReceiver& callback);
  void PostRawStream(const std::string& path, const HttpParams& form_params,
                     const ContentReceiver& callback);

 private:
  using tcp = boost::asio::ip::tcp;
  using tcp_stream = boost::beast::tcp_stream;
  using ssl_stream = boost::beast::ssl_stream<tcp_stream>;

  // URL encode a single string
  static std::string UrlEncode(const std::string& str);

  // Encode parameters as query string or form data
  static std::string EncodeParams(const HttpParams& params);

  // Connect to the server
  void Connect();

  // Disconnect from the server
  void Disconnect();

  // Check if connected
  bool IsConnected() const;

  // Perform HTTP request and return response
  HttpResult DoRequest(boost::beast::http::verb method, const std::string& path,
                       const std::string& body, const std::string& content_type,
                       const HttpHeaders& extra_headers = {});

  // Perform streaming HTTP request
  void DoStreamRequest(boost::beast::http::verb method, const std::string& path,
                       const std::string& body, const std::string& content_type,
                       const HttpHeaders& extra_headers,
                       const ContentReceiver& callback);

  // Check response and parse JSON
  nlohmann::json CheckAndParseResponse(const std::string& path,
                                       HttpResult&& result) const;

  // Check for warnings in response headers
  void CheckWarnings(const HttpHeaders& headers) const;

  // Check if status code indicates an error
  static bool IsErrorStatus(int status_code);

  // Convert Beast error code to HttpError
  static HttpError ToHttpError(boost::beast::error_code ec);

  ILogReceiver* log_receiver_;
  std::string host_;
  std::string port_str_;
  std::string auth_header_;
  HttpHeaders default_headers_;
  std::chrono::seconds timeout_{100};
  bool use_ssl_{true};

  boost::asio::io_context io_context_;
  boost::asio::ssl::context ssl_context_;
  std::unique_ptr<ssl_stream> ssl_stream_;
  std::unique_ptr<tcp_stream> tcp_stream_;
  bool connected_{false};
};

}  // namespace detail
}  // namespace databento
