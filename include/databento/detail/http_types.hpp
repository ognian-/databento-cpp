#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace databento::detail {

// Backend-agnostic HTTP error codes
// These map to httplib::Error values for compatibility
enum class HttpError : std::uint8_t {
  Success = 0,
  Unknown,
  Connection,
  BindIPAddress,
  Read,
  Write,
  ExceedRedirectCount,
  Canceled,
  SSLConnection,
  SSLLoadingCerts,
  SSLServerVerification,
  UnsupportedMultipartBoundaryChars,
  Compression,
  ConnectionTimeout,
  ProxyConnection,
};

// Convert HttpError to string for error messages
inline const char* ToString(HttpError error) {
  switch (error) {
    case HttpError::Success:
      return "Success";
    case HttpError::Unknown:
      return "Unknown";
    case HttpError::Connection:
      return "Connection";
    case HttpError::BindIPAddress:
      return "BindIPAddress";
    case HttpError::Read:
      return "Read";
    case HttpError::Write:
      return "Write";
    case HttpError::ExceedRedirectCount:
      return "ExceedRedirectCount";
    case HttpError::Canceled:
      return "Canceled";
    case HttpError::SSLConnection:
      return "SSLConnection";
    case HttpError::SSLLoadingCerts:
      return "SSLLoadingCerts";
    case HttpError::SSLServerVerification:
      return "SSLServerVerification";
    case HttpError::UnsupportedMultipartBoundaryChars:
      return "UnsupportedMultipartBoundaryChars";
    case HttpError::Compression:
      return "Compression";
    case HttpError::ConnectionTimeout:
      return "ConnectionTimeout";
    case HttpError::ProxyConnection:
      return "ProxyConnection";
  }
  return "Unknown";
}

// Range for partial content requests (HTTP Range header)
struct HttpRange {
  std::int64_t start{0};
  std::int64_t end{-1};  // -1 means to end of file
};

// Helper to build Range header value
inline std::pair<std::string, std::string> MakeRangeHeader(
    const HttpRange& range) {
  std::string value = "bytes=" + std::to_string(range.start) + "-";
  if (range.end >= 0) {
    value += std::to_string(range.end);
  }
  return {"Range", value};
}

}  // namespace databento::detail
