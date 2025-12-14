#pragma once

// Include common HTTP types
#include "databento/detail/http_types.hpp"

// Select HTTP backend based on compile-time configuration
#if defined(DATABENTO_HTTP_BACKEND_ASIO)
#include "databento/detail/http_client_asio.hpp"
#else
#include "databento/detail/http_client_httplib.hpp"
#endif
