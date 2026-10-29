/**
 * @file Protocol.hpp
 * @brief TrustTunnel HTTP/2 client/server factory 聚合入口。
 * @details 对外公开连接参数、认证 binding 与 typed factory；HTTP/2 session、wire writer、
 *          driver 和 stream transport 由 Detail owners 持有。
 */
#pragma once

#include <Prism/Protocols/Trusttunnel/Http2/Client.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Client/Types.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Server.hpp>
#include <Prism/Protocols/Trusttunnel/Http2/Server/Types.hpp>
