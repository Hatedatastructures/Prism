/**
 * @file Native.hpp
 * @brief Native 伪装方案聚合头
 * @details 原生 TLS 兜底：服务端 TLS 握手 + 直通（传输透明）。
 */

#pragma once

#include <preview/Protocols/Native/Types.hpp>
#include <preview/Protocols/Native/Conn.hpp>
