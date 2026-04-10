/**
 * @file http.hpp
 * @brief HTTP 协议支持库聚合头文件
 * @details 聚合 HTTP 代理请求解析和中继模块，提供专为代理场景设计的轻量级
 * HTTP 请求头解析功能和协议握手/认证/转发能力。
 */
#pragma once

#include <prism/protocol/http/parser.hpp>
#include <prism/protocol/http/relay.hpp>
