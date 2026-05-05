/**
 * @file protocol.hpp
 * @brief Protocol 模块聚合头文件
 * @details 聚合引入所有支持协议的实现，包含协议分析、
 * HTTP/1.1、SOCKS5、Trojan、VLESS 和 Shadowsocks 2022
 * 协议处理模块。提供统一的协议探测、目标地址解析和
 * 协议转换接口，使用 string_view 避免数据拷贝。
 * @note 所有方法都是线程安全的，可并发调用。
 * @warning 协议探测基于预读数据，可能因数据不足而返回
 * unknown。
 */
#pragma once

#include <prism/protocol/analysis.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/protocol/tls/signal.hpp>

#include <prism/protocol/http.hpp>
#include <prism/protocol/trojan.hpp>
#include <prism/protocol/vless.hpp>
#include <prism/protocol/shadowsocks.hpp>
#include <prism/protocol/socks5.hpp>
