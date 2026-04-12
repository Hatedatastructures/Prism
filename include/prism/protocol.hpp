/**
 * @file protocol.hpp
 * @brief Protocol 模块聚合头文件
 * @details 包含所有支持协议的实现，提供统一的协议处理接口。
 *
 * @section overview 概述
 *
 * Protocol 模块是代理系统协议栈的核心，负责协议探测、解析和转换。
 * 主要功能包括协议探测（识别客户端使用的协议）、目标地址解析（从协议报文中提取目标地址）
 * 和协议转换（在不同协议格式间转换数据）。
 *
 * @section architecture 架构图
 *
 * @code
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                       Protocol Module                           │
 * │                                                                 │
 * │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
 * │  │   HTTP/1.1  │    │   SOCKS5    │    │   Trojan    │         │
 * │  │  (CONNECT)  │    │ (RFC 1928)  │    │  (TLS/ALPN) │         │
 * │  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
 * │         │                  │                  │                 │
 * │         └──────────────────┼──────────────────┘                 │
 * │                            ▼                                    │
 * │                   ┌────────────────┐                            │
 * │                   │    Analysis    │                            │
 * │                   │ (Protocol Probe)                            │
 * │                   └────────────────┘                            │
 * └─────────────────────────────────────────────────────────────────┘
 * @endcode
 *  * @section protocol_detection 协议探测
 * @section protocols 协议支持
 *
 * | 协议     | 识别方式              | 支持命令                        |
 * |---------|----------------------|--------------------------------|
 * | HTTP/1.1| 请求行 + Host 头      | CONNECT                        |
 * | SOCKS5  | 版本号 0x05          | CONNECT, BIND, UDP ASSOCIATE   |
 * | TLS     | ClientHello 报文头   | 包含 Trojan 等子协议            |
 * | Trojan  | TLS 内层首字节       | CONNECT, UDP ASSOCIATE         |
 *
 * @section design 设计原则
 *
 * - **无状态性**：协议处理器不维护连接状态，仅负责数据报文处理
 * - **高性能**：使用 std::string_view 避免数据拷贝，PMR 内存池管理
 * - **错误容忍**：解析失败时返回错误码，不抛出异常
 *
 * @note 所有方法都是线程安全的，可并发调用。
 * @warning 协议探测基于预读数据，可能因数据不足而返回 unknown。
 */
#pragma once

#include <prism/protocol/analysis.hpp>

#include <prism/protocol/http.hpp>
#include <prism/protocol/trojan.hpp>
#include <prism/protocol/vless.hpp>
#include <prism/protocol/shadowsocks.hpp>
#include <prism/protocol/socks5.hpp>
