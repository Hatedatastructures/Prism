/**
 * @file protocol.hpp
 * @brief Protocol 模块聚合头文件
 * @details 包含所有支持协议的实现，提供统一的协议处理接口。该模块是代理系统协议栈的核心，负责协议探测、解析和转换。
 *
 * 模块组成：
 * @details - frame.hpp：通用协议帧定义，支持文本、二进制及控制帧；
 * @details - analysis.hpp：协议分析与识别，提供协议探测和目标地址解析；
 * @details - http/：HTTP 协议支持库，包含请求/响应对象及序列化支持；
 * @details - socks5/：SOCKS5 协议支持库，实现 RFC 1928 服务端逻辑；
 * @details - trojan/：Trojan 协议支持库，实现基于 TLS 的加密代理协议。
 *
 * 协议支持：
 * @details - HTTP/1.1：通过请求行和 Host 头识别，支持 CONNECT 方法代理；
 * @details - SOCKS5：通过版本号识别，支持 CONNECT、BIND、UDP ASSOCIATE 命令；
 * @details - TLS：通过 ClientHello 报文头识别，包含 Trojan 等子协议；
 * @details - Trojan：基于 TLS 的加密代理协议，支持凭据验证和流量伪装。
 *
 * 设计原则：
 * @details - 无状态性：协议处理器不维护连接状态，仅负责数据报文处理；
 * @details - 高性能：使用 std::string_view 避免数据拷贝，PMR 内存池管理；
 * @details - 错误容忍：解析失败时返回错误码，不抛出异常。
 *
 * @note 所有方法都是线程安全的，可并发调用。
 * @warning 协议探测基于预读数据，可能因数据不足而返回 unknown。
 */
#pragma once

#include <forward-engine/protocol/frame.hpp>
#include <forward-engine/protocol/analysis.hpp>

#include <forward-engine/protocol/http.hpp>
#include <forward-engine/protocol/trojan.hpp>
#include <forward-engine/protocol/socks5.hpp>