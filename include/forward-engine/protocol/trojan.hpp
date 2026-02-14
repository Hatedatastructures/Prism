/**
 * @file trojan.hpp
 * @brief Trojan 协议支持库聚合头文件
 * @details 聚合了 Trojan 协议相关的头文件，提供完整的 Trojan 协议实现。Trojan 是一种基于 TLS 的加密代理协议，通过在应用层添加固定格式的头部来实现流量伪装和认证。
 *
 * 模块组成：
 * @details - constants.hpp：Trojan 协议常量定义，包含命令和地址类型枚举；
 * @details - message.hpp：Trojan 消息结构，定义地址结构和请求消息结构；
 * @details - wire.hpp：Trojan 协议线级解析，提供凭据、头部、地址和端口的解码函数；
 * @details - stream.hpp：Trojan 协议装饰器，提供协议握手、凭据验证和数据转发功能。
 *
 * 核心特性：
 * @details - 协议完整：实现 Trojan 协议完整握手流程，支持所有地址类型和命令；
 * @details - 装饰器模式：包装底层传输层，透明添加协议头部，支持链式组合；
 * @details - 凭据验证：支持可配置的凭据验证回调，实现灵活的认证机制；
 * @details - 协程友好：所有操作基于 boost::asio::awaitable，支持异步无阻塞处理。
 *
 * 安全特性：
 * @details - 凭据验证：支持密码哈希验证，防止未授权访问；
 * @details - 协议混淆：协议格式设计为与正常 TLS 流量相似，增强抗检测能力；
 * @details - 前向安全：依赖底层 TLS 传输提供前向安全性。
 *
 * @note 遵循 Trojan 协议规范：https://trojan-gfw.github.io/trojan/protocol
 * @warning 加密依赖：协议本身不提供加密，依赖底层传输层（如 TLS）提供机密性。
 */
#pragma once

#include <forward-engine/protocol/trojan/constants.hpp>
#include <forward-engine/protocol/trojan/message.hpp>
#include <forward-engine/protocol/trojan/wire.hpp>
#include <forward-engine/protocol/trojan/stream.hpp>