/**
 * @file trojan.hpp
 * @brief Trojan 协议支持库聚合头文件
 * @details 聚合了 Trojan 协议相关的头文件，提供完整的 Trojan 协议实现。
 * Trojan 是一种基于 TLS 的加密代理协议，通过在应用层添加固定格式的
 * 头部来实现流量伪装和认证。模块组成包括 constants.hpp 定义 Trojan
 * 协议常量，包含命令和地址类型枚举。message.hpp 定义 Trojan 消息结构，
 * 定义地址结构和请求消息结构。wire.hpp 提供 Trojan 协议线级解析，提供
 * 凭据、头部、地址和端口的解码函数。stream.hpp 提供 Trojan 协议装饰器，
 * 提供协议握手、凭据验证和数据转发功能。核心特性包括协议完整，实现
 * Trojan 协议完整握手流程，支持所有地址类型和命令。装饰器模式，包装
 * 底层传输层，透明添加协议头部，支持链式组合。凭据验证，支持可配置的
 * 凭据验证回调，实现灵活的认证机制。协程友好，所有操作基于 boost::asio
 * ::awaitable，支持异步无阻塞处理。安全特性包括凭据验证，支持密码哈希
 * 验证，防止未授权访问。协议混淆，协议格式设计为与正常 TLS 流量相似，
 * 增强抗检测能力。前向安全，依赖底层 TLS 传输提供前向安全性。
 * @note 遵循 Trojan 协议规范 https://trojan-gfw.github.io/trojan/protocol
 * @warning 加密依赖方面，协议本身不提供加密，依赖底层传输层如 TLS 提供
 * 机密性。
 */
#pragma once

#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/trojan/message.hpp>
#include <prism/protocol/trojan/wire.hpp>
#include <prism/protocol/trojan/stream.hpp>
