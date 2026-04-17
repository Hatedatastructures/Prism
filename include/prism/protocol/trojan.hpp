/**
 * @file trojan.hpp
 * @brief Trojan 协议聚合头文件
 * @details 引入 Trojan 协议的所有子头文件，包括常量定义、消息结构、
 * 格式编解码和中继器。Trojan 是基于 TLS 的加密代理协议，
 * 通过固定格式头部实现流量伪装和认证
 * @note 遵循 Trojan 协议规范 https://trojan-gfw.github.io/trojan/protocol
 * @warning 协议本身不提供加密，依赖底层传输层如 TLS 提供机密性
 */
#pragma once

#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/trojan/message.hpp>
#include <prism/protocol/trojan/format.hpp>
#include <prism/protocol/trojan/relay.hpp>
