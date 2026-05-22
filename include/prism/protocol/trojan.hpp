/**
 * @file trojan.hpp
 * @brief Trojan 协议聚合头文件
 * @details 引入 Trojan 协议的所有子头文件，包括常量定义、消息结构、
 * 格式编解码和中继器。Trojan 是基于 TLS 的加密代理协议，
 * 通过固定格式头部实现流量伪装和认证。
 * @note 新增子模块头文件时需同步在此处添加 include
 */
#pragma once

#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/trojan/packet.hpp>
#include <prism/protocol/trojan/framing.hpp>
#include <prism/protocol/trojan/conn.hpp>
