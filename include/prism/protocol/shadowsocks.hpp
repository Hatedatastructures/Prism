/**
 * @file shadowsocks.hpp
 * @brief SS2022 协议聚合头文件
 * @details 引入 SS2022 协议的所有子头文件，包括常量定义、
 * 消息结构、配置、盐值管理、格式编解码、TCP/UDP 中继器、
 * 重放保护和会话追踪等模块。
 * @note 新增子模块头文件时需同步在此处添加 include
 */
#pragma once

#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/message.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/protocol/shadowsocks/salts.hpp>
#include <prism/protocol/shadowsocks/format.hpp>
#include <prism/protocol/shadowsocks/relay.hpp>
#include <prism/protocol/shadowsocks/replay.hpp>
#include <prism/protocol/shadowsocks/tracker.hpp>
#include <prism/protocol/shadowsocks/datagram.hpp>