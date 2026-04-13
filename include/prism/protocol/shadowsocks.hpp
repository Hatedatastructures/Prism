/**
 * @file shadowsocks.hpp
 * @brief SS2022 协议聚合头文件
 * @details 引入 SS2022 协议的所有子头文件。
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


// TODO 零拷贝优化，减少出现memcpy