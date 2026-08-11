/**
 * @file shadowsocks2022.hpp
 * @brief Shadowsocks 2022 协议聚合头（re-export 子头）
 * @details 供测试引用过渡使用。
 */

#pragma once

#include <common/shadowsocks2022/chunk.hpp>
#include <common/shadowsocks2022/client.hpp>
#include <common/shadowsocks2022/codec.hpp>
#include <common/shadowsocks2022/handshake.hpp>
#include <common/shadowsocks2022/kdf.hpp>
#include <common/shadowsocks2022/server.hpp>
#include <common/shadowsocks2022/session.hpp>
#include <common/shadowsocks2022/types.hpp>

// 命名空间别名（BeastTest 兼容：shadowsocks2022::）
namespace shadowsocks2022 = psmtest::ss2022;
