/**
 * @file Codec.hpp
 * @brief VMess 编解码兼容聚合入口
 * @details 公开入口保留不变；认证/KDF、请求握手、响应握手和数据
 *          分块分别由 Auth.hpp、RequestCodec.hpp、ResponseCodec.hpp
 *          与 ChunkCodec.hpp 提供。
 */

#pragma once

#include <preview/Protocols/Vmess/Auth.hpp>
#include <preview/Protocols/Vmess/ChunkCodec.hpp>
#include <preview/Protocols/Vmess/RequestCodec.hpp>
#include <preview/Protocols/Vmess/ResponseCodec.hpp>
#include <preview/Protocols/Vmess/Types.hpp>
