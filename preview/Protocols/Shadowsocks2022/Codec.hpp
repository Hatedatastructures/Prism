/**
 * @file Codec.hpp
 * @brief Shadowsocks 2022 编解码兼容聚合入口
 * @details 请求握手、响应/数据报、会话密钥和分块数据面分别由
 *          RequestCodec.hpp、ResponseCodec.hpp、KeyDerivation.hpp 与
 *          ChunkCodec.hpp 提供。
 */

#pragma once

#include <preview/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <preview/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <preview/Protocols/Shadowsocks2022/RequestCodec.hpp>
#include <preview/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <preview/Protocols/Shadowsocks2022/Types.hpp>
