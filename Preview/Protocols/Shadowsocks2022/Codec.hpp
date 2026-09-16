/**
 * @file Codec.hpp
 * @brief Shadowsocks 2022 编解码兼容聚合入口
 * @details 请求握手、响应/数据报、会话密钥和分块数据面分别由
 *          RequestCodec.hpp、ResponseCodec.hpp、KeyDerivation.hpp 与
 *          ChunkCodec.hpp 提供。
 * @note 本文件仅聚合并导出 SS2022 公共 codec 子头，不重复定义 wire 逻辑。
 */

#pragma once

#include <Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Preview/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Preview/Protocols/Shadowsocks2022/RequestCodec.hpp>
#include <Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <Preview/Protocols/Shadowsocks2022/Types.hpp>
