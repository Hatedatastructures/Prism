/**
 * @file Codec.hpp
 * @brief VMess 编解码兼容聚合入口
 * @details 公开入口保留不变；认证/KDF、请求握手、响应握手和数据
 *          分块分别由 Auth.hpp、RequestCodec.hpp、ResponseCodec.hpp
 *          与 ChunkCodec.hpp 提供。
 * @note 本文件只聚合公共 VMess codec 子头，不重复定义 wire 或密码学逻辑。
 */

#pragma once

#include <Preview/Protocols/Vmess/Auth.hpp>
#include <Preview/Protocols/Vmess/ChunkCodec.hpp>
#include <Preview/Protocols/Vmess/RequestCodec.hpp>
#include <Preview/Protocols/Vmess/ResponseCodec.hpp>
#include <Preview/Protocols/Vmess/Types.hpp>
