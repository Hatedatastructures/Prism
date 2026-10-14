/**
 * @file Codec.hpp
 * @brief VLESS 编解码公开聚合头
 * @details 具体职责分别由 AddressCodec、RequestCodec、UdpCodec 和
 *          BeastCodec 拥有；保留本头以兼容既有 Preview 调用方和
 *          公开聚合包含路径。
 */

#pragma once

#include <Preview/Protocols/Vless/Types.hpp>
#include <Preview/Protocols/Vless/AddressCodec.hpp>
#include <Preview/Protocols/Vless/RequestCodec.hpp>
#include <Preview/Protocols/Vless/UdpCodec.hpp>
#include <Preview/Protocols/Vless/BeastCodec.hpp>
