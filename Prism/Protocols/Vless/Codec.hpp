/**
 * @file Codec.hpp
 * @brief VLESS 编解码公开聚合头
 * @details 具体职责分别由 AddressCodec、RequestCodec、UdpCodec 和
 *          BeastCodec 拥有；保留本头以兼容既有 Prism 调用方和
 *          公开聚合包含路径。
 */

#pragma once

#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/AddressCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>
#include <Prism/Protocols/Vless/BeastCodec.hpp>
