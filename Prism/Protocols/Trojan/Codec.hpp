/**
 * @file Codec.hpp
 * @brief Trojan 编解码公开聚合头
 * @details 具体职责分别由 CredentialCodec、AddressCodec、UdpCodec、
 *          RequestCodec 和 BeastCodec 拥有；保留本头以兼容既有
 *          Prism 调用方和公开聚合包含路径。
 */

#pragma once

#include <Prism/Protocols/Trojan/Types.hpp>
#include <Prism/Protocols/Trojan/CredentialCodec.hpp>
#include <Prism/Protocols/Trojan/AddressCodec.hpp>
#include <Prism/Protocols/Trojan/UdpCodec.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Trojan/BeastCodec.hpp>
