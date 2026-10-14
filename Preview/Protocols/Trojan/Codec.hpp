/**
 * @file Codec.hpp
 * @brief Trojan 编解码公开聚合头
 * @details 具体职责分别由 CredentialCodec、AddressCodec、UdpCodec、
 *          RequestCodec 和 BeastCodec 拥有；保留本头以兼容既有
 *          Preview 调用方和公开聚合包含路径。
 */

#pragma once

#include <Preview/Protocols/Trojan/Types.hpp>
#include <Preview/Protocols/Trojan/CredentialCodec.hpp>
#include <Preview/Protocols/Trojan/AddressCodec.hpp>
#include <Preview/Protocols/Trojan/UdpCodec.hpp>
#include <Preview/Protocols/Trojan/RequestCodec.hpp>
#include <Preview/Protocols/Trojan/BeastCodec.hpp>
