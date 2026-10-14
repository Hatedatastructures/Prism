/**
 * @file Codec.hpp
 * @brief SOCKS5 编解码兼容聚合头
 * @details 具体职责分别位于 AddressCodec、AuthCodec、MessageCodec、
 *          BeastCodec 和 TransportCodec；保留本头以兼容既有 Preview
 *          调用方和聚合包含路径。
 */

#pragma once

#include <Preview/Protocols/Socks5/AddressCodec.hpp>
#include <Preview/Protocols/Socks5/AuthCodec.hpp>
#include <Preview/Protocols/Socks5/BeastCodec.hpp>
#include <Preview/Protocols/Socks5/MessageCodec.hpp>
#include <Preview/Protocols/Socks5/TransportCodec.hpp>
