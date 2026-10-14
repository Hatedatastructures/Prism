/**
 * @file Wire.hpp
 * @brief ShadowTLS ClientHello wire 构造
 * @details 只负责构造兼容模式使用的最小 ClientHello 字节布局，
 *          不持有认证密码、传输对象或会话状态。
 */

#pragma once

#include <Preview/Protocols/Shadowtls/Types.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace Preview::Shadowtls::Detail::Wire
{

    /**
     * @brief 构造简化 ClientHello
     * @param ClientRandom 32 字节客户端随机数
     * @return 含 TLS 记录头的完整 ClientHello
     * @note SessionId 由 Conn 在发送前填充认证 HMAC。
     */
    [[nodiscard]] inline auto BuildClientHello(
        std::span<const std::uint8_t> ClientRandom) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Hello(TlsHdrsize + SessionIdStart + TlsSessionIdSz + 16, 0);
        Hello[0] = 0x16;
        Hello[TlsHdrsize] = HsTypeClienthello;
        Hello[TlsHdrsize + SessionIdStart - 1] = TlsSessionIdSz;
        if (ClientRandom.size() >= TlsRndSize)
        {
            std::memcpy(Hello.data() + TlsHdrsize + 1 + 3 + 2,
                        ClientRandom.data(), TlsRndSize);
        }
        return Hello;
    }

} // namespace Preview::Shadowtls::Detail::Wire
