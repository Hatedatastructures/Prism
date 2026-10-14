/**
 * @file ClientHello.hpp
 * @brief ShadowTLS ClientHello/ServerHello 解析与 SessionId 认证
 * @details 拥有首个 TLS hello record 的结构化视图、边界校验和
 *          ShadowTLS SessionId HMAC 生成/校验；不拥有 application-data
 *          记录的 HMAC 链或 XOR 保护状态。
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Shadowtls/Types.hpp>

namespace Preview::Shadowtls::Detail
{

    /// SessionId 生成输入（password + ClientHello + 输出 sid）
    struct SessionIdInput
    {
        std::string_view password;                             ///< 密码
        std::span<const std::uint8_t> ClientHello;            ///< 不含 TLS 头的握手数据
        std::span<std::uint8_t, TlsSessionIdSz> SessionId; ///< 输出 sid（32B）
    };

    /**
     * @struct ClientHelloRecord
     * @brief 完整 TLS ClientHello record 的只读视图
     * @details 视图指向调用方拥有的输入缓冲，不复制线路字节。
     */
    struct ClientHelloRecord
    {
        std::span<const std::uint8_t> Hello{};    ///< 含 handshake header 的 ClientHello
        std::span<const std::uint8_t> SessionId{}; ///< 认证 SessionId
        std::size_t SessionIdOffset{0};            ///< 在完整 record 中的偏移
    };

    /**
     * @struct ServerHelloRecord
     * @brief 完整 TLS ServerHello record 的只读视图
     */
    struct ServerHelloRecord
    {
        std::span<const std::uint8_t> Hello{};  ///< 含 handshake header 的 ServerHello
        std::span<const std::uint8_t> Random{}; ///< ServerHello random
        std::span<const std::uint8_t> SessionId{};
        bool Tls13{false};
    };

    /**
     * @brief 解析完整 TLS ClientHello record
     * @param Record 含 5 字节 TLS record 头的完整输入
     * @param Parsed 输出的 ClientHello 视图
     * @return 增量解析/协议校验结果
     * @note ShadowTLS v3 要求首个 record 只包含一个 ClientHello，且 SessionId 固定 32 字节。
     */
    [[nodiscard]] inline auto ParseClientHelloRecord(std::span<const std::uint8_t> Record,
                                                     ClientHelloRecord &Parsed) -> Error
    {
        Parsed = {};
        if (Record.size() < TlsHdrsize)
        {
            return Error::NeedMore;
        }
        const auto Length = (static_cast<std::size_t>(Record[3]) << 8) | Record[4];
        if (Length > MaxTlsPlaintext)
        {
            return Error::BadLength;
        }
        const auto Total = TlsHdrsize + Length;
        if (Record.size() < Total)
        {
            return Error::NeedMore;
        }
        if (Record.size() != Total)
        {
            return Error::BadLength;
        }
        if (Record[0] != 0x16 || Record[1] != TlsRecordVersionMajor ||
            (Record[2] < 0x01 || Record[2] > TlsRecordVersionMinor))
        {
            return Error::BadMagic;
        }

        const auto Body = Record.subspan(TlsHdrsize);
        if (Body.size() < 4)
        {
            return Error::NeedMore;
        }
        if (Body[0] != HsTypeClienthello)
        {
            return Error::BadMagic;
        }
        const auto HelloLength = (static_cast<std::size_t>(Body[1]) << 16) |
                                 (static_cast<std::size_t>(Body[2]) << 8) | Body[3];
        if (HelloLength > Body.size() - 4)
        {
            return Error::NeedMore;
        }
        if (HelloLength + 4 != Body.size())
        {
            return Error::BadMessage;
        }
        const auto HelloBody = Body.subspan(4, HelloLength);
        if (HelloBody.size() < SessionIdStart - 4)
        {
            return Error::NeedMore;
        }
        const auto SessionLength = Body[SessionIdStart - 1];
        if (SessionLength > TlsSessionIdSz)
        {
            return Error::BadLength;
        }
        if (SessionLength != TlsSessionIdSz)
        {
            return Error::BadMessage;
        }
        if (Body.size() < SessionIdStart + SessionLength)
        {
            return Error::NeedMore;
        }
        Parsed.Hello = Body;
        Parsed.SessionId = Body.subspan(SessionIdStart, SessionLength);
        Parsed.SessionIdOffset = TlsHdrsize + SessionIdStart;
        return Error::None;
    }

    /**
     * @brief 解析完整 TLS ServerHello record
     * @param Record 含 5 字节 TLS record 头的完整输入
     * @param Parsed 输出 ServerHello 视图
     * @return 增量解析/协议校验结果
     * @details 仅解析 ShadowTLS 需要的 random、SessionId 和 TLS 1.3
     *          supported_versions，不执行证书或 Finished 校验。
     */
    [[nodiscard]] inline auto ParseServerHelloRecord(std::span<const std::uint8_t> Record,
                                                     ServerHelloRecord &Parsed) -> Error
    {
        Parsed = {};
        if (Record.size() < TlsHdrsize)
        {
            return Error::NeedMore;
        }
        const auto Length = (static_cast<std::size_t>(Record[3]) << 8) | Record[4];
        if (Length > MaxTlsPlaintext)
        {
            return Error::BadLength;
        }
        const auto Total = TlsHdrsize + Length;
        if (Record.size() < Total)
        {
            return Error::NeedMore;
        }
        if (Record.size() != Total)
        {
            return Error::BadLength;
        }
        if (Record[0] != 0x16 || Record[1] != TlsRecordVersionMajor ||
            (Record[2] < 0x01 || Record[2] > TlsRecordVersionMinor))
        {
            return Error::BadMagic;
        }

        const auto Body = Record.subspan(TlsHdrsize);
        if (Body.size() < 4)
        {
            return Error::NeedMore;
        }
        if (Body[0] != 2)
        {
            return Error::BadMagic;
        }
        const auto HelloLength = (static_cast<std::size_t>(Body[1]) << 16) |
                                 (static_cast<std::size_t>(Body[2]) << 8) | Body[3];
        if (HelloLength > Body.size() - 4)
        {
            return Error::NeedMore;
        }
        if (HelloLength + 4 != Body.size())
        {
            return Error::BadMessage;
        }
        const auto Hello = Body.subspan(4, HelloLength);
        constexpr std::size_t PrefixLength = 2 + TlsRndSize + 1;
        if (Hello.size() < PrefixLength)
        {
            return Error::NeedMore;
        }
        const auto SessionLength = static_cast<std::size_t>(Hello[PrefixLength - 1]);
        const auto CipherOffset = PrefixLength + SessionLength;
        if (SessionLength > TlsSessionIdSz)
        {
            return Error::BadLength;
        }
        if (SessionLength > Hello.size() - PrefixLength)
        {
            return Error::NeedMore;
        }
        if (CipherOffset + 2 + 1 + 2 > Hello.size())
        {
            return Error::NeedMore;
        }
        const auto ExtensionsLengthOffset = CipherOffset + 2 + 1;
        const auto ExtensionsLength = (static_cast<std::size_t>(Hello[ExtensionsLengthOffset]) << 8) |
                                       Hello[ExtensionsLengthOffset + 1];
        const auto ExtensionsOffset = ExtensionsLengthOffset + 2;
        if (ExtensionsLength > Hello.size() - ExtensionsOffset)
        {
            return Error::NeedMore;
        }
        if (ExtensionsOffset + ExtensionsLength != Hello.size())
        {
            return Error::BadMessage;
        }

        auto Extensions = Hello.subspan(ExtensionsOffset, ExtensionsLength);
        while (!Extensions.empty())
        {
            if (Extensions.size() < 4)
            {
                return Error::BadMessage;
            }
            const auto Type = (static_cast<std::size_t>(Extensions[0]) << 8) | Extensions[1];
            const auto ExtensionLength = (static_cast<std::size_t>(Extensions[2]) << 8) | Extensions[3];
            Extensions = Extensions.subspan(4);
            if (ExtensionLength > Extensions.size())
            {
                return Error::NeedMore;
            }
            if (Type == 43 && ExtensionLength == 2 && Extensions[0] == 0x03 && Extensions[1] == 0x04)
            {
                Parsed.Tls13 = true;
            }
            Extensions = Extensions.subspan(ExtensionLength);
        }

        Parsed.Hello = Body;
        Parsed.Random = Hello.subspan(2, TlsRndSize);
        Parsed.SessionId = Hello.subspan(2 + TlsRndSize + 1, SessionLength);
        return Error::None;
    }

    /**
     * @brief 生成 SessionId（客户端侧）
     * @param Input 生成输入
     * @return 错误码
     * @details 对齐 sing v3 generateSessionID：前 28 字节随机，
     * 后 4 字节 = HMAC-SHA1(password, hello[:sidStart] + sid + hello[sidEnd:])[:4]。
     */
    [[nodiscard]] inline auto GenerateSessionId(const SessionIdInput &Input) -> Error
    {
        const auto &Password = Input.password;
        const auto &ClientHello = Input.ClientHello;
        auto &SessionId = Input.SessionId;
        if (ClientHello.size() < SessionIdStart + TlsSessionIdSz)
        {
            return Error::BadLength;
        }
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Password.size() > MaxInt)
        {
            return Error::BadLength;
        }

        // HMAC-SHA1(password, ClientHello[:sidStart] + sessionID + ClientHello[sidEnd:])[:4]
        HMAC_CTX *Context = HMAC_CTX_new();
        if (!Context)
        {
            return Error::IoError;
        }
        bool Ok = HMAC_Init_ex(
                      Context,
                      Password.data(),
                      static_cast<int>(Password.size()),
                      EVP_sha1(),
                      nullptr) == 1;
        Ok = Ok && HMAC_Update(Context, ClientHello.data(), SessionIdStart) == 1;
        Ok = Ok && HMAC_Update(Context, SessionId.data(), TlsSessionIdSz) == 1;
        Ok = Ok && HMAC_Update(
                         Context,
                         ClientHello.data() + SessionIdStart + TlsSessionIdSz,
                         ClientHello.size() - SessionIdStart - TlsSessionIdSz) == 1;
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t MdLen = 0;
        Ok = Ok && HMAC_Final(Context, md.data(), &MdLen) == 1;
        HMAC_CTX_free(Context);
        if (!Ok || MdLen < HmacSize)
        {
            return Error::IoError;
        }

        std::memcpy(SessionId.data() + TlsSessionIdSz - HmacSize, md.data(), HmacSize);
        return Error::None;
    }

    /**
     * @brief 校验 ClientHello（服务端侧）
     * @param Password 密码
     * @param ClientHello 含 TLS 头的完整消息
     * @return true = SessionId HMAC 校验通过
     * @details 对齐 sing v3 / C++ VerifyClientHello：
     * HMAC-SHA1(password, hello[5:] 且 SessionId 末尾 4 字节置零)[:4] == SessionId 末尾 4 字节。
     */
    [[nodiscard]] inline auto VerifyClientHello(
        std::string_view Password,
        std::span<const std::byte> ClientHello) -> bool
    {
        constexpr std::size_t MinLen = TlsHdrsize + 1 + 3 + 2 + TlsRndSize + 1 + TlsSessionIdSz;
        if (ClientHello.size() < MinLen)
        {
            return false;
        }
        const auto *Raw = reinterpret_cast<const std::uint8_t *>(ClientHello.data());
        if (Raw[0] != 0x16 || Raw[TlsHdrsize] != HsTypeClienthello)
        {
            return false;
        }
        const std::size_t SidLenIdx = TlsHdrsize + 1 + 3 + 2 + TlsRndSize;
        if (Raw[SidLenIdx] != TlsSessionIdSz)
        {
            return false;
        }

        // 构造 HMAC 数据：hello[5:] 且 SessionId 末尾 4 字节置零
        const std::size_t DataSize = ClientHello.size() - TlsHdrsize;
        std::vector<std::uint8_t> HmacData(DataSize);
        std::memcpy(HmacData.data(), Raw + TlsHdrsize, DataSize);
        const std::size_t HmacOffsetInData = SessionIdStart + TlsSessionIdSz - HmacSize;
        std::memset(HmacData.data() + HmacOffsetInData, 0, HmacSize);

        // 期望 HMAC
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Password.size() > MaxInt)
        {
            return false;
        }
        HMAC_CTX *Context = HMAC_CTX_new();
        if (!Context)
        {
            return false;
        }
        bool Ok = HMAC_Init_ex(
                      Context,
                      Password.data(),
                      static_cast<int>(Password.size()),
                      EVP_sha1(),
                      nullptr) == 1;
        Ok = Ok && HMAC_Update(Context, HmacData.data(), HmacData.size()) == 1;
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t MdLen = 0;
        Ok = Ok && HMAC_Final(Context, md.data(), &MdLen) == 1;
        HMAC_CTX_free(Context);
        if (!Ok || MdLen < HmacSize)
        {
            return false;
        }

        // 客户端 tag
        const std::size_t ClientHmacOffset = SidLenIdx + 1 + TlsSessionIdSz - HmacSize;
        return CRYPTO_memcmp(md.data(), Raw + ClientHmacOffset, HmacSize) == 0;
    }

} // namespace Preview::Shadowtls::Detail
