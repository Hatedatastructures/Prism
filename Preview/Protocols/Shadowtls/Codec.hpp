/**
 * @file Codec.hpp
 * @brief ShadowTLS v3 认证编解码（纯函数）
 * @details 对齐 sing-shadowtls v3_client.go / v3_conn.go：
 *          - GenerateSessionId：HMAC-SHA1(password, clientHello 前段 + sessionID
 *            + clientHello 后段)[:4] 塞入 SessionId 末尾
 *          - VerifyClientHello：校验 ClientHello SessionId 内 HMAC
 *          - FrameHmac：HMAC-SHA1(password, serverRandom + tag + payload)[:4]
 *          - Kdf：SHA256(password + serverRandom)，用于流加密密钥
 * @note 参考 sing-shadowtls v3 协议规范。
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Shadowtls/Types.hpp>

namespace Preview::Shadowtls
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

    /// 帧 HMAC 输入（password + ServerRandom + tag + payload）
    struct FrameHmacInput
    {
        std::string_view password;                   ///< 密码
        std::span<const std::uint8_t> ServerRandom; ///< 32 字节 Server random
        char tag{'C'};                               ///< 标签（'C' 客户端 / 'S' 服务端）
        std::span<const std::uint8_t> payload;       ///< 载荷
    };

    [[nodiscard]] inline auto Kdf(std::string_view Password,
                                  std::span<const std::uint8_t> ServerRandom)
        -> std::array<std::uint8_t, 32>;

    inline auto XorSlice(std::span<std::uint8_t> Data,
                         std::span<const std::uint8_t> Key) -> void;

    /**
     * @brief 计算帧 HMAC（post-handshake 认证）
     * @param Input 输入
     * @return 4 字节 HMAC
     */
    [[nodiscard]] inline auto FrameHmac(const FrameHmacInput &Input)
        -> std::array<std::uint8_t, HmacSize>
    {
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Input.ServerRandom.size() != TlsRndSize || Input.password.size() > MaxInt ||
            (Input.tag != TagClient && Input.tag != TagServer))
        {
            return {};
        }
        HMAC_CTX *Context = HMAC_CTX_new();
        if (!Context)
        {
            return {};
        }
        bool Ok = HMAC_Init_ex(
                      Context,
                      Input.password.data(),
                      static_cast<int>(Input.password.size()),
                      EVP_sha1(),
                      nullptr) == 1;
        Ok = Ok && HMAC_Update(Context, Input.ServerRandom.data(), Input.ServerRandom.size()) == 1;
        const auto TagByte = static_cast<std::uint8_t>(Input.tag);
        Ok = Ok && HMAC_Update(Context, &TagByte, 1) == 1;
        if (Ok && !Input.payload.empty())
        {
            Ok = HMAC_Update(Context, Input.payload.data(), Input.payload.size()) == 1;
        }
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t MdLen = 0;
        Ok = Ok && HMAC_Final(Context, md.data(), &MdLen) == 1;
        HMAC_CTX_free(Context);
        if (!Ok || MdLen < HmacSize)
        {
            return {};
        }

        std::array<std::uint8_t, HmacSize> Output{};
        std::memcpy(Output.data(), md.data(), HmacSize);
        return Output;
    }

    /**
     * @class RecordProtector
     * @brief ShadowTLS v3 application-data 记录保护器
     * @details 每个方向维护独立的 HMAC 链。链初始状态为
     *          HMAC(password, serverRandom + direction)，每帧先追加明文，
     *          取当前 digest 作为 4 字节认证码，再把该 digest 写回链状态。
     *          这与 sing-shadowtls v3 的 verifiedConn 语义一致。
     */
    class RecordProtector final
    {
    public:
        /**
         * @brief 创建单方向记录保护器
         * @param Password 认证密码
         * @param ServerRandom TLS ServerHello random
         * @param Direction 方向标签，客户端为 C，服务端为 S
         */
        RecordProtector(std::string_view Password, std::span<const std::uint8_t> ServerRandom,
                        char Direction, RecordSeed Seed = RecordSeed::Directional,
                        bool XorPayload = false, bool AppendDigest = true)
            : Context_(HMAC_CTX_new()), Direction_(Direction), XorPayload_(XorPayload),
              AppendDigest_(AppendDigest)
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (!Context_ || ServerRandom.size() != TlsRndSize ||
                (Direction != TagClient && Direction != TagServer) || Password.size() > MaxInt)
            {
                return;
            }
            if (HMAC_Init_ex(Context_, Password.data(), static_cast<int>(Password.size()), EVP_sha1(), nullptr) != 1 ||
                HMAC_Update(Context_, ServerRandom.data(), ServerRandom.size()) != 1 ||
                (Seed == RecordSeed::Directional &&
                 HMAC_Update(Context_, reinterpret_cast<const std::uint8_t *>(&Direction_), 1) != 1))
            {
                return;
            }
            if (XorPayload_)
            {
                Key_ = Kdf(Password, ServerRandom);
            }
            Valid_ = true;
        }

        RecordProtector(const RecordProtector &) = delete;
        auto operator=(const RecordProtector &) -> RecordProtector & = delete;

        RecordProtector(RecordProtector &&Other) noexcept
            : Context_(std::exchange(Other.Context_, nullptr)), Direction_(Other.Direction_),
              Key_(Other.Key_), XorPayload_(Other.XorPayload_), AppendDigest_(Other.AppendDigest_), Valid_(Other.Valid_)
        {
            Other.Valid_ = false;
        }

        auto operator=(RecordProtector &&Other) noexcept -> RecordProtector &
        {
            if (this == &Other)
            {
                return *this;
            }
            if (Context_)
            {
                HMAC_CTX_free(Context_);
            }
            Context_ = std::exchange(Other.Context_, nullptr);
            Direction_ = Other.Direction_;
            Key_ = Other.Key_;
            XorPayload_ = Other.XorPayload_;
            AppendDigest_ = Other.AppendDigest_;
            Valid_ = Other.Valid_;
            Other.Valid_ = false;
            return *this;
        }

        ~RecordProtector()
        {
            if (Context_)
            {
                HMAC_CTX_free(Context_);
            }
        }

        /**
         * @brief 返回保护器是否成功初始化
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Valid_;
        }

        /**
         * @brief 编码一条 application-data 记录
         * @param Payload 明文载荷
         * @param Record 输出完整 TLS 记录
         * @return 编码结果
         */
        [[nodiscard]] auto Encode(std::span<const std::uint8_t> Payload,
                                  std::vector<std::uint8_t> &Record) -> Error
        {
            Record.clear();
            if (!Valid_)
            {
                return Error::IoError;
            }
            if (Payload.size() > MaxTlsPlaintext)
            {
                return Error::BadLength;
            }
            std::vector<std::uint8_t> WirePayload(Payload.begin(), Payload.end());
            if (XorPayload_)
            {
                XorSlice(WirePayload, Key_);
            }
            std::array<std::uint8_t, HmacSize> Digest{};
            const auto Err = Compute(WirePayload, Digest);
            if (Err != Error::None)
            {
                return Err;
            }
            const auto PayloadUpdated = WirePayload.empty() ||
                                        HMAC_Update(Context_, WirePayload.data(), WirePayload.size()) == 1;
            const auto DigestUpdated = !AppendDigest_ || HMAC_Update(Context_, Digest.data(), Digest.size()) == 1;
            if (!PayloadUpdated || !DigestUpdated)
            {
                return Error::IoError;
            }

            Record.resize(TlsHdrsize + HmacSize + WirePayload.size());
            Record[0] = TlsContentApplicationData;
            Record[1] = TlsRecordVersionMajor;
            Record[2] = TlsRecordVersionMinor;
            const auto Length = static_cast<std::uint16_t>(HmacSize + WirePayload.size());
            Record[3] = static_cast<std::uint8_t>(Length >> 8);
            Record[4] = static_cast<std::uint8_t>(Length);
            std::copy(Digest.begin(), Digest.end(), Record.begin() + TlsHdrsize);
            std::copy(WirePayload.begin(), WirePayload.end(), Record.begin() + TlsHdrsize + HmacSize);
            return Error::None;
        }

        /**
         * @brief 解码并认证一条完整 application-data 记录
         * @param Record 输入记录，可为分片缓冲
         * @param Payload 输出明文载荷
         * @return 解码结果；认证失败时不推进 HMAC 链
         */
        [[nodiscard]] auto Decode(std::span<const std::uint8_t> Record,
                                  std::vector<std::uint8_t> &Payload) -> Error
        {
            Payload.clear();
            if (!Valid_)
            {
                return Error::IoError;
            }
            if (Record.size() < TlsHdrsize)
            {
                return Error::NeedMore;
            }
            if (Record[0] != TlsContentApplicationData || Record[1] != TlsRecordVersionMajor ||
                Record[2] != TlsRecordVersionMinor)
            {
                return Error::BadMagic;
            }
            const auto Length = (static_cast<std::size_t>(Record[3]) << 8) | Record[4];
            if (Length < HmacSize || Length > HmacSize + MaxTlsPlaintext)
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

            auto PayloadView = Record.subspan(TlsHdrsize + HmacSize, Length - HmacSize);
            std::array<std::uint8_t, HmacSize> Digest{};
            const auto Err = Compute(PayloadView, Digest);
            if (Err != Error::None || CRYPTO_memcmp(Digest.data(), Record.data() + TlsHdrsize, HmacSize) != 0)
            {
                return Error::BadAuth;
            }
            const auto PayloadUpdated = PayloadView.empty() ||
                                        HMAC_Update(Context_, PayloadView.data(), PayloadView.size()) == 1;
            const auto DigestUpdated = !AppendDigest_ || HMAC_Update(Context_, Digest.data(), Digest.size()) == 1;
            if (!PayloadUpdated || !DigestUpdated)
            {
                return Error::IoError;
            }
            Payload.assign(PayloadView.begin(), PayloadView.end());
            if (XorPayload_)
            {
                XorSlice(Payload, Key_);
            }
            return Error::None;
        }

    private:
        [[nodiscard]] auto Compute(std::span<const std::uint8_t> Payload,
                                   std::array<std::uint8_t, HmacSize> &Digest) const -> Error
        {
            if (!Context_)
            {
                return Error::IoError;
            }
            HMAC_CTX Snapshot;
            HMAC_CTX_init(&Snapshot);
            const auto Copied = HMAC_CTX_copy_ex(&Snapshot, Context_) == 1;
            const auto Updated = Copied &&
                                 (Payload.empty() || HMAC_Update(&Snapshot, Payload.data(), Payload.size()) == 1);
            std::array<std::uint8_t, EVP_MAX_MD_SIZE> Full{};
            std::uint32_t FullLength = 0;
            const auto Finalized = Updated && HMAC_Final(&Snapshot, Full.data(), &FullLength) == 1;
            HMAC_CTX_cleanup(&Snapshot);
            if (!Finalized || FullLength < HmacSize)
            {
                return Error::IoError;
            }
            std::copy_n(Full.begin(), HmacSize, Digest.begin());
            return Error::None;
        }

        HMAC_CTX *Context_{nullptr};
        char Direction_{TagClient};
        std::array<std::uint8_t, 32> Key_{};
        bool XorPayload_{false};
        bool AppendDigest_{true};
        bool Valid_{false};
    };

    /**
     * @brief 派生流密钥（对齐 sing v3 Kdf）
     * @param Password 密码
     * @param ServerRandom 32 字节 Server random
     * @return SHA256(password + serverRandom)
     */
    [[nodiscard]] inline auto Kdf(
        std::string_view Password,
        std::span<const std::uint8_t> ServerRandom)
        -> std::array<std::uint8_t, 32>
    {
        if (ServerRandom.size() != TlsRndSize)
        {
            return {};
        }
        SHA256_CTX Context;
        bool Ok = SHA256_Init(&Context) == 1;
        Ok = Ok && SHA256_Update(&Context, Password.data(), Password.size()) == 1;
        Ok = Ok && SHA256_Update(&Context, ServerRandom.data(), ServerRandom.size()) == 1;
        std::array<std::uint8_t, 32> Output{};
        Ok = Ok && SHA256_Final(Output.data(), &Context) == 1;
        if (!Ok)
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 字节异或（对齐 sing v3 xorSlice，用于流加密）
     * @param Data 待异或数据（原地）
     * @param Key 密钥
     */
    inline auto XorSlice(
        std::span<std::uint8_t> Data,
        std::span<const std::uint8_t> Key) -> void
    {
        if (Key.empty())
        {
            return;
        }
        for (std::size_t I = 0; I < Data.size(); ++I)
        {
            Data[I] ^= Key[I % Key.size()];
        }
    }

} // namespace Preview::Shadowtls
