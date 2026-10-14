/**
 * @file RecordProtector.hpp
 * @brief ShadowTLS application-data 记录 HMAC 链与流保护
 * @details 拥有 post-handshake 帧 HMAC、KDF、XOR 和有状态记录保护器。
 *          ClientHello/ServerHello 的解析与 SessionId 认证由 ClientHello.hpp
 *          负责。
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

namespace Preview::Shadowtls::Detail
{

    /// 帧 HMAC 输入（password + ServerRandom + tag + payload）
    struct FrameHmacInput
    {
        std::string_view password;                   ///< 密码
        std::span<const std::uint8_t> ServerRandom; ///< 32 字节 Server random
        char tag{'C'};                               ///< 标签（'C' 客户端 / 'S' 服务端）
        std::span<const std::uint8_t> payload;       ///< 载荷
    };

    /// application-data 记录保护模式；模式同时确定 payload XOR 和 digest 链推进规则。
    enum class ProtectionMode : std::uint8_t
    {
        Application,
        ServerFlight,
    };

    /// 记录保护器的构造输入；Password/ServerRandom 只借用至同步构造返回。
    struct RecordProtectionOptions final
    {
        std::string_view Password;
        std::span<const std::uint8_t> ServerRandom;
        char Tag{TagClient};
        RecordSeed ChainSeed{RecordSeed::Directional};
        ProtectionMode Mode{ProtectionMode::Application};
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
         * @param Options 密码、ServerRandom、方向、链种子和 wire 保护模式
         * @details 构造完成后只保留派生 key 与 HMAC chain；输入字符串和随机数不被保存。
         */
        explicit RecordProtector(RecordProtectionOptions Options)
            : Context_(HMAC_CTX_new()), Direction_(Options.Tag), Mode_(Options.Mode)
        {
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            const auto ValidMode = Mode_ == ProtectionMode::Application ||
                                   Mode_ == ProtectionMode::ServerFlight;
            const auto ValidSeed =
                (Mode_ == ProtectionMode::Application &&
                 Options.ChainSeed == RecordSeed::Directional) ||
                (Mode_ == ProtectionMode::ServerFlight &&
                 Options.ChainSeed == RecordSeed::ServerRandomOnly);
            if (!Context_ || Options.ServerRandom.size() != TlsRndSize ||
                (Options.Tag != TagClient && Options.Tag != TagServer) ||
                Options.Password.size() > MaxInt || !ValidMode || !ValidSeed)
            {
                return;
            }
            if (HMAC_Init_ex(Context_, Options.Password.data(),
                             static_cast<int>(Options.Password.size()), EVP_sha1(), nullptr) != 1 ||
                HMAC_Update(Context_, Options.ServerRandom.data(), Options.ServerRandom.size()) != 1 ||
                (Options.ChainSeed == RecordSeed::Directional &&
                 HMAC_Update(Context_, reinterpret_cast<const std::uint8_t *>(&Direction_), 1) != 1))
            {
                return;
            }
            if (Mode_ == ProtectionMode::ServerFlight)
            {
                Key_ = Kdf(Options.Password, Options.ServerRandom);
            }
            Valid_ = true;
        }

        RecordProtector(const RecordProtector &) = delete;
        auto operator=(const RecordProtector &) -> RecordProtector & = delete;

        RecordProtector(RecordProtector &&Other) noexcept
            : Context_(std::exchange(Other.Context_, nullptr)), Direction_(Other.Direction_),
              Key_(Other.Key_), Mode_(Other.Mode_), Valid_(Other.Valid_)
        {
            Other.ClearKey();
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
            ClearKey();
            Context_ = std::exchange(Other.Context_, nullptr);
            Direction_ = Other.Direction_;
            Key_ = Other.Key_;
            Mode_ = Other.Mode_;
            Valid_ = Other.Valid_;
            Other.ClearKey();
            Other.Valid_ = false;
            return *this;
        }

        ~RecordProtector()
        {
            if (Context_)
            {
                HMAC_CTX_free(Context_);
            }
            ClearKey();
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
            if (Mode_ == ProtectionMode::ServerFlight)
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
            const auto DigestUpdated = Mode_ == ProtectionMode::ServerFlight ||
                                       HMAC_Update(Context_, Digest.data(), Digest.size()) == 1;
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
            const auto DigestUpdated = Mode_ == ProtectionMode::ServerFlight ||
                                       HMAC_Update(Context_, Digest.data(), Digest.size()) == 1;
            if (!PayloadUpdated || !DigestUpdated)
            {
                return Error::IoError;
            }
            Payload.assign(PayloadView.begin(), PayloadView.end());
            if (Mode_ == ProtectionMode::ServerFlight)
            {
                XorSlice(Payload, Key_);
            }
            return Error::None;
        }

    private:
        auto ClearKey() noexcept -> void
        {
            OPENSSL_cleanse(Key_.data(), Key_.size());
        }

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
        ProtectionMode Mode_{ProtectionMode::Application};
        bool Valid_{false};
    };

} // namespace Preview::Shadowtls::Detail
