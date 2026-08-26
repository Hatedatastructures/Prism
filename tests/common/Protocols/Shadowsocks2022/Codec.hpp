/**
 * @file Codec.hpp
 * @brief SS2022 编解码（合并：头部编解码 + KDF + 分块 AEAD + 握手 + UDP 数据报）
 * @details 固定头/变长头明文编解码、地址编解码、BLAKE3 会话密钥派生、
 *          AEAD 分块编解码器（ChunkCodec）、握手 Serializer/Parser、
 *          UDP 数据报逐包 AEAD 编解码（BuildUdpPacket /
 *          ParseUdpPacket）全部集中于此。
 * @note 参考 SIP022 规范。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <blake3.h>
#include <common/Core/Error.hpp>
#include <common/Core/Protocol/Address.hpp>
#include <common/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    /**
     * @brief 构造固定头明文
     * @param Type 头类型（0x00 请求 / 0x01 响应）
     * @param TimeSec UTC 秒
     * @param VarLen 变长头长度
     * @return 11 字节明文
     */
    [[nodiscard]] inline auto ParseFixedHeader(std::uint8_t Type, std::uint64_t TimeSec,
                                                 std::uint16_t VarLen)
        -> std::array<std::uint8_t, FixedHdrPlain>
    {
        std::array<std::uint8_t, FixedHdrPlain> Out{};
        Out[0] = Type;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Out[1 + I] = static_cast<std::uint8_t>((TimeSec >> (56 - I * 8)) & 0xFF);
        }
        Out[9] = static_cast<std::uint8_t>((VarLen >> 8) & 0xFF);
        Out[10] = static_cast<std::uint8_t>(VarLen & 0xFF);
        return Out;
    }

    /**
     * @brief 解析出的固定头字段
     */
    struct FixedHeader
    {
        std::uint8_t Type{0};      ///< 头类型
        std::uint64_t TimeSec{0}; ///< UTC 秒
        std::uint16_t VarLen{0};  ///< 变长头长度
    };

    /**
     * @brief 解析固定头明文
     * @param Data 11 字节明文
     * @param out 输出固定头字段
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseFixedHeader(std::span<const std::uint8_t> Data, FixedHeader &Out)
        -> Error
    {
        if (Data.size() < FixedHdrPlain)
        {
            return Error::NeedMore;
        }
        Out.Type = Data[0];
        Out.TimeSec = 0;
        for (std::size_t I = 0; I < 8; ++I)
        {
            Out.TimeSec = (Out.TimeSec << 8) | Data[1 + I];
        }
        Out.VarLen = static_cast<std::uint16_t>(Data[9]) << 8 | Data[10];
        return Error::None;
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （原内联实现 ipv4 无校验存在越界写，统一实现修复为非法输入输出 0.0.0.0）
     */
    template <typename Alloc>
    inline auto EncodeAddress(const Address &Addr, std::vector<std::uint8_t, Alloc> &Out) -> void
    {
        Preview::Protocol::Common::EncodeAddress(Addr, Out);
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &Addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Out;
        EncodeAddress(Addr, Out);
        return Out;
    }

    /**
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE）
     * @param Data 完整缓冲区
     * @param addr 输出目标地址
     * @param off 输入起始偏移，输出结束偏移
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address &Addr,
                                            std::size_t &Off) -> Error
    {
        if (Off >= Data.size())
        {
            return Error::NeedMore;
        }
        Addr.Type = static_cast<AddressType>(Data[Off++]);
        switch (Addr.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[Off], Data[Off + 1], Data[Off + 2],
                          Data[Off + 3]);
            Addr.Host = buf.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        }
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        Addr.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        return Error::None;
    }

    /**
     * @brief 构造变长头明文（地址 + padding + 初始载荷）
     * @param addr 目标地址
     * @param PadLen padding 长度
     * @param payload 初始载荷（可空）
     * @return 变长头明文
     */
    [[nodiscard]] inline auto BuildVarHeader(const Address &Addr, std::uint16_t PadLen,
                                               std::span<const std::uint8_t> payload = {})
        -> std::vector<std::uint8_t>
    {
        auto Out = EncodeAddress(Addr);
        Out.push_back(static_cast<std::uint8_t>((PadLen >> 8) & 0xFF));
        Out.push_back(static_cast<std::uint8_t>(PadLen & 0xFF));
        for (std::uint16_t I = 0; I < PadLen; ++I)
        {
            Out.push_back(0);
        }
        Out.insert(Out.end(), payload.begin(), payload.end());
        return Out;
    }

    /**
     * @brief 解析变长头明文
     * @param Data 变长头明文
     * @param addr 输出目标地址
     * @param payload 输出剩余载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto ParseVarHeader(std::span<const std::uint8_t> Data, Address &Addr,
                                               std::span<const std::uint8_t> &payload) -> Error
    {
        if (Data.size() < 2)
        {
            return Error::NeedMore;
        }
        Addr.Type = static_cast<AddressType>(Data[0]);
        std::size_t Off = 1;
        switch (Addr.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < Off + 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[Off], Data[Off + 1], Data[Off + 2],
                          Data[Off + 3]);
            Addr.Host = buf.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < Off + 16)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Len = Data[Off++];
            if (Data.size() < Off + Len)
            {
                return Error::NeedMore;
            }
            Addr.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Len);
            Off += Len;
            break;
        }
        }
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        Addr.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() < Off + 2)
        {
            return Error::NeedMore;
        }
        const auto PadLen = static_cast<std::size_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        if (Data.size() < Off + PadLen)
        {
            return Error::NeedMore;
        }
        Off += PadLen;
        payload = Data.subspan(Off);
        return Error::None;
    }

    // ==================== chunk.hpp（分块 AEAD）合并 ====================

    namespace detail
    {

        /**
         * @brief Nonce 小端 +1（对齐 Go increaseNonce）
         * @param Nonce 12 字节 Nonce（原地递增）
         */
        inline auto IncNonce(std::span<std::uint8_t> Nonce) -> void
        {
            for (auto &b : Nonce)
            {
                ++b;
                if (b != 0)
                {
                    break;
                }
            }
        }

        /**
         * @brief AEAD 加密（AES-128-GCM，AAD 为空）
         * @param key 密钥
         * @param nonce12 12 字节 Nonce
         * @param plain 明文
         * @return 密文 + tag
         */
        template <typename Alloc>
        [[nodiscard]] inline auto AeadSeal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain,
                                            std::vector<std::uint8_t, Alloc> &Out) -> std::size_t
        {
            Out.clear();
            Out.resize(plain.size() + AeadTagLen);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return 0;
            }
            int Len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_EncryptUpdate(ctx, Out.data(), &Len, plain.data(), static_cast<int>(plain.size()));
            int OutLen = Len;
            EVP_EncryptFinal_ex(ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + OutLen);
            Out.resize(static_cast<std::size_t>(OutLen) + AeadTagLen);
            EVP_CIPHER_CTX_free(ctx);
            return Out.size();
        }

        /**
         * @brief AEAD 加密（写入 out 偏移处）
         * @param key 密钥
         * @param nonce12 12 字节 Nonce
         * @param plain 明文
         * @param out 输出缓冲
         * @param offset 写入偏移（out 已预分配 offset + plain + tag）
         * @return 写入字节数（含 tag）；0 = 失败
         */
        template <typename Alloc>
        [[nodiscard]] inline auto AeadSeal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain,
                                            std::vector<std::uint8_t, Alloc> &Out,
                                            const std::size_t offset) -> std::size_t
        {
            if (Out.size() < offset + plain.size() + AeadTagLen)
            {
                Out.resize(offset + plain.size() + AeadTagLen);
            }
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return 0;
            }
            int Len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_EncryptUpdate(ctx, Out.data() + offset, &Len, plain.data(), static_cast<int>(plain.size()));
            int OutLen = Len;
            EVP_EncryptFinal_ex(ctx, Out.data() + offset + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + offset + OutLen);
            EVP_CIPHER_CTX_free(ctx);
            return OutLen + AeadTagLen;
        }

        [[nodiscard]] inline auto AeadSeal(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> plain) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            AeadSeal(key, nonce12, plain, Out);
            return Out;
        }

        /**
         * @brief AEAD 解密（失败返回空）
         * @param key 密钥
         * @param nonce12 12 字节 Nonce
         * @param cipher 密文（含 tag）
         * @return 明文；失败返回空
         */
        [[nodiscard]] inline auto AeadOpen(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> cipher) -> std::vector<std::uint8_t>
        {
            if (cipher.size() < AeadTagLen)
            {
                return {};
            }
            std::vector<std::uint8_t> Out(cipher.size() - AeadTagLen);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int Len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_DecryptUpdate(ctx, Out.data(), &Len, cipher.data(),
                              static_cast<int>(cipher.size() - AeadTagLen));
            int OutLen = Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - AeadTagLen);
            const auto Ok = EVP_DecryptFinal_ex(ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_free(ctx);
            if (Ok != 1)
            {
                return {};
            }
            Out.resize(static_cast<std::size_t>(OutLen));
            return Out;
        }

        /**
         * @brief 解密（写入复用缓冲）
         * @param key 密钥
         * @param nonce12 12 字节 Nonce
         * @param cipher 密文（含 tag）
         * @param out 输出缓冲（调用方持有复用，热路径零分配）
         * @return true = 解密成功
         */
        template <typename Alloc>
        [[nodiscard]] inline auto AeadOpen(std::span<const std::uint8_t> key,
                                            std::span<const std::uint8_t> nonce12,
                                            std::span<const std::uint8_t> cipher,
                                            std::vector<std::uint8_t, Alloc> &Out) -> bool
        {
            Out.clear();
            if (cipher.size() < AeadTagLen)
            {
                return false;
            }
            Out.resize(cipher.size() - AeadTagLen);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return false;
            }
            int Len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key.data(), nonce12.data());
            EVP_DecryptUpdate(ctx, Out.data(), &Len, cipher.data(),
                              static_cast<int>(cipher.size() - AeadTagLen));
            int OutLen = Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                                const_cast<std::uint8_t *>(cipher.data()) + cipher.size() - AeadTagLen);
            const auto Ok = EVP_DecryptFinal_ex(ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_free(ctx);
            if (Ok != 1)
            {
                Out.clear();
                return false;
            }
            Out.resize(static_cast<std::size_t>(OutLen));
            return true;
        }

    } // namespace detail

    /**
     * @brief SS2022 AEAD 分块编解码器（状态机）
     */
    class ChunkCodec
    {
    public:
        /**
         * @brief 构造
         * @param key 会话密钥（16 字节 aes-128-gcm）
         * @param StartNonce 起始 Nonce（默认 0；握手消耗 2 个 Nonce
         *                    后数据面从 2 开始，供互操作测试指定）
         */
        explicit ChunkCodec(std::span<const std::uint8_t> key, std::size_t StartNonce = 0)
            : Key_(key.begin(), key.end())
        {
            for (std::size_t I = 0; I < StartNonce; ++I)
            {
                detail::IncNonce(Nonce_);
            }
        }

        /**
         * @brief 加密单块（写入复用缓冲）
         * @param plain 明文
         * @param out 输出缓冲（调用方持有复用，热路径零分配）
         * @return 写入字节数；0 = 失败
         */
        template <typename Alloc>
        [[nodiscard]] auto Seal(std::span<const std::uint8_t> plain,
                                std::vector<std::uint8_t, Alloc> &Out) -> std::size_t
        {
            Out.clear();
            std::array<std::uint8_t, 2> LenPlain{static_cast<std::uint8_t>((plain.size() >> 8) & 0xFF),
                                                  static_cast<std::uint8_t>(plain.size() & 0xFF)};
            // 直接写 out：头 18B（len 密文）+ 尾部（body 密文），零中间分配
            const auto LenN = detail::AeadSeal(Key_, Nonce_, LenPlain, Out);
            detail::IncNonce(Nonce_);
            Out.resize(LenN + plain.size() + AeadTagLen);
            (void)detail::AeadSeal(Key_, Nonce_, plain, Out, LenN);
            detail::IncNonce(Nonce_);
            return Out.size();
        }

        /**
         * @brief 加密单块（长度 Nonce 递增）
         * @param plain 明文
         * @return [len 密文 18B][载荷密文 len+16B]
         */
        [[nodiscard]] auto Seal(std::span<const std::uint8_t> plain) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            Seal(plain, Out);
            return Out;
        }

        /**
         * @brief 解密长度块（2 字节密文 + 16 tag）
         * @param head 18 字节长度块
         * @return 载荷长度（0 = 结束块）；nullopt = 校验失败
         */
        [[nodiscard]] auto OpenLen(std::span<const std::uint8_t> head) -> std::optional<std::size_t>
        {
            if (head.size() < LenBlockSize)
            {
                return std::nullopt;
            }
            const auto LenPlain = detail::AeadOpen(Key_, Nonce_, head.first(LenBlockSize));
            if (LenPlain.size() != 2)
            {
                return std::nullopt;
            }
            detail::IncNonce(Nonce_);
            const auto N = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            if (N > MaxChunkSize)
            {
                return std::nullopt;
            }
            return N;
        }

        /**
         * @brief 解密载荷块（写入复用缓冲）
         * @param Data 载荷密文块
         * @param out 输出缓冲（调用方持有复用，热路径零分配）
         * @return 明文长度；0 = 校验失败
         */
        template <typename Alloc>
        [[nodiscard]] auto OpenPayload(std::span<const std::uint8_t> Data,
                                        std::vector<std::uint8_t, Alloc> &Out) -> std::size_t
        {
            Out.clear();
            if (Data.size() < AeadTagLen)
            {
                return 0;
            }
            if (!detail::AeadOpen(Key_, Nonce_, Data, Out))
            {
                Out.clear();
                return 0;
            }
            detail::IncNonce(Nonce_);
            return Out.size();
        }

        /**
         * @brief 解密载荷块（n 字节密文 + 16 tag）
         * @param Data 载荷密文块
         * @return 明文（空 = 校验失败）
         */
        [[nodiscard]] auto OpenPayload(std::span<const std::uint8_t> Data) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            OpenPayload(Data, Out);
            return Out;
        }

        /**
         * @brief 解密单块（完整块：长度 + 载荷）
         * @param Data 完整块
         * @param consumed 输出消耗字节数
         * @return 明文；空 = 失败或空块（len=0）
         */
        [[nodiscard]] auto Open(std::span<const std::uint8_t> Data, std::size_t &Consumed)
            -> std::vector<std::uint8_t>
        {
            auto Len = OpenLen(Data);
            if (!Len)
            {
                return {};
            }
            if (*Len == 0)
            {
                Consumed = LenBlockSize;
                return {};
            }
            if (Data.size() < LenBlockSize + *Len + AeadTagLen)
            {
                return {};
            }
            const auto Body = OpenPayload(Data.subspan(LenBlockSize, *Len + AeadTagLen));
            if (Body.empty())
            {
                return {};
            }
            Consumed = LenBlockSize + *Len + AeadTagLen;
            return Body;
        }

        /**
         * @brief 加密裸块（无长度块，供 SS2022 握手头使用）
         * @param plain 明文
         * @return 密文（plain + 16B tag）；Nonce 递增一次
         * @details 标准 SS2022 握手首部（请求/响应）为单个 AEAD 块，
         * 无长度块前缀；数据面才使用 chunk 流（Seal/Open）。
         */
        [[nodiscard]] auto SealRaw(std::span<const std::uint8_t> plain)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            detail::AeadSeal(Key_, Nonce_, plain, Out);
            detail::IncNonce(Nonce_);
            return Out;
        }

        /**
         * @brief 解密裸块（无长度块）
         * @param Data 密文（plain + 16B tag）
         * @return 明文；空 = 校验失败
         * @details 与 SealRaw 配对，Nonce 递增一次。
         */
        [[nodiscard]] auto OpenRaw(std::span<const std::uint8_t> Data)
            -> std::vector<std::uint8_t>
        {
            auto Out = detail::AeadOpen(Key_, Nonce_, Data);
            if (Out.empty())
            {
                return {};
            }
            detail::IncNonce(Nonce_);
            return Out;
        }

        /**
         * @brief 解密裸块并返回认证结果（支持空明文）
         * @param Data 密文（plain + 16B tag）
         * @param out 输出缓冲（调用方持有，可为空）
         * @return true = 认证通过且 Nonce 推进；false = 校验失败
         * @details 与单参版本的区别：空明文（如响应 payloadLen=0
         * 的尾随空块）认证成功后同样推进 Nonce，避免数据面失步。
         */
        template <typename Alloc>
        [[nodiscard]] auto OpenRaw(std::span<const std::uint8_t> Data,
                                    std::vector<std::uint8_t, Alloc> &Out) -> bool
        {
            if (!detail::AeadOpen(Key_, Nonce_, Data, Out))
            {
                return false;
            }
            detail::IncNonce(Nonce_);
            return true;
        }

        /**
         * @brief 结束块（长度 0）
         * @return 结束块密文
         */
        [[nodiscard]] auto Finish() -> std::vector<std::uint8_t>
        {
            return Seal({});
        }

    private:
        std::vector<std::uint8_t> Key_;
        std::array<std::uint8_t, 12> Nonce_{};
    };

    /**
     * @brief 派生会话密钥
     * @param psk 预共享密钥（16/32 字节）
     * @param salt 随机盐（与 psk 等长）
     * @param OutLen 输出长度
     * @return 会话子密钥
     */
    [[nodiscard]] inline auto SessionKey(std::span<const std::uint8_t> psk,
                                          std::span<const std::uint8_t> Salt, std::size_t OutLen = 16)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> material;
        material.reserve(psk.size() + Salt.size());
        material.insert(material.end(), psk.begin(), psk.end());
        material.insert(material.end(), Salt.begin(), Salt.end());
        std::vector<std::uint8_t> Out(OutLen);
        blake3_hasher hasher;
        blake3_hasher_init_derive_key(&hasher, KdfContext.data());
        blake3_hasher_update(&hasher, material.data(), material.size());
        blake3_hasher_finalize(&hasher, Out.data(), OutLen);
        return Out;
    }

    // ==================== Kdf.hpp（密钥派生）合并 ====================

    /**
     * @brief SS2022 握手消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 目标地址
        Address dst;
        /// 初始载荷（握手包内）
        std::string InitialPayload;
    };

    /**
     * @brief SS2022 握手序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造
         * @param psk 预共享密钥（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16> &psk) : Psk_(psk)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message &msg, std::uint64_t TimeSec) -> void
        {
            // @note 盐必须 CSPRNG：MinGW 的 std::random_device 存在确定性序列风险，
            //       盐重复 = 跨会话 keystream 重用（与生产 RAND_bytes 口径一致）
            std::array<std::uint8_t, 16> Salt{};
            RAND_bytes(Salt.data(), static_cast<int>(Salt.size()));
            const auto key = SessionKey(Psk_, Salt, 16);

            std::random_device rd; // padding 长度非密码学用途，random_device 足够
            const auto PadLen = static_cast<std::uint16_t>(1 + rd() % 16);
            std::vector<std::uint8_t> var;
            const auto Addr = EncodeAddress(msg.dst);
            var.insert(var.end(), Addr.begin(), Addr.end());
            var.push_back(static_cast<std::uint8_t>((PadLen >> 8) & 0xFF));
            var.push_back(static_cast<std::uint8_t>(PadLen & 0xFF));
            for (std::uint16_t I = 0; I < PadLen; ++I)
            {
                var.push_back(static_cast<std::uint8_t>(rd() & 0xFF));
            }
            var.insert(var.end(), msg.InitialPayload.begin(), msg.InitialPayload.end());

            const auto Fixed =
                ParseFixedHeader(HeaderTypeClient, TimeSec, static_cast<std::uint16_t>(var.size()));

            ChunkCodec Codec(key);
            const auto FixedEnc = Codec.SealRaw(Fixed);
            const auto VarEnc = Codec.SealRaw(var);

            Wire_.clear();
            Wire_.reserve(Salt.size() + FixedEnc.size() + VarEnc.size());
            Wire_.insert(Wire_.end(), Salt.begin(), Salt.end());
            Wire_.insert(Wire_.end(), FixedEnc.begin(), FixedEnc.end());
            Wire_.insert(Wire_.end(), VarEnc.begin(), VarEnc.end());
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
            Offset_ += N;
            return N;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief SS2022 握手解析器（wire → 对象，Beast 风格）
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param psk 预共享密钥（16 字节）
         */
        explicit Parser(const std::array<std::uint8_t, 16> &psk) : Psk_(psk)
        {
        }

        /**
         * @brief 增量喂入
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen)
            {
                ec = make_error_code(Error::NeedMore);
                return 0;
            }

            const auto Salt = std::span<const std::uint8_t>(Buf_).first(16);
            const auto key = SessionKey(Psk_, Salt, 16);
            ChunkCodec Codec(key);

            auto FixedPlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                  16, FixedHdrPlain + AeadTagLen));
            if (FixedPlain.size() != FixedHdrPlain || FixedPlain[0] != HeaderTypeClient)
            {
                ec = make_error_code(Error::AuthFailed);
                return 0;
            }
            const auto VarLen = static_cast<std::size_t>(FixedPlain[9]) << 8 | FixedPlain[10];
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen + VarLen + AeadTagLen)
            {
                ec = make_error_code(Error::NeedMore);
                return 0;
            }
            auto VarPlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                16 + FixedHdrPlain + AeadTagLen,
                                                VarLen + AeadTagLen));
            if (VarPlain.empty())
            {
                ec = make_error_code(Error::AuthFailed);
                return 0;
            }

            std::size_t Off = 0;
            auto Err = ParseAddress(std::span<const std::uint8_t>(VarPlain).subspan(Off), Msg_.dst, Off);
            if (Err != Error::None)
            {
                ec = make_error_code(Err);
                return 0;
            }
            if (VarPlain.size() < Off + 2)
            {
                ec = make_error_code(Error::BadMessage);
                return 0;
            }
            const auto PadLen = static_cast<std::size_t>(VarPlain[Off]) << 8 | VarPlain[Off + 1];
            Off += 2;
            if (VarPlain.size() < Off + PadLen)
            {
                ec = make_error_code(Error::BadMessage);
                return 0;
            }
            Off += PadLen;
            Msg_.InitialPayload.assign(reinterpret_cast<const char *>(VarPlain.data() + Off),
                                        VarPlain.size() - Off);
            Done_ = true;
            return Buf_.size();
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

    // ==================== datagram.hpp（UDP 数据报编解码）合并 ====================

    /// UDP 数据报类型字节（简化变体固定 0x01）
    inline constexpr std::uint8_t UdpType = 0x01;

    /// SessionID 长度（SeparateHeader 前 8 字节）
    inline constexpr std::size_t SessionIdLen = 8;

    /// PacketID 长度（SeparateHeader 后 8 字节）
    inline constexpr std::size_t PacketIdLen = 8;

    /// SeparateHeader 总长度（SessionID + PacketID）
    inline constexpr std::size_t SeparateHdrLen = SessionIdLen + PacketIdLen;

    /// 时间戳长度（8 字节大端）
    inline constexpr std::size_t UdpTsLen = 8;

    /// 单个 UDP 数据报载荷上限（测试库约定）
    inline constexpr std::size_t MaxUdpPayload = 65535;

    namespace detail
    {

        /**
         * @brief UDP 数据报 AEAD 加密输入
         */
        struct UdpSealInput
        {
            std::span<const std::uint8_t> key;   ///< 16 字节会话密钥
            std::span<const std::uint8_t> Nonce; ///< 12 字节 Nonce
            std::span<const std::uint8_t> plain; ///< 明文载荷
            std::span<const std::uint8_t> aad;   ///< 附加认证数据
        };

        /**
         * @brief UDP 数据报 AEAD 解密输入
         */
        struct UdpOpenInput
        {
            std::span<const std::uint8_t> key;    ///< 16 字节会话密钥
            std::span<const std::uint8_t> Nonce;  ///< 12 字节 Nonce
            std::span<const std::uint8_t> cipher; ///< 密文 + 16B tag
            std::span<const std::uint8_t> aad;    ///< 附加认证数据
        };

        /**
         * @brief UDP 数据报单次 AES-128-GCM 加密（带 AAD）
         * @param in 加密输入
         * @return 密文 + 16B tag；失败返回空
         * @details 与 ChunkCodec 的 AEAD 等价，仅多出 AAD 参数。
         */
        [[nodiscard]] inline auto UdpSeal(const UdpSealInput &in) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out(in.plain.size() + AeadTagLen);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int Len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.Nonce.data());
            if (!in.aad.empty())
            {
                EVP_EncryptUpdate(ctx, nullptr, &Len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_EncryptUpdate(ctx, Out.data(), &Len, in.plain.data(), static_cast<int>(in.plain.size()));
            int OutLen = Len;
            EVP_EncryptFinal_ex(ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + OutLen);
            Out.resize(static_cast<std::size_t>(OutLen) + AeadTagLen);
            EVP_CIPHER_CTX_free(ctx);
            return Out;
        }

        /**
         * @brief UDP 数据报单次 AES-128-GCM 解密（带 AAD）
         * @param in 解密输入
         * @return 明文；空 = 校验失败或空载荷
         * @details tag 校验失败返回空，调用方需结合 cipher 长度区分
         * 空载荷与失败（约定：cipher 恰为 16B tag 时空返回合法）。
         */
        [[nodiscard]] inline auto UdpOpen(const UdpOpenInput &in) -> std::vector<std::uint8_t>
        {
            if (in.cipher.size() < AeadTagLen)
            {
                return {};
            }
            std::vector<std::uint8_t> Out(in.cipher.size() - AeadTagLen);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int Len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.Nonce.data());
            if (!in.aad.empty())
            {
                EVP_DecryptUpdate(ctx, nullptr, &Len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_DecryptUpdate(ctx, Out.data(), &Len, in.cipher.data(),
                              static_cast<int>(in.cipher.size() - AeadTagLen));
            int OutLen = Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                                const_cast<std::uint8_t *>(in.cipher.data()) + in.cipher.size() -
                                    AeadTagLen);
            const auto Ok = EVP_DecryptFinal_ex(ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_free(ctx);
            if (Ok != 1)
            {
                return {};
            }
            Out.resize(static_cast<std::size_t>(OutLen));
            return Out;
        }

    } // namespace detail

    /**
     * @brief UDP 数据报构造输入
     */
    struct UdpBuildInput
    {
        std::span<const std::uint8_t> SessionKey; ///< 16 字节会话密钥
        std::uint64_t PacketId{0};                ///< 递增包序号
        const Address *Target{nullptr};            ///< 目标地址
        std::span<const std::uint8_t> payload;     ///< 载荷明文
    };

    /**
     * @brief UDP 数据报解析输入
     */
    struct UdpParseInput
    {
        std::span<const std::uint8_t> SessionKey;   ///< 16 字节会话密钥
        std::span<const std::uint8_t> packet;        ///< 完整数据报
        Address *Target{nullptr};                    ///< 输出目标地址
        std::vector<std::uint8_t> *payload{nullptr}; ///< 输出载荷
    };

    /**
     * @brief 构造 UDP 数据报（写入复用缓冲）
     * @param in 构造输入
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     * @return false = 参数非法
     */
    template <typename Alloc>
    [[nodiscard]] inline auto BuildUdpPacket(const UdpBuildInput &in,
                                               std::vector<std::uint8_t, Alloc> &Out) -> bool
    {
        Out.clear();
        if (!in.Target || in.SessionKey.size() < SessionIdLen + PacketIdLen)
        {
            return false;
        }

        // 1. SeparateHeader（明文）：SessionID(8) + PacketID(8 BE)
        std::array<std::uint8_t, SeparateHdrLen> Separate{};
        std::memcpy(Separate.data(), in.SessionKey.data(), SessionIdLen);
        for (std::size_t I = 0; I < PacketIdLen; ++I)
        {
            Separate[SessionIdLen + I] = static_cast<std::uint8_t>((in.PacketId >> (56 - I * 8)) & 0xFF);
        }

        // 2. 明文头部：Type(1) + Timestamp(8 BE) + 地址（ATYP + ADDR + PORT 2B）
        std::vector<std::uint8_t> head;
        head.reserve(1 + UdpTsLen + 24);
        head.push_back(UdpType);
        const auto Ts = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                                       std::chrono::system_clock::now().time_since_epoch())
                                                       .count());
        for (std::size_t I = 0; I < UdpTsLen; ++I)
        {
            head.push_back(static_cast<std::uint8_t>((Ts >> (56 - I * 8)) & 0xFF));
        }
        EncodeAddress(*in.Target, head);

        // 3. Nonce = SessionID[4..8] + PacketID[0..8]（12 字节）
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), Separate.data() + SessionIdLen / 2, SessionIdLen / 2);
        std::memcpy(Nonce.data() + SessionIdLen / 2, Separate.data() + SessionIdLen, PacketIdLen);

        // 4. 加密载荷（AAD = SeparateHeader）并组装
        const auto BodyEnc =
            detail::UdpSeal(detail::UdpSealInput{in.SessionKey, Nonce, in.payload, Separate});
        if (BodyEnc.empty())
        {
            return false;
        }
        Out.reserve(Separate.size() + head.size() + BodyEnc.size());
        Out.insert(Out.end(), Separate.begin(), Separate.end());
        Out.insert(Out.end(), head.begin(), head.end());
        Out.insert(Out.end(), BodyEnc.begin(), BodyEnc.end());
        return true;
    }

    /**
     * @brief 构造 UDP 数据报（逐包 AEAD 无状态加密）
     * @param in 构造输入
     * @return 完整数据报字节；参数非法返回空
     * @details 格式见文件头注释。与 ParseUdpPacket 配对使用，
     * 不依赖任何会话状态，可用任意递增 PacketId 序列。
     */
    [[nodiscard]] inline auto BuildUdpPacket(const UdpBuildInput &in) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Out;
        BuildUdpPacket(in, Out);
        return Out;
    }

    /**
     * @brief 解析 UDP 数据报（逐包 AEAD 无状态解密）
     * @param in 解析输入（SessionKey + packet + 输出 Target/payload）
     * @return 错误码；bad_auth = SessionID 不匹配 / tag 校验失败，
     *         bad_message = 类型字节非法
     * @details 与 BuildUdpPacket 配对使用。只解析 Type + 地址 +
     * 载荷；时间戳不校验（简化变体）。
     */
    [[nodiscard]] inline auto ParseUdpPacket(const UdpParseInput &in) -> Error
    {
        if (!in.Target || !in.payload)
        {
            return Error::BadLength;
        }
        const auto &SessionKey16 = in.SessionKey;
        const auto &packet = in.packet;
        auto &Target = *in.Target;
        auto &payload = *in.payload;
        // 最小长度：SeparateHeader(16) + Type(1) + TS(8) + ATYP(1) + PORT(2) + tag(16)
        if (SessionKey16.size() < SessionIdLen ||
            packet.size() < SeparateHdrLen + 1 + UdpTsLen + 1 + 2 + AeadTagLen)
        {
            return Error::BadLength;
        }
        const auto Separate = packet.first(SeparateHdrLen);

        // SessionID 校验（前 8 字节须与会话密钥一致）
        if (std::memcmp(Separate.data(), SessionKey16.data(), SessionIdLen) != 0)
        {
            return Error::BadAuth;
        }

        // 类型字节校验
        if (packet[SeparateHdrLen] != UdpType)
        {
            return Error::BadMessage;
        }

        // 解析明文头部中的目标地址（ATYP + ADDR + PORT 2B BE）
        std::size_t Off = SeparateHdrLen + 1 + UdpTsLen;
        std::size_t Consumed = 0;
        auto Err = ParseAddress(packet.subspan(Off), Target, Consumed);
        if (Err != Error::None)
        {
            return Err;
        }
        Off += Consumed;

        // Nonce = SessionID[4..8] + PacketID[0..8]（12 字节）
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), Separate.data() + SessionIdLen / 2, SessionIdLen / 2);
        std::memcpy(Nonce.data() + SessionIdLen / 2, Separate.data() + SessionIdLen, PacketIdLen);

        // 解密载荷（AAD = SeparateHeader）；cipher 恰为 tag 时允许空载荷
        const auto BodyEnc = packet.subspan(Off);
        const auto Body = detail::UdpOpen(detail::UdpOpenInput{SessionKey16, Nonce, BodyEnc, Separate});
        if (Body.empty() && BodyEnc.size() > AeadTagLen)
        {
            return Error::BadAuth;
        }
        payload = Body;
        return Error::None;
    }

} // namespace Preview::Shadowsocks2022
