/**
 * @file AuthCrypto.hpp
 * @brief VMess 认证使用的密码学原语
 * @details 提供摘要、字节视图、KDF padding、AES-GCM、AES-ECB 与帧掩码哈希。
 *          本头不拥有 VMess KDF 链、AuthID 格式或认证头 wire。
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace Prism::Vmess::detail
{

    /**
     * @brief HMAC-SHA256 单次
     * @param Key 输入密钥
     * @param Data 输入数据
     * @return 32 字节摘要
     */
    [[nodiscard]] inline auto HmacSha256(
        std::span<const std::uint8_t> Key,
        std::span<const std::uint8_t> Data)
        -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Output{};
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Key.size() > MaxInt)
        {
            return {};
        }
        unsigned int Len = 0;
        const auto *Result = HMAC(
            EVP_sha256(),
            Key.data(),
            static_cast<int>(Key.size()),
            Data.data(),
            Data.size(),
            Output.data(),
            &Len);
        if (Result == nullptr || Len != Output.size())
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief MD5 摘要（16 字节）
     * @param Data 输入数据
     * @return 16 字节摘要
     */
    [[nodiscard]] inline auto Md5(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Output{};
        unsigned int Len = 0;
        EVP_Digest(Data.data(), Data.size(), Output.data(), &Len, EVP_md5(), nullptr);
        return Output;
    }

    /**
     * @brief SHA-256 摘要（32 字节）
     * @param Data 输入数据
     * @return 32 字节摘要
     */
    [[nodiscard]] inline auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Output{};
        unsigned int Len = 0;
        EVP_Digest(Data.data(), Data.size(), Output.data(), &Len, EVP_sha256(), nullptr);
        return Output;
    }

    /**
     * @brief 路径转字节视图（支持 string_view / span / array）
     * @tparam Path 路径类型
     * @param Object 路径对象
     * @return 只读字节视图
     */
    template <typename Path>
    [[nodiscard]] inline auto AsBytes(const Path &Object) -> std::span<const std::uint8_t>
    {
        if constexpr (std::is_convertible_v<Path, std::string_view>)
        {
            const std::string_view StringView(Object);
            return {reinterpret_cast<const std::uint8_t *>(StringView.data()), StringView.size()};
        }
        else
        {
            return std::span<const std::uint8_t>(Object);
        }
    }

    /**
     * @brief 路径填充到 64 字节块
     * @param Path 路径字节
     * @param Mask 异或掩码（0x36 / 0x5C）
     * @return 64 字节填充块
     */
    [[nodiscard]] inline auto XorPad(
        std::span<const std::uint8_t> Path,
        std::uint8_t Mask)
        -> std::array<std::uint8_t, 64>
    {
        std::array<std::uint8_t, 64> Output{};
        const auto Count = std::min(Path.size(), Output.size());
        std::copy(Path.begin(), Path.begin() + static_cast<std::ptrdiff_t>(Count), Output.begin());
        for (auto &Byte : Output)
        {
            Byte ^= Mask;
        }
        return Output;
    }

    /**
     * @brief AES-GCM 加密输入
     */
    struct SealInput
    {
        std::span<const std::uint8_t> Key;
        std::span<const std::uint8_t> Nonce;
        std::span<const std::uint8_t> Plain;
        std::span<const std::uint8_t> Aad;
    };

    /**
     * @brief AES-GCM 解密输入
     */
    struct OpenInput
    {
        std::span<const std::uint8_t> Key;
        std::span<const std::uint8_t> Nonce;
        std::span<const std::uint8_t> Cipher;
        std::span<const std::uint8_t> Aad;
    };

    [[nodiscard]] inline auto ValidAesGcmInput(const SealInput &Input) noexcept -> bool
    {
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        return Input.Key.size() == 16 && Input.Nonce.size() == 12 &&
               Input.Plain.size() <= MaxInt && Input.Aad.size() <= MaxInt;
    }

    [[nodiscard]] inline auto ValidAesGcmInput(const OpenInput &Input) noexcept -> bool
    {
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        return Input.Key.size() == 16 && Input.Nonce.size() == 12 &&
               Input.Cipher.size() <= MaxInt && Input.Aad.size() <= MaxInt;
    }

    /**
     * @brief AES-128-GCM 加密（带 AAD）
     * @param Input 加密输入
     * @return 密文 + 16 字节 tag；失败返回空
     */
    [[nodiscard]] inline auto AesGcmSeal(const SealInput &Input) -> std::vector<std::uint8_t>
    {
        if (!ValidAesGcmInput(Input))
        {
            return {};
        }
        std::vector<std::uint8_t> Output(Input.Plain.size() + 16);
        EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
        if (!Context)
        {
            return {};
        }
        int Len = 0;
        bool Ok = EVP_EncryptInit_ex(Context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
        Ok = Ok && EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
        Ok = Ok && EVP_EncryptInit_ex(Context, nullptr, nullptr, Input.Key.data(), Input.Nonce.data()) == 1;
        if (Ok && !Input.Aad.empty())
        {
            Ok = EVP_EncryptUpdate(
                     Context, nullptr, &Len, Input.Aad.data(), static_cast<int>(Input.Aad.size())) == 1;
        }
        int OutLen = 0;
        if (Ok)
        {
            Ok = EVP_EncryptUpdate(
                     Context, Output.data(), &Len, Input.Plain.data(), static_cast<int>(Input.Plain.size())) == 1;
            OutLen = Len;
        }
        if (Ok)
        {
            Ok = EVP_EncryptFinal_ex(Context, Output.data() + OutLen, &Len) == 1;
            OutLen += Len;
        }
        if (Ok)
        {
            Ok = EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_GCM_GET_TAG, 16, Output.data() + OutLen) == 1;
        }
        if (!Ok || OutLen != static_cast<int>(Input.Plain.size()))
        {
            EVP_CIPHER_CTX_free(Context);
            return {};
        }
        Output.resize(static_cast<std::size_t>(OutLen) + 16);
        EVP_CIPHER_CTX_free(Context);
        return Output;
    }

    /**
     * @brief AES-128-GCM 解密（带 AAD）
     * @param Input 解密输入
     * @return 明文；失败返回空
     */
    [[nodiscard]] inline auto AesGcmOpen(const OpenInput &Input) -> std::vector<std::uint8_t>
    {
        if (Input.Cipher.size() < 16)
        {
            return {};
        }
        const auto CipherLen = Input.Cipher.size() - 16;
        const OpenInput ValidInput{
            Input.Key, Input.Nonce,
            std::span<const std::uint8_t>(Input.Cipher).subspan(0, CipherLen), Input.Aad};
        if (!ValidAesGcmInput(ValidInput))
        {
            return {};
        }
        std::vector<std::uint8_t> Output(CipherLen);
        EVP_CIPHER_CTX *Context = EVP_CIPHER_CTX_new();
        if (!Context)
        {
            return {};
        }
        int Len = 0;
        bool Ok = EVP_DecryptInit_ex(Context, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
        Ok = Ok && EVP_CIPHER_CTX_ctrl(Context, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
        Ok = Ok && EVP_DecryptInit_ex(Context, nullptr, nullptr, Input.Key.data(), Input.Nonce.data()) == 1;
        if (Ok && !Input.Aad.empty())
        {
            Ok = EVP_DecryptUpdate(
                     Context, nullptr, &Len, Input.Aad.data(), static_cast<int>(Input.Aad.size())) == 1;
        }
        int OutLen = 0;
        if (Ok && CipherLen > 0)
        {
            Ok = EVP_DecryptUpdate(
                     Context, Output.data(), &Len, Input.Cipher.data(), static_cast<int>(CipherLen)) == 1;
            OutLen = Len;
        }
        if (Ok)
        {
            Ok = EVP_CIPHER_CTX_ctrl(
                     Context,
                     EVP_CTRL_GCM_SET_TAG,
                     16,
                     const_cast<std::uint8_t *>(Input.Cipher.data()) + CipherLen) == 1;
        }
        if (Ok)
        {
            std::array<std::uint8_t, 16> FinalOutput{};
            std::uint8_t *FinalData = nullptr;
            if (Output.empty())
            {
                FinalData = FinalOutput.data();
            }
            else
            {
                FinalData = Output.data() + OutLen;
            }
            Ok = EVP_DecryptFinal_ex(Context, FinalData, &Len) == 1;
            OutLen += Len;
        }
        EVP_CIPHER_CTX_free(Context);
        if (!Ok || OutLen != static_cast<int>(CipherLen))
        {
            return {};
        }
        Output.resize(static_cast<std::size_t>(OutLen));
        return Output;
    }

    /**
     * @brief FNV-1a 32 位
     * @param Data 输入数据
     * @return 32 位哈希
     */
    [[nodiscard]] inline auto Fnv1a32(std::span<const std::uint8_t> Data) -> std::uint32_t
    {
        std::uint32_t H = 0x811C9DC5;
        for (const auto Byte : Data)
        {
            H ^= Byte;
            H *= 0x01000193;
        }
        return H;
    }

    /**
     * @brief AES-128-ECB 无填充加密
     */
    [[nodiscard]] inline auto AesEcbEncrypt(std::span<const std::uint8_t, 16> Key,
                                             std::span<const std::uint8_t, 16> Plain)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Out{};
        EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
        if (!Ctx)
        {
            return {};
        }
        int Len = 0;
        int Total = 0;
        const bool Ok = EVP_EncryptInit_ex(Ctx, EVP_aes_128_ecb(), nullptr, Key.data(), nullptr) == 1 &&
                        EVP_CIPHER_CTX_set_padding(Ctx, 0) == 1 &&
                        EVP_EncryptUpdate(Ctx, Out.data(), &Len, Plain.data(), Plain.size()) == 1;
        if (Ok)
        {
            Total = Len;
            const bool FinalOk = EVP_EncryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
            Total += Len;
            EVP_CIPHER_CTX_free(Ctx);
            if (!FinalOk || Total != static_cast<int>(Out.size()))
            {
                return {};
            }
            return Out;
        }
        EVP_CIPHER_CTX_free(Ctx);
        return {};
    }

    /**
     * @brief AES-128-ECB 无填充解密
     */
    [[nodiscard]] inline auto AesEcbDecrypt(std::span<const std::uint8_t, 16> Key,
                                             std::span<const std::uint8_t, 16> Cipher)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Out{};
        EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
        if (!Ctx)
        {
            return {};
        }
        int Len = 0;
        int Total = 0;
        const bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_128_ecb(), nullptr, Key.data(), nullptr) == 1 &&
                        EVP_CIPHER_CTX_set_padding(Ctx, 0) == 1 &&
                        EVP_DecryptUpdate(Ctx, Out.data(), &Len, Cipher.data(), Cipher.size()) == 1;
        if (Ok)
        {
            Total = Len;
            const bool FinalOk = EVP_DecryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
            Total += Len;
            EVP_CIPHER_CTX_free(Ctx);
            if (!FinalOk || Total != static_cast<int>(Out.size()))
            {
                return {};
            }
            return Out;
        }
        EVP_CIPHER_CTX_free(Ctx);
        return {};
    }

} // namespace Prism::Vmess::detail
