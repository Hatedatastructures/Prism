#include <prism/crypto/block.hpp>
#include <openssl/evp.h>
#include <cstring>

namespace psm::crypto
{
    auto aes_ecb_encrypt(const std::span<const std::uint8_t, 16> input, const std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};

        const EVP_CIPHER *cipher = nullptr;
        if (key.size() == 16)
        {
            cipher = EVP_aes_128_ecb();
        }
        else
        {
            cipher = EVP_aes_256_ecb();
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr);

        // 禁用填充（输入已是完整块）
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        int out_len = 0;
        EVP_EncryptUpdate(ctx, out.data(), &out_len, input.data(), 16);
        EVP_EncryptFinal_ex(ctx, out.data() + out_len, &out_len);

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    auto aes_ecb_decrypt(const std::span<const std::uint8_t, 16> input, const std::span<const std::uint8_t> key)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};

        const EVP_CIPHER *cipher = nullptr;
        if (key.size() == 16)
        {
            cipher = EVP_aes_128_ecb();
        }
        else
        {
            cipher = EVP_aes_256_ecb();
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), nullptr);

        // 禁用填充
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        int out_len = 0;
        EVP_DecryptUpdate(ctx, out.data(), &out_len, input.data(), 16);
        EVP_DecryptFinal_ex(ctx, out.data() + out_len, &out_len);

        EVP_CIPHER_CTX_free(ctx);
        return out;
    }
} // namespace psm::crypto
