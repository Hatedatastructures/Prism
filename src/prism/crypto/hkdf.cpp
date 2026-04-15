#include <prism/crypto/hkdf.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <prism/trace.hpp>

namespace psm::crypto
{
    constexpr std::string_view HkdfTag = "[Crypto.HKDF]";

    // HMAC-SHA256：用密钥对数据进行消息认证。
    // 在 TLS 1.3 中用于：
    // - HKDF-Extract（提取伪随机密钥）
    // - Finished 消息的 verify_data 计算
    // 直接调用 BoringSSL 的 HMAC API。
    auto hmac_sha256(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> result{};

        unsigned int mac_len = 0;
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             data.data(), data.size(), result.data(), &mac_len);

        return result;
    }

    // HMAC-SHA512：类似 hmac_sha256，但输出 64 字节。
    // 在 Reality 协议中用于 Ed25519 自签名证书的签名值计算：
    // 签名 = HMAC-SHA512(auth_key, ed25519_public_key)
    auto hmac_sha512(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA512_LEN>
    {
        std::array<std::uint8_t, SHA512_LEN> result{};

        unsigned int mac_len = 0;
        HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()),
             data.data(), data.size(), result.data(), &mac_len);

        return result;
    }

    // HKDF-Extract：RFC 5869 Step 1 —— 从输入密钥材料中提取伪随机密钥（PRK）。
    // PRK = HMAC-SHA256(salt, IKM)
    // salt 为空时使用 Hash.len 字节全零作为盐。
    // 在 TLS 1.3 密钥调度中反复使用：early_secret、handshake_secret、master_secret 都通过它提取。
    auto hkdf_extract(const std::span<const std::uint8_t> salt, const std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        // salt 为空时使用全零
        if (salt.empty())
        {
            std::array<std::uint8_t, SHA256_LEN> zero_salt{};
            return hmac_sha256(zero_salt, ikm);
        }
        return hmac_sha256(salt, ikm);
    }

    // HKDF-Expand：RFC 5869 Step 2 —— 将 PRK 扩展为指定长度的输出密钥。
    //
    // 核心迭代公式：T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
    // - T(0) = 空串
    // - counter 从 1 开始，每轮递增
    // - 最多迭代 255 轮（每轮输出 32 字节，最大 8160 字节）
    //
    // 输出 = T(1) || T(2) || ... 截取到所需长度。
    auto hkdf_expand(const std::span<const std::uint8_t> prk, const std::span<const std::uint8_t> info,
                     const std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        // RFC 5869: 最大输出长度 = 255 * HashLen
        if (length > 255 * SHA256_LEN)
        {
            trace::error("{} HKDF-Expand requested length {} exceeds max {}", HkdfTag, length, 255 * SHA256_LEN);
            return {fault::code::invalid_argument, {}};
        }

        if (prk.size() < SHA256_LEN)
        {
            trace::error("{} HKDF-Expand PRK too short: {}", HkdfTag, prk.size());
            return {fault::code::invalid_argument, {}};
        }

        std::vector<std::uint8_t> result;
        result.reserve(length);

        // T(0) = empty
        // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        std::array<std::uint8_t, SHA256_LEN> t{};
        std::size_t t_size = 0;
        std::size_t offset = 0;
        std::uint8_t counter = 1;

        while (offset < length)
        {
            // 构造 HMAC 输入: T(i-1) || info || counter（栈缓冲，最大 ~289 字节）
            constexpr std::size_t max_hmac_input_size = SHA256_LEN + 256 + 1;
            std::array<std::uint8_t, max_hmac_input_size> hmac_buf{};
            const auto hmac_size = t_size + info.size() + 1;
            if (t_size > 0)
            {
                std::memcpy(hmac_buf.data(), t.data(), t_size);
            }
            if (!info.empty())
            {
                std::memcpy(hmac_buf.data() + t_size, info.data(), info.size());
            }
            hmac_buf[hmac_size - 1] = counter;

            const auto block = hmac_sha256(prk.first(SHA256_LEN), {hmac_buf.data(), hmac_size});

            // 截取本轮输出中需要的部分
            const auto to_copy = std::min(SHA256_LEN, length - offset);
            result.insert(result.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(to_copy));
            offset += to_copy;

            // T(i) = 完整的 block（不是截断后的），作为下一轮的输入
            t = block;
            t_size = SHA256_LEN;
            ++counter;
        }

        return {fault::code::success, std::move(result)};
    }

    // HKDF-Expand-Label：TLS 1.3 专用的密钥派生函数（RFC 8446 Section 7.1）。
    //
    // 和标准 HKDF-Expand 的区别在于 info 的构造方式：
    // HkdfLabel = {
    //   uint16 length;              // 期望输出的字节数
    //   opaque label<7..255>;       // "tls13 " + 用户指定的 label
    //   opaque context<0..255>;     // 上下文数据（通常是 transcript hash）
    // }
    //
    // 这个函数是 TLS 1.3 密钥调度的核心，所有密钥（握手密钥、应用密钥、finished_key 等）
    // 都通过它派生。label 区分不同的用途（"key"、"iv"、"finished"、"derived" 等）。
    auto hkdf_expand_label(const std::span<const std::uint8_t> secret, const std::string_view label,
                           const std::span<const std::uint8_t> context, const std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        // "tls13 " 前缀 + 用户 label（如 "tls13 key"、"tls13 iv"、"tls13 derived"）
        static constexpr std::string_view tls13_prefix = "tls13 ";
        const auto full_label_len = tls13_prefix.size() + label.size();

        if (full_label_len > 255)
        {
            trace::error("{} HKDF-Expand-Label label too long: {}", HkdfTag, full_label_len);
            return {fault::code::invalid_argument, {}};
        }

        if (context.size() > 255)
        {
            trace::error("{} HKDF-Expand-Label context too long: {}", HkdfTag, context.size());
            return {fault::code::invalid_argument, {}};
        }

        // 组装 HkdfLabel 结构体（栈缓冲）：
        // Length(2) || LabelLen(1) || Label(N) || ContextLen(1) || Context(N)
        constexpr std::size_t max_hkdf_label_size = 2 + 1 + 255 + 1 + 255;
        std::array<std::uint8_t, max_hkdf_label_size> label_buf{};
        std::size_t pos = 0;

        // Length: 2 字节大端序
        label_buf[pos++] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
        label_buf[pos++] = static_cast<std::uint8_t>(length & 0xFF);

        // Label: 1 字节长度前缀 + "tls13 " + 用户 label
        label_buf[pos++] = static_cast<std::uint8_t>(full_label_len);
        std::memcpy(label_buf.data() + pos, tls13_prefix.data(), tls13_prefix.size());
        pos += tls13_prefix.size();
        std::memcpy(label_buf.data() + pos, label.data(), label.size());
        pos += label.size();

        // Context: 1 字节长度前缀 + 内容
        label_buf[pos++] = static_cast<std::uint8_t>(context.size());
        if (!context.empty())
        {
            std::memcpy(label_buf.data() + pos, context.data(), context.size());
            pos += context.size();
        }

        return hkdf_expand(secret, {label_buf.data(), pos}, length);
    }

    // SHA-256 单数据块哈希。直接调用 BoringSSL 的 SHA256。
    // 用于计算空字符串的哈希（SHA-256("")）等简单场景。
    auto sha256(const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> hash{};
        ::SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    // SHA-256 两数据块哈希。使用 EVP_MD_CTX 流式接口，
    // 先喂 data1 再喂 data2，等价于 SHA-256(data1 || data2)。
    // 在 TLS 1.3 中用于计算 hello_hash = SHA-256(ClientHello || ServerHello)。
    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> hash{};

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return hash;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return hash;
        }

        EVP_DigestUpdate(ctx, data1.data(), data1.size());
        EVP_DigestUpdate(ctx, data2.data(), data2.size());

        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        return hash;
    }

    // SHA-256 三数据块哈希。用于计算 transcript hash。
    // 如 SHA-256(CH || SH || EE+Cert+CV) 用于 CertificateVerify，
    // SHA-256(CH || SH || EE+Cert+CV+Finished) 用于应用密钥派生。
    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2,
                const std::span<const std::uint8_t> data3)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> hash{};

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return hash;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return hash;
        }

        EVP_DigestUpdate(ctx, data1.data(), data1.size());
        EVP_DigestUpdate(ctx, data2.data(), data2.size());
        EVP_DigestUpdate(ctx, data3.data(), data3.size());

        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        return hash;
    }
} // namespace psm::crypto
