/**
 * @file ChunkCodec.hpp
 * @brief VMess 分块 AEAD 编解码与流状态机
 * @details 该文件只负责数据面分块：长度块、载荷块、Nonce 推进以及
 *          ChunkStream 的增量封装。认证头由 AuthCrypto.hpp、AuthKdf.hpp、AuthId.hpp、
 *          AuthHeader.hpp 实现，请求/响应头位于 RequestCodec.hpp 与 ResponseCodec.hpp。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Crypto/Aead.hpp>
#include <Prism/Protocols/Vmess/ChunkMask.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace Prism::Vmess
{

    /** @brief AuthenticatedLength EOF sentinel；加上 16 字节 AEAD 开销后按 uint16 回绕为零。 */
    inline constexpr std::uint16_t AuthenticatedLengthEofMarker = 0xFFF0U;

    /**
     * @brief VMess 分块加密器（状态机）
     */
    class ChunkEncryptor
    {
    public:
        /// 分块开销：2 长度 + 16 长度 tag + 16 载荷 tag
        static constexpr std::size_t Overhead = 2 + 16 + 16;

        /**
         * @brief 构造
         * @param Key 16 字节分块密钥
         * @param Nonce 12 字节起始 Nonce
         */
        explicit ChunkEncryptor(std::span<const std::uint8_t, 16> Key,
            std::span<const std::uint8_t, 12> Nonce);

        /**
         * @brief 构造标准 VMess 数据块编码器
         * @param Key 16 字节数据层密钥
         * @param Nonce 16 字节 request/response nonce
         * @param OptionsValue 请求头 option 位
         */
        explicit ChunkEncryptor(std::span<const std::uint8_t, 16> Key,
            std::span<const std::uint8_t, 16> Nonce, std::uint8_t OptionsValue);

        /**
         * @brief 加密一块数据
         * @details 明文长度不得超过 MaxChunkLen；Finish 成功后进入终态，后续 Seal 返回 0。
         * @param Plain 明文
         * @param Out 输出（容量至少为 Plain.size() + Overhead）
         * @return 写入字节数（含块头）
         */
        auto Seal(std::span<const std::uint8_t> Plain, std::span<std::uint8_t> Out) -> std::size_t;

        /**
         * @brief 写出流结束标记
         * @details 成功后进入终态，后续 Seal 和 Finish 返回 0；缓冲不足时不改变状态。
         * @param Out 输出（容量至少为 18）
         * @return AuthenticatedLength 写入认证长度 marker，否则写入两字节零长度。
         */
        auto Finish(std::span<std::uint8_t> Out) -> std::size_t;

    private:
        [[nodiscard]] auto SealChunk(std::span<const std::uint8_t> Nonce, std::span<const std::uint8_t> Plain,
            std::span<std::uint8_t> Out) -> bool;

        [[nodiscard]] auto UseAuthenticatedLength() const noexcept -> bool;

        [[nodiscard]] auto NextMask() -> std::uint16_t;

        std::array<std::uint8_t, 16> Key_;
        std::array<std::uint8_t, 16> NonceSeed_;
        std::array<std::uint8_t, 12> LegacyNonce_;
        Prism::Crypto::AeadContext Aead_;
        std::uint8_t Options_{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
        std::uint16_t NonceCount_{0};
        std::optional<ShakeStream> MaskStream_;
        bool Finished_{false};
    };

    /**
     * @brief VMess 分块解密器（状态机，支持增量两步解析）
     * @details 识别结束 marker 后进入终态；后续 OpenLen、OpenPayload 和 Open 均返回 ProtocolError。
     */
    class ChunkDecryptor
    {
    public:
        /**
         * @brief 构造
         * @param Key 16 字节分块密钥
         * @param Nonce 12 字节起始 Nonce
         */
        explicit ChunkDecryptor(std::span<const std::uint8_t, 16> Key,
            std::span<const std::uint8_t, 12> Nonce);

        /**
         * @brief 构造标准 VMess 数据块解码器
         * @param Key 16 字节数据层密钥
         * @param Nonce 16 字节 request/response nonce
         * @param OptionsValue 请求头 option 位
         */
        explicit ChunkDecryptor(std::span<const std::uint8_t, 16> Key,
            std::span<const std::uint8_t, 16> Nonce, std::uint8_t OptionsValue);

        /**
         * @brief 解密长度字段（2 字节密文 + 16 tag）
         * @param Head 18 字节块头
         * @return 载荷长度、AuthenticatedLength EOF marker 或错误码；legacy 零长度也结束流。
         * @note 识别任一结束 marker 后进入终态，后续解析返回 ProtocolError。
         */
        auto OpenLen(std::span<const std::uint8_t> Head) -> std::expected<std::size_t, Error>;

        /**
         * @brief 解密载荷字段
         * @param Data 载荷密文块（长度 + 16）
         * @param Out 输出明文
         * @return 错误码；识别结束 marker 后调用返回 ProtocolError。
         */
        auto OpenPayload(std::span<const std::uint8_t> Data, std::span<std::uint8_t> Out) -> Error;

        /**
         * @brief 解密一块完整数据
         * @param Data 完整密文块
         * @param Out 输出明文
         * @param Consumed 输出消耗字节数；错误时为 0，成功 marker 时为头部长度。
         * @return 错误码；NeedMore 表示数据不足
         */
        auto Open(std::span<const std::uint8_t> Data, std::span<std::uint8_t> Out, std::size_t& Consumed)
            -> Error;

    private:
        [[nodiscard]] auto OpenChunk(std::span<const std::uint8_t> Nonce,
            std::span<const std::uint8_t> Cipher, std::span<std::uint8_t> Out) -> bool;

        [[nodiscard]] auto UseAuthenticatedLength() const noexcept -> bool;

        [[nodiscard]] auto NextMask() -> std::uint16_t;

        std::array<std::uint8_t, 16> Key_;
        std::array<std::uint8_t, 16> NonceSeed_;
        std::array<std::uint8_t, 12> LegacyNonce_;
        Prism::Crypto::AeadContext Aead_;
        std::uint8_t Options_{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
        std::uint16_t NonceCount_{0};
        std::optional<ShakeStream> MaskStream_;
        bool Finished_{false};
    };

    /**
     * @brief VMess 会话级分块流（Beast 风格封装）
     * @details 加密和解密方向各自维护独立 Nonce 状态。
     */
    class ChunkStream
    {
    public:
        /**
         * @brief 解密结果
         */
        struct Result
        {
            /// 错误码（Error::None 成功）
            std::error_code Ec;
            /// 已消耗 wire 字节数
            std::size_t Consumed{0};
        };

        /**
         * @brief 初始化
         * @param Key 16 字节分块密钥
         * @param Iv 16 字节分块 IV（Nonce 取前 12 字节）
         */
        auto Init(std::span<const std::uint8_t, 16> Key, std::span<const std::uint8_t, 16> Iv) -> void;

        /**
         * @brief 加密一块载荷；空输入写入 VMess 结束 marker。
         * @details marker 成功写出后流进入终态，后续 Encrypt 返回失败。
         * @param Payload 明文
         * @param Wire 输出密文
         * @return false 表示成功，true 表示加密失败
         */
        auto Encrypt(std::span<const std::uint8_t> Payload, std::string& Wire) -> bool;

        /**
         * @brief 解密一块密文
         * @details 解码结束 marker 后流进入终态，后续 Decrypt 返回 ProtocolError。
         * @param Wire 密文（完整块）
         * @param Plain 输出明文
         * @return 解密结果
         */
        auto Decrypt(std::span<const std::uint8_t> Wire, std::string& Plain) -> Result;

    private:
        ChunkEncryptor Enc_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
        ChunkDecryptor Dec_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
    };

} // namespace Prism::Vmess
