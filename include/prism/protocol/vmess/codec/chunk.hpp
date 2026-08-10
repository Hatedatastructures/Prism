/**
 * @file chunk.hpp
 * @brief VMess 数据分块流编解码
 * @details 线上格式（AEAD 模式，ChunkStream + ChunkMasking）：
 *   [len 2B（XOR SHAKE128 掩码）][GCM 密文 payload][可选 padding]
 *   len 含 padding；SHAKE128 流由 requestNonce/responseNonce 派生，
 *   GlobalPadding 消费先于 ChunkMasking。
 *   数据层 AEAD nonce = [2B 大端计数][源 nonce[2:12]]。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/protocol/vmess/constants.hpp>

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace psm::protocol::vmess::codec
{

    namespace net = boost::asio;

    /**
     * @class shake_stream
     * @brief 增量 SHAKE128 XOF 输出流
     * @details 手写 Keccak-f[1600]（rate=168 字节），支持任意长度
     *          连续输出，与 Go x/crypto/sha3.ShakeHash 字节兼容。
     */
    class shake_stream
    {
    public:
        explicit shake_stream(std::span<const std::uint8_t> seed);

        /// 读取下一段 XOF 输出（一次性返回内部缓冲剩余段）
        [[nodiscard]] auto next() -> std::span<const std::uint8_t>;

    private:
        std::array<std::uint64_t, 25> state_{};  ///< Keccak 状态
        std::array<std::uint8_t, 168> buffer_{}; ///< 输出缓冲
        std::size_t cursor_{168};                ///< 缓冲消费游标
    };

    /**
     * @struct stream_params
     * @brief 数据流构造参数（聚合，遵守 Rule 1）
     */
    struct stream_params
    {
        transport::transmission *transport{nullptr}; ///< 底层传输层
        std::array<std::uint8_t, 16> key{};          ///< 数据加密密钥
        std::array<std::uint8_t, 16> nonce{};        ///< nonce 源（取 [2:12]）
        std::uint8_t option{0};                      ///< 选项位
        std::uint8_t security{0};                    ///< 安全类型
    };

    /**
     * @class read_stream
     * @brief VMess 数据块读取流（服务端侧）
     * @details 每次 read_chunk 返回一个完整块明文。
     *          len==0 表示对端 EOF。支持 GlobalPadding 丢弃。
     */
    class read_stream
    {
    public:
        explicit read_stream(stream_params params);

        /**
         * @brief 读取一个数据块并解密
         * @param out 明文输出缓冲
         * @param ec 错误码输出
         * @return 明文长度（0 表示 EOF）
         */
        [[nodiscard]] auto read_chunk(std::span<std::byte> out, std::error_code &ec)
            -> net::awaitable<std::size_t>;

    private:
        stream_params params_;
        std::unique_ptr<shake_stream> mask_stream_;    ///< 掩码派生流
        std::unique_ptr<shake_stream> padding_stream_; ///< 填充派生流
        std::uint16_t nonce_count_{0};                 ///< AEAD nonce 计数
        std::unique_ptr<EVP_AEAD_CTX, void (*)(EVP_AEAD_CTX *)> aead_; ///< 数据加密上下文
    };

    /**
     * @class write_stream
     * @brief VMess 数据块写入流（服务端侧）
     * @details write_chunk 将一块数据密封后写出。
     */
    class write_stream
    {
    public:
        explicit write_stream(stream_params params);

        /**
         * @brief 密封并写入一个数据块
         * @param data 明文数据
         * @param ec 错误码输出
         * @return 写入字节数
         */
        [[nodiscard]] auto write_chunk(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /// 刷新并完成写流（写 len=0 终止块）
        [[nodiscard]] auto finish(std::error_code &ec) -> net::awaitable<std::size_t>;

    private:
        stream_params params_;
        std::unique_ptr<shake_stream> mask_stream_;
        std::unique_ptr<shake_stream> padding_stream_;
        std::uint16_t nonce_count_{0};
        std::unique_ptr<EVP_AEAD_CTX, void (*)(EVP_AEAD_CTX *)> aead_;
    };

} // namespace psm::protocol::vmess::codec
