/**
 * @file session.hpp
 * @brief Reality 加密传输层
 * @details 实现 TLS 1.3 应用数据记录的加密/解密传输层，
 * 继承 transmission 接口，替代 BoringSSL 的 encrypted 传输层，
 * 提供 Reality 协议所需的 TLS 1.3 应用数据加密通道
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <memory>
#include <system_error>
#include <prism/channel/transport/transmission.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/memory/container.hpp>
#include <prism/stealth/reality/constants.hpp>
#include <prism/stealth/reality/keygen.hpp>
#include <boost/asio.hpp>

namespace psm::stealth
{
    namespace net = boost::asio;

    /**
     * @class seal
     * @brief Reality 加密传输层
     * @details 封装 TLS 1.3 应用数据记录的加密/解密。
     * 读取时从底层传输读取加密的 TLS 记录后解密并缓冲明文，
     * 写入时将明文加密为 TLS 记录后写入底层传输。
     * 使用 AES-128-GCM AEAD 加密，nonce 由 IV 和序列号异或生成。
     */
    class seal final : public channel::transport::transmission
    {
    public:
        /**
         * @brief 构造加密传输层
         * @param transport 底层传输连接
         * @param keys TLS 1.3 密钥材料
         * @details 使用密钥材料初始化加密和解密上下文，
         * 服务端密钥用于加密（写入），客户端密钥用于解密（读取）
         */
        explicit seal(channel::transport::shared_transmission transport,
                      key_material keys);

        /**
         * @brief 检查传输是否可靠
         * @details 始终返回 true，seal 基于 TCP 传输
         * @return bool 始终返回 true
         */
        [[nodiscard]] auto is_reliable() const noexcept -> bool override;

        /**
         * @brief 获取执行器
         * @details 返回底层传输的执行器，用于协程调度
         * @return executor_type 执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override;

        /**
         * @brief 异步读取解密后的数据
         * @details 优先从明文缓冲区返回已解密数据，缓冲区耗尽后
         * 从底层传输读取加密记录并解密填充缓冲区
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，返回读取字节数
         */
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步加密写入数据
         * @details 将明文数据加密为 TLS 记录后写入底层传输
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，返回写入字节数
         */
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief Scatter-gather 加密写入
         * @details 将多个缓冲区拼接到 scatter_buf_ 后一次性加密写入，
         * 避免多次加密和写入的系统调用开销
         * @param buffers 缓冲区数组
         * @param count 缓冲区数量
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，返回写入字节数
         */
        auto async_write_scatter(const std::span<const std::byte> *buffers, std::size_t count,
                                 std::error_code &ec) -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         * @details 关闭底层传输连接，清空明文缓冲区
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消底层传输的挂起操作
         */
        void cancel() override;

    private:
        /**
         * @brief 从底层传输读取并解密一个 TLS 记录
         * @details 读取 TLS 记录头获取长度，再读取密文体，
         * 使用客户端密钥解密后将明文存入 plaintext_buffer_
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，返回解密后的明文长度
         */
        auto read_encrypted_record(std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /**
         * @brief 加密并写入一个 TLS 记录
         * @details 使用服务端密钥加密数据，构造 TLS 记录后写入底层传输
         * @param data 明文数据
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，返回写入字节数
         */
        auto write_encrypted_record(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /**
         * @brief 生成 AEAD nonce
         * @details 将 IV 和序列号按字节异或生成 nonce
         * @param iv 初始化向量
         * @param sequence 序列号
         * @return 生成的 nonce
         */
        [[nodiscard]] auto make_nonce(std::span<const std::uint8_t> iv, std::uint64_t sequence) const
            -> std::array<std::uint8_t, tls::AEAD_NONCE_LEN>;

        channel::transport::shared_transmission transport_; // 底层传输连接
        key_material keys_;                                 // TLS 1.3 密钥材料

        crypto::aead_context server_encryptor_; // 服务端加密上下文（用于写入）
        crypto::aead_context client_decryptor_; // 客户端解密上下文（用于读取）

        std::uint64_t read_sequence_ = 0;  // 读取序列号，用于生成 nonce
        std::uint64_t write_sequence_ = 0; // 写入序列号，用于生成 nonce

        bool first_write_logged_ = false; // 首次写入日志标志
        bool first_read_logged_ = false;  // 首次读取日志标志

        memory::vector<std::byte> plaintext_buffer_; // 解密后的明文缓冲区
        std::size_t plaintext_offset_ = 0;           // 明文缓冲区当前读取偏移

        memory::vector<std::byte> record_body_buf_;         // TLS 记录体读取缓冲区
        memory::vector<std::uint8_t> decrypted_buf_;        // 解密输出缓冲区
        memory::vector<std::uint8_t> write_plain_buf_;      // 写入明文拼接缓冲区
        memory::vector<std::uint8_t> write_ciphertext_buf_; // 写入密文缓冲区
        memory::vector<std::byte> scatter_buf_;             // scatter-gather 拼接缓冲区
    };
} // namespace psm::stealth
