/**
 * @file conn.hpp
 * @brief SS2022 (SIP022) 协议中继器声明
 * @details SS2022 relay 是一个 AEAD 加密传输层装饰器。与 Trojan/VLESS 不同，
 * SS2022 relay 在整个会话生命周期内保持活跃，因为所有数据都经过 AEAD 加解密。
 * handshake() 解密请求头、验证时间戳、解析地址后，relay 继续作为 transmission
 * 提供加解密的读写操作
 */
#pragma once

#include <prism/crypto/aead.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/protocol/shadowsocks/config.hpp>
#include <prism/protocol/shadowsocks/constants.hpp>
#include <prism/protocol/shadowsocks/packet.hpp>
#include <prism/protocol/shadowsocks/util/salts.hpp>
#include <prism/protocol/types.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <memory>
#include <span>
#include <tuple>


namespace psm::protocol::shadowsocks
{

    namespace net = boost::asio;
    using shared_transmission = psm::transport::shared_transmission;

    /**
     * @class conn
     * @brief SS2022 AEAD 流加密中继器
     * @details 继承 transmission，在底层传输层之上添加 SS2022 协议的 AEAD
     * 加解密功能。handshake() 完成后，async_read_some/async_write_some
     * 自动处理 AEAD 分帧加密/解密。读取状态机为 header 到解密 2B 长度
     * 到 payload 到解密 payload 到返回数据。写入流程为将数据分块到加密
     * 长度加 payload 到 scatter-gather 写入底层
     */
    class conn : public transport::transmission, public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 获取内层传输指针（装饰器链导航）
         * @return transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> transport::transmission * override
        {
            return next_layer_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transport::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 构造函数
         * @param next_layer 底层传输层，必须已建立连接
         * @param cfg SS2022 协议配置
         * @param salts Salt 重放保护池，worker 线程独占
         */
        explicit conn(shared_transmission next_layer, const config &cfg, std::shared_ptr<salt_pool> salts);

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         */
        [[nodiscard]] auto executor() const
            -> executor_type override;

        /**
         * @brief 异步读取数据
         * @details 从底层传输层读取 AEAD 加密帧并解密返回明文
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @details 将明文数据加密为 AEAD 帧后写入底层传输层
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 关闭传输层
         */
        void close() override;

        /**
         * @brief 取消所有未完成的异步操作
         */
        void cancel() override;

        /**
         * @brief 执行 SS2022 握手
         * @details 读取请求 salt，派生会话密钥，解密固定/变长头，
         * 验证时间戳和 salt 唯一性，解析目标地址。
         * 握手成功后需调用 acknowledge() 发送响应
         * @return 错误码和请求信息
         */
        [[nodiscard]] auto handshake()
            -> net::awaitable<std::pair<fault::code, request>>;

        /**
         * @brief 发送 SS2022 握手响应
         * @details 必须在 handshake() 成功后调用。将响应发送延迟到
         * 上游拨号成功后，避免拨号失败时客户端收到误导性的成功响应
         * @return 错误码
         */
        [[nodiscard]] auto acknowledge()
            -> net::awaitable<fault::code>;

        /**
         * @brief 获取解析后的目标地址
         * @return 目标地址的常量引用
         */
        [[nodiscard]] auto target() const noexcept
            -> const protocol::target &
        {
            return target_;
        }

    private:
        shared_transmission next_layer_;       // 底层传输层
        config config_;                        // SS2022 协议配置
        std::shared_ptr<salt_pool> salt_pool_; // Salt 重放保护池

        std::unique_ptr<crypto::aead_context> decrypt_ctx_; // 解密上下文
        std::unique_ptr<crypto::aead_context> encrypt_ctx_; // 加密上下文
        cipher_method method_{cipher_method::aes_128_gcm};  // 加密方法
        std::size_t key_salt_len_{16};                   // 密钥/salt 长度

        memory::vector<std::uint8_t> psk_; // 解码后的 PSK

        memory::vector<std::byte> decrypted_; // 解密后的数据缓冲区
        std::size_t decrypted_off_{0};     // 已消费的解密缓冲区偏移

        std::array<std::byte, len_block_size> length_buf_{}; // 加密长度块缓冲区（2+16=18字节）
        memory::vector<std::byte> chunk_buf_;                   // 加密 payload 块缓冲区
        std::uint16_t cur_payload_len_{0};                  // 当前 chunk 的 payload 长度

        memory::vector<std::byte> init_payload_; // 握手中的初始 payload
        std::size_t init_off_{0};             // 初始 payload 偏移

        memory::vector<std::uint8_t> payload_enc_buf_; // 发送加密缓冲区（复用）

        protocol::target target_; // 目标地址

        memory::vector<std::uint8_t> client_salt_; // 延迟响应所需的客户端 salt
        std::int64_t handshake_ts_{0};             // 握手时间戳

        /**
         * @brief 从 PSK + salt 派生 AEAD 上下文
         * @param salt 盐值
         * @return AEAD 上下文智能指针
         */
        [[nodiscard]] auto derive_aead_context(std::span<const std::uint8_t> salt) const
            -> std::unique_ptr<crypto::aead_context>;

        /**
         * @brief 读取并验证加密固定头
         * @details 读取 type + timestamp + varHeaderLen
         * @return 错误码、变长头长度和时间戳
         */
        [[nodiscard]] auto read_fixed_hdr() const
            -> net::awaitable<std::tuple<fault::code, std::uint16_t, std::int64_t>>;

        /**
         * @brief 读取并解析加密变长头
         * @details 解析地址 + padding + 初始 payload
         * @param var_header_len 变长头长度
         * @param req 请求结构，解析结果填充到此对象
         * @return 错误码
         */
        [[nodiscard]] auto read_var_hdr(std::uint16_t var_hdr_len, request &req)
            -> net::awaitable<fault::code>;

        /**
         * @brief 构建并发送服务端响应
         * @param client_salt 客户端 salt
         * @param server_ts 服务端时间戳
         * @return 错误码
         */
        [[nodiscard]] auto send_response(std::span<const std::uint8_t> client_salt, std::int64_t server_ts)
            -> net::awaitable<fault::code>;

        /**
         * @brief 读取并解密下一个数据块到 decrypted_
         * @param ec 错误码输出参数
         * @return 异步操作
         */
        [[nodiscard]] auto fetch_chunk(std::error_code &ec)
            -> net::awaitable<void>;

        /**
         * @brief 加密并写入一个数据块
         * @param data 待加密的明文数据
         * @param ec 错误码输出参数
         * @return 实际写入的字节数
         */
        [[nodiscard]] auto send_chunk(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;
    };

    using shared_conn = std::shared_ptr<conn>;

    /**
     * @brief 创建 SS2022 中继器
     * @param next_layer 底层传输层
     * @param cfg SS2022 协议配置
     * @param salts Salt 重放保护池
     * @return shared_conn 中继器共享指针
     */
    [[nodiscard]] inline auto make_conn(shared_transmission next_layer, const config &cfg, std::shared_ptr<salt_pool> salts)
        -> shared_conn
    {
        return std::make_shared<conn>(std::move(next_layer), cfg, std::move(salts));
    }
} // namespace psm::protocol::shadowsocks
