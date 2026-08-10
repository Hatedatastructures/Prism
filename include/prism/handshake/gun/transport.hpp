/**
 * @file transport.hpp
 * @brief gRPC (gun) 传输装饰器
 * @details 继承 transmission，将 h2 流的字节流转换为 gun 帧语义：
 *          读：解析 gun 帧 → 返回 payload；写：封装 gun 帧 → 写入 h2 流。
 *          供内层协议（VLESS/Trojan）作为传输层使用。
 *          数据投递经 concurrent_channel 事件驱动（无轮询）。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <functional>
#include <memory>

namespace psm::handshake::gun
{

    namespace net = boost::asio;

    /**
     * @class transport
     * @brief gun 帧传输装饰器
     * @details 持有 h2 会话的写入回调与读取缓冲：
     *          服务端收到 DATA 帧 → session 解帧 → push 到这里；
     *          写操作 → session 封帧发送。
     */
    class transport final : public psm::transport::transmission
    {
    public:
        /// 写入回调（由 session 提供：封帧后提交 nghttp2）
        using write_cb = std::function<net::awaitable<void>(memory::vector<std::byte>)>;

        /**
         * @brief 构造 gun 传输
         * @param executor 执行器
         * @param write_fn 帧写入回调
         * @param mr 内存资源
         */
        transport(net::any_io_executor executor, write_cb write_fn,
                  memory::resource_pointer mr = memory::current_resource());

        [[nodiscard]] auto executor() const -> executor_type override;

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;

        void cancel() override;

        [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 投递一段解帧后的明文数据（由 session 帧解析循环调用）
         * @param data 明文数据
         * @return 投递是否成功（false 表示已关闭或通道拥塞，数据被丢弃）
         */
        auto push(std::span<const std::byte> data) -> bool;

        /// 通知对端流结束（EOF）
        void notify_eof();

    private:
        using channel_type = net::experimental::concurrent_channel<
            void(boost::system::error_code, memory::vector<std::byte>)>;

        net::any_io_executor executor_;
        write_cb write_fn_;
        memory::resource_pointer mr_;
        std::unique_ptr<channel_type> channel_; ///< 明文数据通道
        memory::vector<std::byte> current_;      ///< 当前消费块
        std::size_t current_offset_{0};          ///< 消费游标
        bool closed_{false};                     ///< 本地关闭
    };

    using shared_transport = std::shared_ptr<transport>;

    /**
     * @brief 创建 gun 传输
     * @param executor 执行器
     * @param write_fn 帧写入回调
     * @param mr 内存资源
     */
    [[nodiscard]] inline auto make_transport(net::any_io_executor executor, transport::write_cb write_fn,
                                             memory::resource_pointer mr = memory::current_resource())
        -> shared_transport
    {
        return std::make_shared<transport>(std::move(executor), std::move(write_fn), mr);
    }

} // namespace psm::handshake::gun
