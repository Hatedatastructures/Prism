/**
 * @file DatagramAdapter.hpp
 * @brief QUIC 数据报提供者与 Preview 传输适配器
 * @details 仅定义 QUIC 数据报数据面的最小异步契约，不包含 ngtcp2
 *          握手、连接建立或拥塞控制实现。底层 QUIC 会话实现
 *          DatagramProvider 后，由 DatagramAdapter 转换为
 *          Transmission::Type::Udp，供协议数据面复用。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <system_error>

#include <preview/Transport/Transmission.hpp>

namespace Preview::Quic
{

    namespace net = boost::asio;

    /**
     * @class DatagramProvider
     * @brief QUIC 数据报数据面提供者
     * @details 提供者由 QUIC 会话或测试实现注入；每次 Receive/Send
     *          对应一个数据报，禁止把一次短写自动拆成多个数据报。
     */
    class DatagramProvider
    {
    public:
        virtual ~DatagramProvider() noexcept = default;

        /**
         * @brief 获取异步操作执行器
         */
        [[nodiscard]] virtual auto Executor() const -> net::any_io_executor = 0;

        /**
         * @brief 接收一个数据报
         * @param Buffer 接收缓冲区
         * @param Ec 错误码输出
         * @return 实际接收字节数；数据报超过缓冲区时由实现定义截断策略
         */
        [[nodiscard]] virtual auto Receive(std::span<std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 发送一个数据报
         * @param Buffer 待发送数据报
         * @param Ec 错误码输出
         * @return 实际发送字节数；返回值小于 Buffer.size() 时视为短写
         */
        [[nodiscard]] virtual auto Send(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 关闭数据报提供者
         */
        virtual void Close() = 0;

        /**
         * @brief 取消挂起的数据报操作
         */
        virtual void Cancel() = 0;

        /**
         * @brief 查询提供者是否已关闭
         */
        [[nodiscard]] virtual auto IsClosed() const noexcept -> bool = 0;
    };

    /// 数据报提供者共享指针
    using SharedDatagramProvider = std::shared_ptr<DatagramProvider>;

    /**
     * @class DatagramAdapter
     * @brief 将数据报提供者适配为 Preview Transmission
     * @details 对外暴露 Udp 传输类型。读取直接委托提供者；写入若提供者
     *          返回短写，则返回已发送字节数并设置 IoError，阻止协议层
     *          把单个数据报剩余部分误发成第二个数据报。
     */
    class DatagramAdapter final : public Preview::Transmission
    {
    public:
        /**
         * @brief 构造适配器
         * @param Provider 数据报提供者（所有权移交）
         */
        explicit DatagramAdapter(SharedDatagramProvider Provider)
            : Provider_(std::move(Provider))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Provider_ ? Provider_->Executor() : ExecutorType{};
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Provider_)
            {
                Ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await Provider_->Receive(Buffer, Ec);
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            if (!Provider_)
            {
                Ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            const auto Written = co_await Provider_->Send(Buffer, Ec);
            if (!Ec && Written != Buffer.size())
            {
                Ec = make_error_code(Error::IoError);
            }
            co_return Written;
        }

        void Close() override
        {
            if (Provider_)
            {
                Provider_->Close();
            }
        }

        void Cancel() override
        {
            if (Provider_)
            {
                Provider_->Cancel();
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Provider_ && !Provider_->IsClosed();
        }

        [[nodiscard]] auto Provider() const noexcept -> SharedDatagramProvider
        {
            return Provider_;
        }

    private:
        SharedDatagramProvider Provider_;
    };

    /// 数据报适配器共享指针
    using SharedDatagramAdapter = std::shared_ptr<DatagramAdapter>;

} // namespace Preview::Quic
