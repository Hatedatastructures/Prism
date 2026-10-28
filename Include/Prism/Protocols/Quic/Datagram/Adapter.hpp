/**
 * @file Adapter.hpp
 * @brief QUIC 数据报提供者与 Prism 传输适配器
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
#include <stdexcept>
#include <system_error>

#include <Prism/Protocols/Common/IoBridge.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <utility>

namespace Prism::Quic
{

    namespace Net = boost::asio;

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
        [[nodiscard]] virtual auto Executor() const -> Net::any_io_executor = 0;

        /**
         * @brief 接收一个数据报
         * @param Buffer 接收缓冲区
         * @param ErrorCode 错误码输出
         * @return 实际接收字节数；数据报超过缓冲区时由实现定义截断策略
         */
        [[nodiscard]] virtual auto Receive(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> = 0;

        /**
         * @brief 发送一个数据报
         * @param Buffer 待发送数据报
         * @param ErrorCode 错误码输出
         * @return 实际发送字节数；返回值小于 Buffer.size() 时视为短写
         */
        [[nodiscard]] virtual auto Send(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> = 0;

        /**
         * @brief 关闭数据报提供者
         */
        virtual auto Close() -> void = 0;

        /**
         * @brief 取消挂起的数据报操作
         */
        virtual auto Cancel() -> void = 0;

        /**
         * @brief 查询提供者是否已关闭
         */
        [[nodiscard]] virtual auto IsClosed() const noexcept -> bool = 0;
    };

    /// 数据报提供者共享指针
    using SharedDatagramProvider = std::shared_ptr<DatagramProvider>;

    /**
     * @class DatagramAdapter
     * @brief 将数据报提供者适配为 Prism Transmission
     * @details 对外暴露 Udp 传输类型。读取直接委托提供者；写入若提供者
     *          返回短写，则返回已发送字节数并设置 IoError，阻止协议层
     *          把单个数据报剩余部分误发成第二个数据报。
     */
    class DatagramAdapter final : public Prism::Transmission
    {
        [[nodiscard]] static auto RequireProviderExecutor(const SharedDatagramProvider &Provider)
            -> Net::any_io_executor;

    public:
        /**
         * @brief 构造适配器
         * @param Provider 数据报提供者（所有权移交）
         */
        explicit DatagramAdapter(SharedDatagramProvider Provider)
            : Prism::Transmission(RequireProviderExecutor(Provider)),
              Provider_(std::move(Provider))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            if (Provider_)
            {
                return Provider_->Executor();
            }
            return Prism::Transmission::Executor();
        }

        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }

        /**
         * @brief 部分读取（委托提供者）；结果与借用沿正式前门交付一次。
         */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Protocols::StartPartialRead(
                Prism::Protocols::PartialReadInput<DatagramAdapter>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /**
         * @brief 部分写入（委托提供者）。
         */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Protocols::StartPartialWrite(
                Prism::Protocols::PartialWriteInput<DatagramAdapter>{Owner(), Buffer, Executor()},
                std::move(Handler));
        }

        /**
         * @brief 数据报载体没有独立写方向 END_STREAM；半关闭按已交付返回。
         * @note 调用者不得据此断言对端已收到半关闭；反向读取保持可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }

        /**
         * @brief 关闭数据报载体
         * @return 命令交付成功；实际退出由 Activity()->Drain() 另行等待。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (Provider_)
            {
                Provider_->Close();
            }
            return {};
        }

        /**
         * @brief 取消挂起的数据报操作；不宣称已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (Provider_)
            {
                Provider_->Cancel();
            }
            return {};
        }

        /** @brief 数据面部分读取实现，由正式前门复用。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>;

        /** @brief 数据面部分写入实现，由正式前门复用；数据报必须整包交付。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>;

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Provider_ && !Provider_->IsClosed();
        }

        [[nodiscard]] auto Provider() const noexcept -> SharedDatagramProvider
        {
            return Provider_;
        }

    private:
        /** @brief 完成交付前的 owner 借用；存活由本次传输预约与调用者共同保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<DatagramAdapter>
        {
            return std::static_pointer_cast<DatagramAdapter>(Transmission::shared_from_this());
        }

        SharedDatagramProvider Provider_;
    };

    /// 数据报适配器共享指针
    using SharedDatagramAdapter = std::shared_ptr<DatagramAdapter>;

} // namespace Prism::Quic
