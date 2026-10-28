/**
 * @file Transport.hpp
 * @brief XHTTP Stream-up/Packet-up 的逻辑双向传输
 * @details 读侧消费下行 GET 的 DATA，写侧提交上行 POST；Packet-up
 *          的每次写入由 owner 创建新的上行流。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    /**
     * @class SplitTransport
     * @brief XHTTP Split 模式的逻辑双向传输
     * @details Close/Cancel 负责本地队列和读等待，CloseFn 由会话 owner
     *          负责关闭 Wire 与加密连接。
     */
    class SplitTransport final : public Transmission
    {
    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using WriteCb = std::function<Net::awaitable<WriteResult>(std::span<const std::byte>)>;
        using CloseCb = std::function<Prism::Fault::Failure()>;

        SplitTransport(
            Net::any_io_executor Executor,
            WriteCb WriteFunction,
            CloseCb CloseFunction);

        [[nodiscard]] auto Executor() const -> ExecutorType override;

        [[nodiscard]] auto CloseFailure() const noexcept -> Prism::Fault::Failure;

        /** @brief 读取一部分已解出的载荷；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 写入一部分载荷；保留写队列与终止错误语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /**
         * @brief split 模式 wire 不携带独立写方向 END_STREAM，半关闭按已交付返回。
         * @note 调用者不得据此断言对端已收到半关闭；反向读取保持可用。
         */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /** @brief 本地封止并交付关闭；底层 carrier 由持有最终关闭权的 owner 执行。 */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /** @brief 可重复取消：与本地封止同一路径，不宣称底层已经关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        void Push(std::span<const std::byte> Data);

        void NotifyEof();

        /** @brief 记录首个 H2/transport terminal error；错误优先于 EOF 并唤醒读写等待。 */
        void NotifyError(std::error_code ErrorCode);

        /** @brief 锁存底层读终态；接收队列耗尽前继续交付已有 DATA。 */
        void NotifyReadTerminal(Prism::Fault::Failure Failure);

        [[nodiscard]] auto DrainTerminalPending() const noexcept -> bool;

    private:
        /** @brief 完成交付前的真实 owner 借用；存活由本次传输预约保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<SplitTransport>;

        /** @brief 本地封止：置位 Closed、取消通知并唤醒全部挂起写请求。 */
        auto CloseLocal() -> ControlResult;

        /** @brief 读取通知块；H2 错误立即终止，底层读终态在已接收 DATA 后交付。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>;

        /** @brief 原协程体：经写队列提交载荷，保留终止错误与失败语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>;

        struct ReadInput final { std::shared_ptr<SplitTransport> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<SplitTransport> Owner; std::span<const std::byte> Buffer; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->ReadPartial(Input.Buffer, Error),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                Prism::Fault::Failure Failure;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer, Failure),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Failure}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        using CompletionChannel = Net::experimental::channel<
            void(boost::system::error_code, std::size_t, Prism::Fault::Failure)>;

        struct WriteRequest final
        {
            WriteRequest(Net::any_io_executor Executor, std::span<const std::byte> Bytes);

            std::vector<std::byte> Data;
            std::shared_ptr<CompletionChannel> Done;
        };

        void StartWriter();

        void FailQueued(Prism::Fault::Failure Failure);

        auto NotifyClose() -> Prism::Fault::Failure;

        auto WriteLoop() -> Net::awaitable<void>;

        auto CompleteWriteLoop(std::exception_ptr Exception) noexcept -> void;

        using ChannelType =
            Net::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::byte>)>;

        Net::any_io_executor Ex_;
        WriteCb WriteFn_;
        CloseCb CloseFn_;
        ChannelType Notify_;
        std::vector<std::byte> RxCurrent_;
        std::size_t RxOffset_{0};
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        std::shared_ptr<WriteRequest> ActiveWriteRequest_;
        bool Closed_{false};
        bool CloseNotified_{false};
        Prism::Fault::Failure CloseFailure_;
        bool Eof_{false};
        bool EofPending_{false};
        bool DrainTerminal_{false};
        std::error_code TerminalError_{};
    };

} // namespace Prism::Xhttp::Detail
