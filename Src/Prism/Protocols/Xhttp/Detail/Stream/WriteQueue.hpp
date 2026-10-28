/**
 * @file WriteQueue.hpp
 * @brief XHTTP Stream-one 写队列与 END_STREAM owner。
 * @details 未匹配前暂存 payload；绑定 stream 后按序写出。排队请求收到同一
 *          typed Failure，失败通知由逻辑传输接手并关闭本地写队列。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail::Detail
{
    /**
     * @class StreamWriteQueue
     * @brief XHTTP Stream-one 单 executor 写队列 owner。
     * @details 队列按构造 executor 串行提交 DATA 和 END_STREAM，复制借用 payload；
     *          Close 只结束队列，物理 carrier 仍由 XhttpTransport 的外层 owner 关闭。
     */
    class StreamWriteQueue final : public std::enable_shared_from_this<StreamWriteQueue>
    {
    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using WriteCallback = std::function<Net::awaitable<WriteResult>(
            std::int32_t, std::span<const std::byte>)>;
        using FinishCallback = std::function<Net::awaitable<WriteResult>(std::int32_t)>;
        using FailureCallback = std::function<void(Prism::Fault::Failure)>;

        StreamWriteQueue(
            Net::any_io_executor Executor,
            WriteCallback Write,
            FinishCallback Finish);

        /**
         * @brief 按序提交 DATA 并等待本次写完成。
         * @param Data 本次借用载荷；入队前复制，调用者可在 awaitable 完成后复用。
         * @return 写入字节数或保留原生 category/value 的 Failure。
         * @details 未绑定 stream 时复制并计入暂存；executor 固定为构造输入。
         */
        [[nodiscard]] auto Write(std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<std::size_t, Prism::Fault::Failure>>;

        /**
         * @brief 排入并等待 END_STREAM，结束本端写方向但保留读取方向。
         * @return 成功或传输/协议边界交付的原始 Failure。
         * @details 仅通过已绑定 stream 的 FinishCallback 提交，不关闭底层 carrier。
         */
        [[nodiscard]] auto Finish()
            -> Net::awaitable<WriteResult>;

        /** @brief 绑定唯一 h2 stream 并启动匹配前暂存；失败回调由逻辑传输接收。 */
        void BindStream(std::int32_t StreamId, FailureCallback Failure);

        /** @brief 停止接收新写入并完成排队请求；不拥有 socket 或最终 carrier close。 */
        void Close();

        /** @brief 等待 writer 与排队请求物理退栈，并返回写入首因。 */
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 只读 writer loop、active request 与队列全部退栈的事实。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        using CompletionChannel = Net::experimental::channel<
            void(boost::system::error_code, std::size_t, Prism::Fault::Failure)>;

        using IdleChannel = Net::experimental::channel<void(boost::system::error_code)>;

        struct WriteCommand final
        {
            std::int32_t StreamId;
            std::span<const std::byte> Data;
            bool EndStream;
            bool AwaitCompletion;
        };

        struct QueuedWrite final
        {
            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream;
            std::shared_ptr<CompletionChannel> Completion;
        };

        struct WriteRequest final
        {
            WriteRequest(
                Net::any_io_executor Executor,
                WriteCommand Command);

            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream{false};
            std::shared_ptr<CompletionChannel> Done;
        };

        [[nodiscard]] static auto NotConnected() noexcept -> Prism::Fault::Failure;

        [[nodiscard]] static auto ExceptionFailure() noexcept -> Prism::Fault::Failure;

        [[nodiscard]] auto Enqueue(
            WriteCommand Command)
            -> Net::awaitable<std::expected<std::size_t, Prism::Fault::Failure>>;

        void QueueWrite(QueuedWrite Value);

        void StartWriter();

        void FailQueued(Prism::Fault::Failure Failure);

        void NotifyFailure(Prism::Fault::Failure Failure) noexcept;

        auto WriteLoop() -> Net::awaitable<void>;

        auto CompleteWriteLoop(std::exception_ptr Exception) noexcept -> void;

        auto RefreshRetired() noexcept -> void;

        auto NotifyIdle() noexcept -> void;

        Net::any_io_executor Ex_;
        WriteCallback Write_;
        FinishCallback Finish_;
        FailureCallback Failure_;
        std::shared_ptr<IdleChannel> Idle_;
        std::vector<std::byte> Pending_;
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        std::shared_ptr<WriteRequest> ActiveRequest_;
        std::int32_t StreamId_{-1};
        bool WriterRunning_{false};
        bool Closed_{false};
        bool Finished_{false};
        std::atomic<bool> Retired_{false};
        Prism::Fault::FailureState FirstFailure_;
    };
} // namespace Prism::Xhttp::Detail::Detail
