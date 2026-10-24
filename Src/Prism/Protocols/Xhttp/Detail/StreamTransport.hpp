/**
 * @file StreamTransport.hpp
 * @brief XHTTP Stream-one 双向传输 owner。
 * @details 读方向消费 h2 DATA 队列，写方向提交 h2 DATA 帧；在 POST
 *          请求匹配前保留写入缓冲。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Protocols/Xhttp/Detail/CarrierSessionSupport.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamWriteQueue.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{

    /**
     * @class XhttpTransport
     * @brief XHTTP Stream-one 的 Transmission 装饰器
     * @details StreamId_ 绑定前，写入按调用顺序缓冲；绑定后由单一写协程
     *          串行提交。Close/Cancel 取消读等待并失败所有未完成写入。
     * @note 除 Executor() 外的状态变更和关闭操作必须在 Executor() 上调用；
     *       CloseOwner 也只在该 executor 上通知拥有者。
     */
    class XhttpTransport final : public Transmission
    {
    public:
        using WriteResult = std::expected<void, Prism::Fault::Failure>;
        using WriteCb = std::function<Net::awaitable<WriteResult>(
            std::int32_t StreamId, std::span<const std::byte>)>;
        using FinishCb = std::function<Net::awaitable<WriteResult>(std::int32_t StreamId)>;
        using CloseCb = std::function<Prism::Fault::Failure()>;
        struct Options final
        {
            Net::any_io_executor Executor;
            WriteCb Write;
            FinishCb Finish;
            CloseCb CloseOwner;
        };

        explicit XhttpTransport(Options Value);

        [[nodiscard]] auto Executor() const -> ExecutorType override;

        [[nodiscard]] auto CloseFailure() const noexcept -> Prism::Fault::Failure;

        /** @brief 保留第一个完整 typed close failure，不替换其 Native category/value。 */
        auto RecordCloseFailure(const Prism::Fault::Failure Failure) noexcept -> void;

        /** @brief 读取一部分已解出的流数据；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 写入一部分流数据；保留写队列、绑定前缓冲与失败语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 真实写半关闭：刷新 END_STREAM 后保留读方向。 */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /** @brief 本地封止并交付关闭；底层 carrier 由持有最终关闭权的 owner 执行。 */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /** @brief 可重复取消：与本地封止同一路径，不宣称底层已经关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        /** @brief 半关闭请求方向，发送 END_STREAM 后继续保留读方向。 */
        [[nodiscard]] auto Finish() -> Net::awaitable<WriteResult>;

        /** @brief 等待 Stream-one frame writer 与其 completion 退栈。 */
        [[nodiscard]] auto DrainWriter()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 读取 Stream-one writer 的物理退休事实。 */
        [[nodiscard]] auto WriterIsRetired() const noexcept -> bool;

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override;

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override;

        /** @brief 投递收到的 DATA 载荷；队列满时关闭传输。 */
        void Push(std::span<const std::byte> Data);

        /** @brief 记录对端 END_STREAM。 */
        void NotifyEof();

        /** @brief 将 H2 RST/协议错误传给挂起读，区别于正常 END_STREAM。 */
        void NotifyError(std::error_code ErrorCode);

        /** @brief 下一次 wire 写失败时先排空本次 EOF 前已接受的 DATA。 */
        void PreserveAcceptedDataForOutputFailure();

        /** @brief 以原 typed cause 处理串行 wire writer 的失败。 */
        void NotifyOutputFailure(Prism::Fault::Failure Failure);

        /** @brief 先锁存 wire 写失败，再交由实际 owner 关闭资源。 */
        template <typename CloseOwner>
        void HandleOutputFailure(
            Prism::Fault::Failure Failure,
            CloseOwner &&CloseOwnerFunction)
        {
            NotifyOutputFailure(Failure);
            CloseOwnerFunction();
        }

        /** @brief 锁存底层读终态；接收队列耗尽前继续交付已有 DATA。 */
        void NotifyReadTerminal(Prism::Fault::Failure Failure);

        [[nodiscard]] auto DrainTerminalPending() const noexcept -> bool;

        /** @brief 绑定 h2 流并刷新匹配前的写缓冲。 */
        void BindStream(std::int32_t StreamId);

        /// 当前匹配流 ID（-1 = 未匹配）。
        std::int32_t StreamId_{-1};

    private:
        /** @brief 完成交付前的真实 owner 借用；存活由本次传输预约保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<XhttpTransport>;

        /** @brief 本地封止：置位 Closed、取消通知并唤醒全部挂起写请求。 */
        auto CloseLocal() -> ControlResult;

        /**
         * @brief 读取通知块，保留终止错误、EOF 与短读语义。
         * @details H2 reset 与背压终止立即优先；底层读终态只在 RxCurrent_ 和已接收队列排空后交付。
         */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>;

        /** @brief 原协程体：经写队列提交数据，保留绑定前缓冲与失败语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>;

        /** @brief 原半关闭路径：刷新 END_STREAM；不具备半关闭条件时交付确定失败。 */
        [[nodiscard]] auto ShutdownPartial() -> Net::awaitable<Prism::Fault::Failure>;

        struct ReadInput final { std::shared_ptr<XhttpTransport> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<XhttpTransport> Owner; std::span<const std::byte> Buffer; };
        struct ShutdownInput final { std::shared_ptr<XhttpTransport> Owner; };
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
        struct ShutdownWork final
        {
            template<class State>
            auto operator()(State Operation, ShutdownInput Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                const auto Failure = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->ShutdownPartial(),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{0, Failure}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        using ChannelType =
            Net::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::byte>)>;

        Net::any_io_executor Ex_;
        std::shared_ptr<Detail::StreamWriteQueue> Writer_;
        CloseCb CloseOwner_;
        ChannelType Notify_;
        std::vector<std::byte> RxCurrent_;
        std::size_t RxOffset_{0};
        bool Closed_{false};
        bool Eof_{false};
        bool EofPending_{false};
        bool DrainTerminal_{false};
        bool PreserveAcceptedDataForOutputFailure_{false};
        std::error_code TerminalError_;
        Prism::Fault::Failure CloseFailure_;

        auto NotifyOwnerClose() noexcept -> Prism::Fault::Failure;
    };

} // namespace Prism::Xhttp::Detail
