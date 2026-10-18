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
#include <Prism/Protocols/Xhttp/Detail/Common.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamWriteQueue.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
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

        explicit XhttpTransport(Options Value)
            : Transmission(Value.Executor),
              Ex_(std::move(Value.Executor)),
              Writer_(std::make_shared<Detail::StreamWriteQueue>(
                  Ex_, std::move(Value.Write), std::move(Value.Finish))),
              CloseOwner_(std::move(Value.CloseOwner)),
              Notify_(Ex_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto CloseFailure() const noexcept -> Prism::Fault::Failure
        {
            return CloseFailure_;
        }

        /** @brief 保留第一个完整 typed close failure，不替换其 Native category/value。 */
        auto RecordCloseFailure(const Prism::Fault::Failure Failure) noexcept -> void
        {
            if (CloseFailure_.Succeeded() && Failure.Failed()) CloseFailure_ = Failure;
        }

        /** @brief 读取一部分已解出的流数据；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler));
        }

        /** @brief 写入一部分流数据；保留写队列、绑定前缓冲与失败语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭：刷新 END_STREAM 后保留读方向。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Initiate<ShutdownWork>(ShutdownInput{Owner()}, std::move(Handler));
        }

        /** @brief 本地封止并交付关闭；底层 carrier 由持有最终关闭权的 owner 执行。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return CloseLocal();
        }

        /** @brief 可重复取消：与本地封止同一路径，不宣称底层已经关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return OnClose();
        }

        /** @brief 半关闭请求方向，发送 END_STREAM 后继续保留读方向。 */
        [[nodiscard]] auto Finish() -> Net::awaitable<WriteResult>
        {
            return Writer_->Finish();
        }

        /** @brief 等待 Stream-one frame writer 与其 completion 退栈。 */
        [[nodiscard]] auto DrainWriter()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            return Writer_->Drain();
        }

        /** @brief 读取 Stream-one writer 的物理退休事实。 */
        [[nodiscard]] auto WriterIsRetired() const noexcept -> bool
        {
            return Writer_->IsRetired();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return nullptr;
        }

        /** @brief 投递收到的 DATA 载荷；队列满时关闭传输。 */
        void Push(std::span<const std::byte> Data)
        {
            if (Closed_ || TerminalError_ || Data.empty())
            {
                return;
            }
            std::vector<std::byte> Copy(Data.begin(), Data.end());
            if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
            {
                (void)Diagnose::Error("XhttpReceiveChannelFull Action=CloseStream");
                Close();
            }
        }

        /** @brief 记录对端 END_STREAM。 */
        void NotifyEof()
        {
            if (!Closed_ && !TerminalError_ && !Eof_ && !EofPending_)
            {
                if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
                {
                    EofPending_ = true;
                }
            }
        }

        /** @brief 将 H2 RST/协议错误传给挂起读，区别于正常 END_STREAM。 */
        void NotifyError(std::error_code ErrorCode)
        {
            if (TerminalError_)
            {
                return;
            }
            TerminalError_ = ErrorCode;
            if (!TerminalError_)
                TerminalError_ = std::make_error_code(std::errc::protocol_error);
            (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
        }

        /** @brief 绑定 h2 流并刷新匹配前的写缓冲。 */
        void BindStream(std::int32_t StreamId)
        {
            if (Closed_ || TerminalError_ || StreamId_ >= 0)
            {
                return;
            }
            StreamId_ = StreamId;
            const auto Weak = std::weak_ptr<XhttpTransport>(Owner());
            Writer_->BindStream(StreamId, [Weak](Prism::Fault::Failure Failure)
            {
                if (const auto State = Weak.lock())
                {
                    State->NotifyError(Prism::Fault::ToNative(Failure));
                    (void)State->CloseLocal();
                }
            });
        }

        /// 当前匹配流 ID（-1 = 未匹配）。
        std::int32_t StreamId_{-1};

    private:
        /** @brief 完成交付前的真实 owner 借用；存活由本次传输预约保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<XhttpTransport>
        {
            return std::static_pointer_cast<XhttpTransport>(Transmission::shared_from_this());
        }

        /** @brief 本地封止：置位 Closed、取消通知并唤醒全部挂起写请求。 */
        auto CloseLocal() -> ControlResult
        {
            if (Closed_)
            {
                if (CloseFailure_.Failed())
                {
                    return std::unexpected(CloseFailure_);
                }
                return {};
            }
            Closed_ = true;
            Notify_.cancel();
            Writer_->Close();
            const auto Failure = NotifyOwnerClose();
            if (Failure.Failed())
            {
                return std::unexpected(Failure);
            }
            return {};
        }

        /** @brief 原协程体：读取通知块，保留终止错误、EOF 与短读语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            while (RxOffset_ >= RxCurrent_.size())
            {
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                    co_return 0;
                }
                if (Closed_)
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    ErrorCode = make_error_code(Error::UnexpectedEof);
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                boost::system::error_code ChEc;
                auto Block = co_await Notify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ChEc));
                if (ChEc)
                {
                    if (TerminalError_)
                    {
                        ErrorCode = TerminalError_;
                        co_return 0;
                    }
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                RxCurrent_ = std::move(Block);
                RxOffset_ = 0;
            }
            const auto N = std::min(Buffer.size(), RxCurrent_.size() - RxOffset_);
            std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, N);
            RxOffset_ += N;
            ErrorCode.clear();
            co_return N;
        }

        /** @brief 原协程体：经写队列提交数据，保留绑定前缓冲与失败语义。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>
        {
            if (Buffer.empty())
            {
                Failure = {};
                co_return 0;
            }
            if (Closed_ || TerminalError_)
            {
                Failure = Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected));
                co_return 0;
            }
            const auto Written = co_await Writer_->Write(Buffer);
            if (!Written)
            {
                Failure = Written.error();
                co_return 0;
            }
            Failure = {};
            co_return *Written;
        }

        /** @brief 原半关闭路径：刷新 END_STREAM；不具备半关闭条件时交付确定失败。 */
        [[nodiscard]] auto ShutdownPartial() -> Net::awaitable<Prism::Fault::Failure>
        {
            if (Closed_ || StreamId_ < 0)
            {
                co_return Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected));
            }
            const auto Result = co_await Finish();
            if (!Result) co_return Result.error();
            co_return Prism::Fault::Failure{};
        }

        struct ReadInput final { std::shared_ptr<XhttpTransport> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<XhttpTransport> Owner; std::span<const std::byte> Buffer; };
        struct ShutdownInput final { std::shared_ptr<XhttpTransport> Owner; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
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
                Prism::Transport::Detail::ConfigureIo(Operation);
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
                Prism::Transport::Detail::ConfigureIo(Operation);
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
        std::error_code TerminalError_;
        Prism::Fault::Failure CloseFailure_;

        auto NotifyOwnerClose() noexcept -> Prism::Fault::Failure
        {
            if (!CloseOwner_)
            {
                return {};
            }
            auto Callback = std::move(CloseOwner_);
            try
            {
                const auto Failure = Callback();
                RecordCloseFailure(Failure);
                if (Failure.Failed()) NotifyError(Prism::Fault::ToNative(Failure));
                return Failure;
            }
            catch (...)
            {
                const auto Typed = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                RecordCloseFailure(Typed);
                NotifyError(Prism::Fault::ToNative(Typed));
                return Typed;
            }
        }
    };

} // namespace Prism::Xhttp::Detail
