/**
 * @file Http2Transport.hpp
 * @brief TrustTunnel HTTP/2 CONNECT 流的 Transmission owner。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Trusttunnel::Detail
{

    namespace Net = boost::asio;

    /**
     * @brief 将 HTTP/2 DATA 映射为 Prism::Transmission 的双向流 owner。
     * @details 负责入站 DATA 的有界排队、出站 partial write 的串行化、
     *          END_STREAM、EOF、Cancel 和最终 Close；HTTP/2 frame 编码由调用方完成。
     */
    class Http2Transport final : public Prism::Transmission
    {
    public:
        using WriteCb = std::function<Net::awaitable<std::expected<void, Prism::Fault::Failure>>(
            std::int32_t, std::span<const std::byte>)>;
        using FinishCb = std::function<Net::awaitable<std::expected<void, Prism::Fault::Failure>>(
            std::int32_t)>;
        using CloseCb = std::function<std::expected<void, Prism::Fault::Failure>()>;

        struct Options final
        {
            Net::any_io_executor Executor;
            WriteCb Write;
            FinishCb Finish;
            CloseCb Close;
        };

        explicit Http2Transport(Options Value)
            : Prism::Transmission(Value.Executor),
              Executor_(std::move(Value.Executor)), WriteFunction_(std::move(Value.Write)),
              FinishFunction_(std::move(Value.Finish)), CloseFunction_(std::move(Value.Close)),
              Notify_(Executor_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
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

        /**
         * @brief 只关闭 HTTP/2 CONNECT 的写方向并刷新 END_STREAM。
         * @details 不关闭底层 TLS read；carrier owner 仍可继续消费对端数据。
         *          Finish 失败时转入本地封止，避免写队列和 END_STREAM 请求悬挂。
         */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Initiate<ShutdownWork>(ShutdownInput{Owner()}, std::move(Handler));
        }

        /**
         * @brief 本地封止并交付关闭
         * @return 命令接管成功；底层 carrier 由持有者按其 owner 关闭。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (Closed_)
            {
                if (CloseFailure_.Failed())
                {
                    return std::unexpected(CloseFailure_);
                }
                return {};
            }
            CloseLocal();
            if (CloseFunction_)
            {
                const auto Closed = CloseFunction_();
                if (!Closed) CloseFailure_ = Closed.error();
            }
            if (CloseFailure_.Failed())
            {
                return std::unexpected(CloseFailure_);
            }
            return {};
        }

        /**
         * @brief 可重复取消：与本地封止同一路径，不宣称底层已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return OnClose();
        }

        [[nodiscard]] auto Finish() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (Closed_ || Finished_ || StreamId_ < 0 || !FinishFunction_)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }
            Finished_ = true;
            auto Request = std::make_shared<WriteRequest>(WriteRequestOptions{
                Executor_, StreamId_, std::span<const std::byte>{}, true});
            WriteQueue_.push_back(Request);
            StartWriter();
            boost::system::error_code WaitError;
            auto Receive = Request->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            auto Result = co_await std::move(Receive);
            if (WaitError)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(WaitError)));
            }
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return nullptr;
        }

        void Push(std::span<const std::byte> Data)
        {
            if (Closed_ || Data.empty())
            {
                return;
            }
            std::vector<std::byte> Copy(Data.begin(), Data.end());
            if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
            {
                CloseLocal();
            }
        }

        void NotifyEof()
        {
            if (!Closed_ && !Eof_)
            {
                if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
                {
                    EofPending_ = true;
                }
            }
        }

        /** @brief 记录 stream RESET/协议失败并唤醒挂起读取，不伪装为 END_STREAM。 */
        auto NotifyError(Prism::Fault::Failure Failure) -> void
        {
            if (TerminalError_ || Closed_)
            {
                return;
            }
            TerminalError_ = Prism::Fault::ToNative(Failure);
            (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
        }

        void BindStream(std::int32_t StreamId)
        {
            if (Closed_ || StreamId_ >= 0)
            {
                return;
            }
            StreamId_ = StreamId;
            if (!PendingWrite_.empty())
            {
                QueuePendingWrite(std::move(PendingWrite_));
            }
        }

        auto SetAuthority(std::string Authority) -> void
        {
            Authority_ = std::move(Authority);
        }

        [[nodiscard]] auto Authority() const -> std::string_view
        {
            return Authority_;
        }

        std::int32_t StreamId_{-1};
        std::string Authority_;

    private:
        struct WriteResult final
        {
            std::size_t Bytes{0};
            Prism::Fault::Failure Failure;
        };

        /** @brief 完成交付前的真实 owner 借用；存活由本次传输预约保证。 */
        [[nodiscard]] auto Owner() -> std::shared_ptr<Http2Transport>
        {
            return std::static_pointer_cast<Http2Transport>(Transmission::shared_from_this());
        }

        /** @brief 本地封止：置位 Closed、取消通知并唤醒全部挂起写请求。 */
        auto CloseLocal() -> void
        {
            Closed_ = true;
            Notify_.cancel();
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                if (Request->Done)
                {
                    (void)Request->Done->try_send(
                        boost::system::error_code{},
                        WriteResult{0, Prism::Fault::FromNative(
                                          std::make_error_code(std::errc::not_connected))});
                }
            }
        }

        /** @brief 原协程体：读取通知块，保留 EOF、取消与短读语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t>
        {
            Error.clear();
            while (ReadOffset_ >= ReadCurrent_.size())
            {
                if (TerminalError_)
                {
                    Error = TerminalError_;
                    co_return 0;
                }
                if (Closed_)
                {
                    Error = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    co_return 0;
                }
                boost::system::error_code ChannelError;
                auto Receive = Notify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ChannelError));
                auto Block = co_await std::move(Receive);
                if (ChannelError)
                {
                    Error = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    co_return 0;
                }
                ReadCurrent_ = std::move(Block);
                ReadOffset_ = 0;
            }
            const auto Count = (std::min)(Buffer.size(), ReadCurrent_.size() - ReadOffset_);
            std::memcpy(Buffer.data(), ReadCurrent_.data() + ReadOffset_, Count);
            ReadOffset_ += Count;
            Error.clear();
            co_return Count;
        }

        /** @brief 原协程体：经写队列提交数据，保留绑定前缓冲与失败语义。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<WriteResult>
        {
            if (Buffer.empty())
            {
                co_return WriteResult{};
            }
            if (Closed_ || Finished_ || !WriteFunction_)
            {
                co_return WriteResult{0, Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected))};
            }
            if (StreamId_ < 0)
            {
                PendingWrite_.insert(PendingWrite_.end(), Buffer.begin(), Buffer.end());
                co_return WriteResult{Buffer.size(), {}};
            }
            auto Request = std::make_shared<WriteRequest>(WriteRequestOptions{
                Executor_, StreamId_, Buffer});
            WriteQueue_.push_back(Request);
            StartWriter();
            boost::system::error_code WaitError;
            auto Receive = Request->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            auto Result = co_await std::move(Receive);
            if (WaitError)
            {
                co_return WriteResult{Result.Bytes,
                    Prism::Fault::FromNative(static_cast<std::error_code>(WaitError))};
            }
            co_return Result;
        }

        /** @brief 原半关闭路径：刷新 END_STREAM；失败时转入本地封止并交付失败。 */
        [[nodiscard]] auto ShutdownPartial()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (Closed_ || Finished_ || StreamId_ < 0 || !FinishFunction_)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            }
            auto Result = co_await Finish();
            if (!Result)
            {
                CloseLocal();
                co_return std::unexpected(Result.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        struct ReadInput final { std::shared_ptr<Http2Transport> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<Http2Transport> Owner; std::span<const std::byte> Buffer; };
        struct ShutdownInput final { std::shared_ptr<Http2Transport> Owner; };
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
                std::error_code Error;
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->WritePartial(Input.Buffer),
                    Net::deferred);
                co_return std::tuple{Prism::IoResult{Result.Bytes, Result.Failure}};
            }
        };
        struct ShutdownWork final
        {
            template<class State>
            auto operator()(State Operation, ShutdownInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(),
                    Input.Owner->ShutdownPartial(),
                    Net::deferred);
                Prism::Fault::Failure Failure;
                if (!Result)
                {
                    Failure = Result.error();
                }
                co_return std::tuple{Prism::IoResult{0, Failure}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        using WriteSignal = Net::experimental::channel<void(boost::system::error_code, WriteResult)>;

        struct WriteRequestOptions final
        {
            Net::any_io_executor Executor;
            std::int32_t StreamId;
            std::span<const std::byte> Bytes;
            bool EndStream{false};
        };

        struct WriteRequest
        {
            explicit WriteRequest(WriteRequestOptions Options)
                : StreamId(Options.StreamId), Data(Options.Bytes.begin(), Options.Bytes.end()),
                  EndStream(Options.EndStream),
                  Done(std::make_shared<WriteSignal>(std::move(Options.Executor), 1))
            {
            }

            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream{false};
            std::shared_ptr<WriteSignal> Done;
        };

        void QueuePendingWrite(std::vector<std::byte> Data)
        {
            if (Data.empty() || Closed_ || !WriteFunction_)
            {
                return;
            }
            auto Request = std::make_shared<WriteRequest>(WriteRequestOptions{
                Executor_, StreamId_, Data});
            Request->Done.reset();
            WriteQueue_.push_back(std::move(Request));
            StartWriter();
        }

        void StartWriter()
        {
            if (WriterRunning_ || Closed_ || WriteQueue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = std::static_pointer_cast<Http2Transport>(Transmission::shared_from_this());
            Net::co_spawn(
                Executor_,
                [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                Net::detached);
        }

        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                boost::system::error_code Error;
                WriteResult Result;
                bool MissingFunction = false;
                if (Request->EndStream)
                {
                    MissingFunction = !FinishFunction_;
                }
                else
                {
                    MissingFunction = !WriteFunction_;
                }
                if (Closed_ || MissingFunction)
                    Result.Failure = Prism::Fault::FromNative(
                        std::make_error_code(std::errc::not_connected));
                else if (Request->EndStream)
                {
                    const auto Finished = co_await FinishFunction_(Request->StreamId);
                    if (!Finished) Result.Failure = Finished.error();
                }
                else
                {
                    const auto Written = co_await WriteFunction_(Request->StreamId, Request->Data);
                    if (!Written) Result.Failure = Written.error();
                    else Result.Bytes = Request->Data.size();
                }
                const auto Failed = Result.Failure.Failed();
                if (Request->Done)
                {
                    (void)Request->Done->try_send(boost::system::error_code{}, Result);
                }
                if (Failed)
                {
                    Closed_ = true;
                    break;
                }
            }
            WriterRunning_ = false;
            co_return;
        }

        Net::any_io_executor Executor_;
        WriteCb WriteFunction_;
        FinishCb FinishFunction_;
        CloseCb CloseFunction_;
        using Channel = Net::experimental::concurrent_channel<void(boost::system::error_code,
                                                                    std::vector<std::byte>)>;
        Channel Notify_;
        std::vector<std::byte> ReadCurrent_;
        std::size_t ReadOffset_{0};
        std::vector<std::byte> PendingWrite_;
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        bool Closed_{false};
        bool Finished_{false};
        bool Eof_{false};
        bool EofPending_{false};
        std::error_code TerminalError_;
        Prism::Fault::Failure CloseFailure_;
    };

} // namespace Prism::Trusttunnel::Detail
