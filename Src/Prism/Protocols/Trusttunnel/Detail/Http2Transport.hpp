/**
 * @file Http2Transport.hpp
 * @brief TrustTunnel HTTP/2 CONNECT 流的 Transmission owner。
 */

#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
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
#include <optional>
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
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 写入一部分流数据；保留写队列、绑定前缓冲与失败语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /**
         * @brief 只关闭 HTTP/2 CONNECT 的写方向并刷新 END_STREAM。
         * @details 不关闭底层 TLS read；carrier owner 仍可继续消费对端数据。
         *          Finish 失败时转入本地封止，避免写队列和 END_STREAM 请求悬挂。
         */
        auto StartWriteShutdown(Completion Handler) -> void override;

        /**
         * @brief 本地封止并交付关闭
         * @return 命令接管成功；底层 carrier 由持有者按其 owner 关闭。
         */
        [[nodiscard]] auto OnClose() -> ControlResult override;

        /**
         * @brief 可重复取消：与本地封止同一路径，不宣称底层已经关闭。
         */
        [[nodiscard]] auto OnCancel() -> ControlResult override;

        [[nodiscard]] auto Finish() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return nullptr;
        }

        void Push(std::span<const std::byte> Data);

        void NotifyEof();

        /** @brief 记录 stream RESET/协议失败并唤醒挂起读取，不伪装为 END_STREAM。 */
        auto NotifyError(Prism::Fault::Failure Failure) -> void;

        /** @brief 锁存底层读取终态；既有 DATA 排空前保持读取入口可用。 */
        auto NotifyReadTerminal(Prism::Fault::Failure Failure) -> void;

        [[nodiscard]] auto DrainTerminalPending() const noexcept -> bool
        {
            return DrainTerminal_;
        }

        /** @brief 判断底层只关闭读方向时是否继续保留 carrier 写侧。 */
        [[nodiscard]] auto ReadHalfClosed() const noexcept -> bool
        {
            return DrainTerminal_ && ReadTerminalFailure_ &&
                ReadTerminalFailure_->Code == Prism::Fault::Code::Eof;
        }

        /** @brief 双向 END_STREAM 都已完成；此后对端 reset 只属于物理拆除。 */
        [[nodiscard]] auto ExchangeComplete() const noexcept -> bool
        {
            return RemoteEnded_ && Finished_;
        }

        /** @brief 非 EOF 读终态关闭 client Wire/TLS；EOF 保留写侧至最终 Close。 */
        auto CloseCarrierForReadTerminal() -> Prism::Fault::Failure;

        void BindStream(std::int32_t StreamId);

        auto SetAuthority(std::string Authority) -> void;

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

        /** @brief 本地封止并唤醒写请求；读终态排空期间保留接收通知。 */
        auto CloseLocal() -> void;

        auto CloseCarrier() -> void;

        /** @brief 原协程体：读取通知块，保留 EOF、取消与短读语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t>;

        /** @brief 原协程体：经写队列提交数据，保留绑定前缓冲与失败语义。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<WriteResult>;

        /** @brief 原半关闭路径：刷新 END_STREAM；失败时转入本地封止并交付失败。 */
        [[nodiscard]] auto ShutdownPartial()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        struct ReadInput final { std::shared_ptr<Http2Transport> Owner; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<Http2Transport> Owner; std::span<const std::byte> Buffer; };
        struct ShutdownInput final { std::shared_ptr<Http2Transport> Owner; };
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
                Prism::Transmission::ConfigureIo(Operation);
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

        void QueuePendingWrite(std::vector<std::byte> Data);

        void StartWriter();

        auto WriteLoop() -> Net::awaitable<void>;

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
        bool RemoteEnded_{false};
        bool Eof_{false};
        bool EofPending_{false};
        bool DrainTerminal_{false};
        bool CloseCarrierInvoked_{false};
        std::error_code TerminalError_;
        std::optional<Prism::Fault::Failure> ReadTerminalFailure_;
        Prism::Fault::Failure CloseFailure_;
    };

} // namespace Prism::Trusttunnel::Detail
