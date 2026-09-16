/**
 * @file NativeServer.hpp
 * @brief HTTP/3 nghttp3 与异步 QUIC provider 的单执行器会话适配
 * @details 负责控制流/QPACK 流生命周期、incoming stream 事件串行化、
 *          nghttp3 输出短写确认以及认证后的裸双向流回调。
 *          所有 nghttp3 调用都在创建会话时提供的执行器上顺序执行。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <functional>
#include <memory>
#include <span>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Http3/Server.hpp>
#include <Preview/Protocols/Quic/StreamAdapter.hpp>

namespace Preview::Http3
{

    namespace Net = boost::asio;

    /**
     * @struct NativeServerRawData
     * @brief 认证后双向 QUIC 流的上层响应动作
     */
    struct NativeServerRawData
    {
        std::vector<std::byte> Data;
        bool Fin{false};
        bool Stop{false};
        std::chrono::milliseconds GracefulClose{0};
    };

    /**
     * @struct NativeServerSessionOptions
     * @brief HTTP/3 会话与异步 QUIC provider 工厂
     */
    struct NativeServerSessionOptions
    {
        Net::any_io_executor Executor{};
        ServerOptions Http{};
        std::function<Net::awaitable<Preview::Quic::SharedStreamProvider>()>
            OpenUnidirectional;
        std::function<Net::awaitable<Preview::Quic::SharedStreamProvider>()>
            AcceptUnidirectional;
        std::function<Net::awaitable<Preview::Quic::SharedStreamProvider>()>
            AcceptBidirectional;
        std::function<NativeServerRawData(std::int64_t, std::span<const std::byte>, bool)> OnRawData;
        std::function<void()> OnAuthenticated;
    };

    /**
     * @class NativeServerSession
     * @brief 将 Preview QUIC provider 接入 HTTP/3 服务端会话
     * @details
     * 1. 异步创建 HTTP/3 控制流和两个 QPACK 单向流；
     * 2. 将所有 incoming 流转为事件，在一个 executor 上调用 nghttp3；
     * 3. 每次 QUIC 短写后调用 AddWriteOffset，FIN 只在全部字节写完后提交；
     * 4. 认证完成后把新的双向流交给 OnRawData（Hysteria2 TCP 数据面）。
     */
    class NativeServerSession final : public std::enable_shared_from_this<NativeServerSession>
    {
    public:
        explicit NativeServerSession(NativeServerSessionOptions Options)
            : Options_(std::move(Options)),
              Server_(MakeServer(Options_.Http)),
              Events_(Options_.Executor, 256)
        {
        }

        NativeServerSession(const NativeServerSession &) = delete;
        auto operator=(const NativeServerSession &) -> NativeServerSession & = delete;

        /**
         * @brief 启动会话并运行到连接关闭或上层请求停止
         * @return 会话最终错误语义
         */
        [[nodiscard]] auto Run() -> Net::awaitable<Fault::Code>
        {
            co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
            if (!Server_ || !Options_.OpenUnidirectional || !Options_.AcceptUnidirectional ||
                !Options_.AcceptBidirectional)
            {
                co_return Fault::Code::NotSupported;
            }
            if (!co_await OpenHttp3Streams() || !InitializeHttp3())
            {
                Close();
                co_return Fault::Code::ProtocolError;
            }

            auto Self = shared_from_this();
            Net::co_spawn(Options_.Executor,
                          [Self]() -> Net::awaitable<void> { co_await Self->AcceptLoop(true); },
                          Net::detached);
            Net::co_spawn(Options_.Executor,
                          [Self]() -> Net::awaitable<void> { co_await Self->AcceptLoop(false); },
                          Net::detached);
            auto InitCode = co_await DrainOutput();
            if (InitCode != Fault::Code::Success)
            {
                Close();
                co_return InitCode;
            }

            while (!Closed_)
            {
                boost::system::error_code ReceiveError;
                const auto EventValue =
                    co_await Events_.async_receive(Net::redirect_error(Net::use_awaitable, ReceiveError));
                if (ReceiveError || !EventValue)
                {
                    break;
                }
                const auto Code = co_await HandleEvent(*EventValue);
                if (Code != Fault::Code::Success)
                {
                    TerminalCode_ = Code;
                    Close();
                    break;
                }
            }
            const auto Result = TerminalCode_;
            Close();
            co_return Result;
        }

        /**
         * @brief 关闭会话及所有 provider
         */
        auto Close() -> void
        {
            auto Self = shared_from_this();
            Net::dispatch(Options_.Executor, [Self = std::move(Self)]() mutable
                          { Self->CloseOnExecutor(); });
        }

        /**
         * @brief 查询认证是否已完成
         */
        [[nodiscard]] auto Authenticated() const noexcept -> bool
        {
            return Authenticated_;
        }

        /** @brief HTTP/3 认证协议是否已完成 */
        [[nodiscard]] auto ProtocolReady() const noexcept -> bool
        {
            return Authenticated_;
        }

        /**
         * @brief 获取 HTTP/3 服务端门面
         */
        [[nodiscard]] auto Http() const noexcept -> const Server &
        {
            return *Server_;
        }

    private:
        auto CloseOnExecutor() -> void
        {
            if (Closed_)
            {
                return;
            }
            Closed_ = true;
            Events_.close();
            for (auto &[StreamId, Provider] : Streams_)
            {
                (void)StreamId;
                if (Provider)
                {
                    Provider->Close();
                }
            }
            Streams_.clear();
            if (Server_)
            {
                Server_->Close();
            }
            if (TerminalCode_ == Fault::Code::Success && Authenticated_)
            {
                return;
            }
            if (TerminalCode_ == Fault::Code::Canceled)
            {
                TerminalCode_ = Fault::Code::Canceled;
            }
        }

        enum class EventType : std::uint8_t
        {
            NewStream,
            Data,
            Error,
        };

        struct Event
        {
            EventType Type{EventType::Error};
            bool Unidirectional{false};
            bool Fin{false};
            std::error_code Error{};
            Preview::Quic::SharedStreamProvider Provider{};
            std::vector<std::byte> Data;
        };

        using EventChannel =
            Net::experimental::channel<void(boost::system::error_code, std::shared_ptr<Event>)>;

        [[nodiscard]] auto OpenHttp3Streams() -> Net::awaitable<bool>
        {
            for (auto &Provider : Http3Streams_)
            {
                Provider = co_await Options_.OpenUnidirectional();
                if (!Provider || Provider->StreamId() < 0)
                {
                    co_return false;
                }
                Streams_[Provider->StreamId()] = Provider;
            }
            co_return true;
        }

        [[nodiscard]] auto InitializeHttp3() -> bool
        {
            std::size_t Index = 0;
            return Server_->Init([this, Index]() mutable -> std::int64_t
                                 {
                                     if (Index >= Http3Streams_.size() || !Http3Streams_[Index])
                                     {
                                         return -1;
                                     }
                                     return Http3Streams_[Index++]->StreamId();
                                 });
        }

        [[nodiscard]] auto AcceptLoop(const bool Unidirectional) -> Net::awaitable<void>
        {
            const auto *Accept = &Options_.AcceptBidirectional;
            if (Unidirectional)
            {
                Accept = &Options_.AcceptUnidirectional;
            }
            while (!Closed_)
            {
                auto Provider = co_await (*Accept)();
                if (!Provider || Closed_)
                {
                    co_return;
                }
                auto EventValue = std::make_shared<Event>();
                EventValue->Type = EventType::NewStream;
                EventValue->Unidirectional = Unidirectional;
                EventValue->Provider = std::move(Provider);
                if (!Publish(std::move(EventValue)))
                {
                    co_return;
                }
            }
        }

        [[nodiscard]] auto ReadLoop(const Preview::Quic::SharedStreamProvider &Provider,
                                    const bool Unidirectional) -> Net::awaitable<void>
        {
            std::array<std::byte, 16384> Buffer{};
            while (!Closed_ && Provider)
            {
                std::error_code Error;
                const auto Count = co_await Provider->Read(Buffer, Error);
                if (Error)
                {
                    auto EventValue = std::make_shared<Event>();
                    EventValue->Type = EventType::Error;
                    EventValue->Error = Error;
                    EventValue->Provider = Provider;
                    (void)Publish(std::move(EventValue));
                    co_return;
                }
                auto EventValue = std::make_shared<Event>();
                EventValue->Type = EventType::Data;
                EventValue->Unidirectional = Unidirectional;
                EventValue->Provider = Provider;
                EventValue->Fin = Count == 0;
                EventValue->Data.assign(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
                if (!Publish(std::move(EventValue)) || Count == 0)
                {
                    co_return;
                }
            }
        }

        [[nodiscard]] auto Publish(std::shared_ptr<Event> EventValue) -> bool
        {
            if (Closed_ || !EventValue)
            {
                return false;
            }
            return Events_.try_send(boost::system::error_code{}, std::move(EventValue));
        }

        [[nodiscard]] auto HandleEvent(const Event &EventValue) -> Net::awaitable<Fault::Code>
        {
            if (EventValue.Type == EventType::NewStream)
            {
                co_return co_await HandleNewStream(EventValue);
            }
            if (EventValue.Type == EventType::Error)
            {
                co_return Fault::Code::IoError;
            }
            co_return co_await HandleData(EventValue);
        }

        [[nodiscard]] auto HandleNewStream(const Event &EventValue) -> Net::awaitable<Fault::Code>
        {
            if (!EventValue.Provider ||
                Streams_.contains(EventValue.Provider->StreamId()))
            {
                co_return Fault::Code::ProtocolError;
            }
            const auto StreamId = EventValue.Provider->StreamId();
            Streams_[StreamId] = EventValue.Provider;
            auto Self = shared_from_this();
            const auto Provider = EventValue.Provider;
            const auto Unidirectional = EventValue.Unidirectional;
            Net::co_spawn(
                Options_.Executor,
                [Self, Provider, Unidirectional]() -> Net::awaitable<void>
                {
                    co_await Self->ReadLoop(Provider, Unidirectional);
                },
                Net::detached);
            co_return Fault::Code::Success;
        }

        [[nodiscard]] auto HandleData(const Event &EventValue) -> Net::awaitable<Fault::Code>
        {
            if (!EventValue.Provider)
            {
                co_return Fault::Code::ProtocolError;
            }
            if (Authenticated_ && EventValue.Provider->StreamId() == AuthStream_)
            {
                co_return Fault::Code::Success;
            }
            if (Authenticated_ && EventValue.Unidirectional)
            {
                co_return Fault::Code::Success;
            }
            if (!Authenticated_ || EventValue.Unidirectional)
            {
                const auto Code = Server_->Feed(EventValue.Provider->StreamId(), EventValue.Data, EventValue.Fin);
                if (Code != Fault::Code::Success)
                {
                    co_return Code;
                }
                if (!Authenticated_ && EventValue.Fin && Server_->AuthHeadersComplete() &&
                    EventValue.Provider->StreamId() == Server_->AuthStreamId())
                {
                    if (!Server_->CheckAuth())
                    {
                        co_return Fault::Code::AuthFailed;
                    }
                    if (Server_->SubmitAuthResponse() != Fault::Code::Success)
                    {
                        co_return Fault::Code::ProtocolError;
                    }
                    Authenticated_ = true;
                    AuthStream_ = Server_->AuthStreamId();
                    if (Options_.OnAuthenticated)
                    {
                        Options_.OnAuthenticated();
                    }
                }
                co_return co_await DrainOutput();
            }

            if (!Options_.OnRawData)
            {
                co_return Fault::Code::Success;
            }
            auto Action = Options_.OnRawData(EventValue.Provider->StreamId(), EventValue.Data, EventValue.Fin);
            const auto Code = co_await WriteRaw(EventValue.Provider, Action.Data, Action.Fin);
            if (Code != Fault::Code::Success)
            {
                co_return Code;
            }
            if (Action.Stop)
            {
                TerminalCode_ = Fault::Code::Success;
                StopStream_ = EventValue.Provider->StreamId();
                if (Action.GracefulClose.count() > 0)
                {
                    Net::steady_timer Timer(Options_.Executor);
                    Timer.expires_after(Action.GracefulClose);
                    boost::system::error_code TimerError;
                    co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
                }
                Close();
            }
            if (EventValue.Fin && StopStream_ == EventValue.Provider->StreamId())
            {
                Close();
            }
            co_return Fault::Code::Success;
        }

        [[nodiscard]] auto DrainOutput() -> Net::awaitable<Fault::Code>
        {
            while (!Closed_)
            {
                std::vector<OutPacket> Packets;
                if (!Server_->PumpOutput(Packets))
                {
                    co_return Fault::Code::ProtocolError;
                }
                if (Packets.empty())
                {
                    co_return Fault::Code::Success;
                }
                for (const auto &Packet : Packets)
                {
                    const auto StreamIterator = Streams_.find(Packet.StreamId);
                    if (StreamIterator == Streams_.end() || !StreamIterator->second)
                    {
                        co_return Fault::Code::ProtocolError;
                    }
                    const auto Code = co_await WritePacket(Packet, StreamIterator->second);
                    if (Code != Fault::Code::Success)
                    {
                        co_return Code;
                    }
                }
            }
            co_return Fault::Code::Canceled;
        }

        [[nodiscard]] auto WritePacket(
            const OutPacket &Packet,
            const Preview::Quic::SharedStreamProvider &Provider) -> Net::awaitable<Fault::Code>
        {
            std::size_t Offset = 0;
            while (Offset < Packet.Data.size())
            {
                std::error_code Error;
                const auto Written = co_await Provider->Write(
                    std::span<const std::byte>(Packet.Data).subspan(Offset), Error);
                if (Error || Written == 0 || Written > Packet.Data.size() - Offset)
                {
                    co_return Fault::Code::IoError;
                }
                Offset += Written;
                Server_->AddWriteOffset(Packet.StreamId, Written);
            }
            if (Packet.Data.empty())
            {
                Server_->AddWriteOffset(Packet.StreamId, 0);
            }
            if (Packet.Fin)
            {
                Provider->ShutdownWrite();
            }
            co_return Fault::Code::Success;
        }

        [[nodiscard]] auto WriteRaw(
            const Preview::Quic::SharedStreamProvider &Provider,
            std::span<const std::byte> Data,
            const bool Fin) -> Net::awaitable<Fault::Code>
        {
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                std::error_code Error;
                const auto Written = co_await Provider->Write(Data.subspan(Offset), Error);
                if (Error || Written == 0 || Written > Data.size() - Offset)
                {
                    co_return Fault::Code::IoError;
                }
                Offset += Written;
            }
            if (Fin)
            {
                Provider->ShutdownWrite();
            }
            co_return Fault::Code::Success;
        }

        NativeServerSessionOptions Options_;
        SharedServer Server_;
        EventChannel Events_;
        std::array<Preview::Quic::SharedStreamProvider, 3> Http3Streams_{};
        std::unordered_map<std::int64_t, Preview::Quic::SharedStreamProvider> Streams_;
        bool Closed_{false};
        bool Authenticated_{false};
        std::int64_t AuthStream_{-1};
        Fault::Code TerminalCode_{Fault::Code::Canceled};
        std::int64_t StopStream_{-1};
    };

} // namespace Preview::Http3
