/**
 * @file H2MuxServer.hpp
 * @brief sing-mux H2Mux 的标准 HTTP/2 服务端桥接。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Composition::SingMux
{

    namespace Net = boost::asio;

    class H2Stream;

    struct H2ServerState final : std::enable_shared_from_this<H2ServerState>
    {
        using FlushChannel = Net::experimental::channel<void(boost::system::error_code)>;

        explicit H2ServerState(Preview::SharedTransmission RawValue)
            : Strand(RawValue->Executor()),
              Raw(std::move(RawValue)),
              Notify(Strand, 1),
              FlushGate(std::make_shared<FlushChannel>(Strand, 1))
        {
            (void)FlushGate->try_send(boost::system::error_code{});
        }

        Net::strand<Net::any_io_executor> Strand;
        Preview::SharedTransmission Raw;
        std::shared_ptr<Preview::Http2::SessionImpl> Session;
        Net::experimental::channel<void(boost::system::error_code)> Notify;
        std::shared_ptr<FlushChannel> FlushGate;
        std::deque<std::shared_ptr<H2Stream>> Incoming;
        std::map<std::int32_t, std::weak_ptr<H2Stream>> Streams;
        bool Closed{false};

        auto OnHeaders(
            std::int32_t StreamId,
            const Preview::Http2::HeaderList &Headers,
            bool EndStream) -> void;
        auto OnData(std::int32_t StreamId, std::span<const std::byte> Data) -> void;
        auto OnClose(std::int32_t StreamId, std::uint32_t ErrorCode) -> void;
        auto Close() -> void;
        [[nodiscard]] auto Flush() -> Net::awaitable<bool>;
        [[nodiscard]] auto WriteAll(std::span<const std::byte> Data) -> Net::awaitable<bool>;
    };

    class H2Stream final : public Preview::Transmission
    {
    public:
        H2Stream(std::shared_ptr<H2ServerState> StateValue, const std::int32_t StreamIdValue)
            : State_(std::move(StateValue)), StreamId_(StreamIdValue), Notify_(State_->Strand)
        {
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int32_t
        {
            return StreamId_;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return State_->Strand;
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            while (true)
            {
                if (Closed_ || !State_ || State_->Closed)
                {
                    ErrorCode.clear();
                    co_return 0;
                }
                if (!Rx_.empty())
                {
                    auto &Front = Rx_.front();
                    const auto Count = (std::min)(Buffer.size(), Front.size());
                    std::copy_n(Front.begin(), Count, Buffer.begin());
                    if (Count == Front.size())
                    {
                        Rx_.pop_front();
                    }
                    else
                    {
                        Front.erase(Front.begin(), Front.begin() + static_cast<std::ptrdiff_t>(Count));
                    }
                    ErrorCode.clear();
                    co_return Count;
                }
                if (RemoteClosed_)
                {
                    ErrorCode.clear();
                    co_return 0;
                }
                Notify_.reset();
                co_await Notify_.async_receive(Net::use_awaitable);
                co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            }
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            if (Closed_ || !State_ || State_->Closed || !State_->Session)
            {
                ErrorCode = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            if (State_->Session->SubmitData(StreamId_, Buffer, false) != 0 ||
                !co_await State_->Flush())
            {
                ErrorCode = std::make_error_code(std::errc::broken_pipe);
                co_return 0;
            }
            ErrorCode.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            if (!State_)
            {
                return;
            }
            auto State = State_;
            const auto StreamIdValue = StreamId_;
            Closed_ = true;
            RemoteClosed_ = true;
            Notify_.try_send(boost::system::error_code{});
            // 注意：executor 必须在 move(State) 之前取出。co_spawn 的实参求值顺序
            // 未指定，GCC 自右向左求值会先把 State 置空，再对空指针取 Strand。
            const auto Executor = State->Strand;
            Net::co_spawn(Executor, CloseOnStrand(std::move(State), StreamIdValue),
                          Net::detached);
        }

        auto Shutdown() -> void override
        {
            if (!State_ || Closed_)
            {
                return;
            }
            auto State = State_;
            const auto StreamIdValue = StreamId_;
            const auto Executor = State->Strand;
            // H2 的半关只发送当前虚拟流的 END_STREAM，不能沿 NextLayer()
            // 关闭共享的 TLS/TCP 会话，否则兄弟流会收到截断响应。
            Net::co_spawn(Executor, CloseOnStrand(std::move(State), StreamIdValue),
                          Net::detached);
        }

        auto Cancel() -> void override
        {
            // 只终止当前虚拟流：Raw 是整条会话共享的底层传输，
            // 取消它会连带摧毁兄弟流（生产表现为并发下整条会话卡死）。
            Closed_ = true;
            RemoteClosed_ = true;
            Notify_.try_send(boost::system::error_code{});
        }

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (State_ && State_->Raw)
            {
                State_->Raw->SetTimeout(Timeout);
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_ && State_ && !State_->Closed && State_->Raw && State_->Raw->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return State_ && State_->Raw ? State_->Raw.get() : nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return State_ && State_->Raw ? State_->Raw.get() : nullptr;
        }

        auto Push(std::span<const std::byte> Data) -> void
        {
            if (Closed_ || RemoteClosed_ || Data.empty())
            {
                return;
            }
            Rx_.emplace_back(Data.begin(), Data.end());
            Notify_.try_send(boost::system::error_code{});
        }

        auto SetRemoteClosed() -> void
        {
            RemoteClosed_ = true;
            Notify_.try_send(boost::system::error_code{});
        }

    private:
        [[nodiscard]] static auto CloseOnStrand(
            std::shared_ptr<H2ServerState> State,
            const std::int32_t StreamIdValue) -> Net::awaitable<void>
        {
            if (State && State->Session)
            {
                (void)State->Session->SubmitData(
                    StreamIdValue, std::span<const std::byte>{}, true);
                (void)co_await State->Flush();
            }
        }

        std::shared_ptr<H2ServerState> State_;
        std::int32_t StreamId_{0};
        Net::experimental::channel<void(boost::system::error_code)> Notify_;
        std::deque<std::vector<std::byte>> Rx_;
        bool RemoteClosed_{false};
        bool Closed_{false};
    };

    inline auto H2ServerState::OnHeaders(
        const std::int32_t StreamId,
        const Preview::Http2::HeaderList & /*Headers*/,
        const bool EndStream) -> void
    {
        if (Closed || Streams.contains(StreamId))
        {
            return;
        }
        auto Stream = std::make_shared<H2Stream>(shared_from_this(), StreamId);
        Streams.emplace(StreamId, Stream);
        Incoming.push_back(Stream);
        if (Session->SubmitHeaders(
                StreamId, Preview::Http2::HeaderList{{":status", "200"}}, false) != 0)
        {
            Stream->SetRemoteClosed();
            Streams.erase(StreamId);
            return;
        }
        if (EndStream)
        {
            Stream->SetRemoteClosed();
        }
        Notify.try_send(boost::system::error_code{});
    }

    inline auto H2ServerState::OnData(
        const std::int32_t StreamId,
        const std::span<const std::byte> Data) -> void
    {
        if (const auto Iterator = Streams.find(StreamId); Iterator != Streams.end())
        {
            if (const auto Stream = Iterator->second.lock())
            {
                Stream->Push(Data);
            }
        }
    }

    inline auto H2ServerState::OnClose(
        const std::int32_t StreamId,
        const std::uint32_t /*ErrorCode*/) -> void
    {
        if (const auto Iterator = Streams.find(StreamId); Iterator != Streams.end())
        {
            if (const auto Stream = Iterator->second.lock())
            {
                Stream->SetRemoteClosed();
            }
            Streams.erase(Iterator);
        }
    }

    inline auto H2ServerState::WriteAll(const std::span<const std::byte> Data)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code ErrorCode;
            const auto Written = co_await Raw->async_write_some(Data.subspan(Offset), ErrorCode);
            if (ErrorCode || Written == 0 || Written > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    inline auto H2ServerState::Flush() -> Net::awaitable<bool>
    {
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (!FlushGate)
        {
            co_return false;
        }
        boost::system::error_code GateError;
        co_await FlushGate->async_receive(
            Net::redirect_error(Net::use_awaitable, GateError));
        co_await Net::dispatch(Strand, Net::use_awaitable);
        if (GateError)
        {
            co_return false;
        }
        struct FlushRelease final
        {
            std::shared_ptr<FlushChannel> Gate;

            ~FlushRelease() noexcept
            {
                if (Gate)
                {
                    (void)Gate->try_send(boost::system::error_code{});
                }
            }
        } Release{FlushGate};

        std::vector<std::byte> Wire;
        while (Session->Collect(Wire))
        {
            if (!co_await WriteAll(Wire))
            {
                co_return false;
            }
            Wire.clear();
            co_await Net::dispatch(Strand, Net::use_awaitable);
        }
        co_return true;
    }

    inline auto H2ServerState::Close() -> void
    {
        Closed = true;
        Notify.try_send(boost::system::error_code{});
        for (auto &[Id, Stream] : Streams)
        {
            if (const auto Value = Stream.lock())
            {
                Value->SetRemoteClosed();
            }
        }
        Streams.clear();
        Incoming.clear();
        if (Raw)
        {
            Raw->Cancel();
            Raw->Close();
        }
    }

    class H2Server final : public std::enable_shared_from_this<H2Server>
    {
    public:
        explicit H2Server(Preview::SharedTransmission Raw)
            : State_(std::make_shared<H2ServerState>(std::move(Raw)))
        {
            State_->Session = std::make_shared<Preview::Http2::SessionImpl>(State_->Strand, true);
            const auto WeakState = std::weak_ptr<H2ServerState>(State_);
            State_->Session->OnHeaders = [WeakState](
                const std::int32_t Id,
                const Preview::Http2::HeaderList &Headers,
                const bool EndStream)
            {
                if (const auto State = WeakState.lock())
                {
                    State->OnHeaders(Id, Headers, EndStream);
                }
            };
            State_->Session->OnData = [WeakState](
                const std::int32_t Id, const std::span<const std::byte> Data)
            {
                if (const auto State = WeakState.lock())
                {
                    State->OnData(Id, Data);
                }
            };
            State_->Session->OnStreamClose = [WeakState](
                const std::int32_t Id, const std::uint32_t ErrorCode)
            {
                if (const auto State = WeakState.lock())
                {
                    State->OnClose(Id, ErrorCode);
                }
            };
        }

        [[nodiscard]] auto RunLoop() -> Net::awaitable<void>
        {
            try
            {
                co_await Net::dispatch(State_->Strand, Net::use_awaitable);
                State_->Session->SendSettings();
                if (!co_await State_->Flush())
                {
                    State_->Close();
                    co_return;
                }
                std::array<std::byte, 16 * 1024> Buffer{};
                while (!State_->Closed && State_->Raw && State_->Raw->IsOpen())
                {
                    std::error_code ErrorCode;
                    const auto Count = co_await State_->Raw->async_read_some(Buffer, ErrorCode);
                    co_await Net::dispatch(State_->Strand, Net::use_awaitable);
                    if (ErrorCode || Count == 0)
                    {
                        break;
                    }
                    std::error_code FeedError;
                    if (!State_->Session->Feed(
                            std::span<const std::byte>(Buffer.data(), Count), FeedError) ||
                        !co_await State_->Flush())
                    {
                        break;
                    }
                }
                State_->Close();
            }
            catch (...)
            {
                State_->Close();
            }
            co_return;
        }

        [[nodiscard]] auto AcceptStream() -> Net::awaitable<Preview::SharedTransmission>
        {
            co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            while (!State_->Closed)
            {
                if (!State_->Incoming.empty())
                {
                    auto Stream = std::move(State_->Incoming.front());
                    State_->Incoming.pop_front();
                    co_return Stream;
                }
                State_->Notify.reset();
                co_await State_->Notify.async_receive(Net::use_awaitable);
                co_await Net::dispatch(State_->Strand, Net::use_awaitable);
            }
            co_return nullptr;
        }

        [[nodiscard]] auto StreamId(const Preview::SharedTransmission &Stream) const noexcept
            -> std::int32_t
        {
            if (const auto *Value = dynamic_cast<const H2Stream *>(Stream.get()))
            {
                return Value->StreamId();
            }
            return 0;
        }

        auto Close() -> void
        {
            auto State = State_;
            Net::dispatch(State->Strand, [State] { State->Close(); });
        }

        auto Cancel() -> void
        {
            Close();
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->Strand;
        }

    private:
        std::shared_ptr<H2ServerState> State_;
    };

} // namespace Preview::Composition::SingMux
