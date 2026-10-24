/**
 * @file MuxInterop.hpp
 * @brief Integration client 共用的 mux wire、partial I/O 与 close/drain owner。
 * @details 仅由 Trojan 与 VMess application-mux 独立 client 使用；不拥有协议
 *          认证、不包含 main/TEST，也不承担外部进程编排。输入 transport 按值或
 *          shared owner 接收，失败返回 false，成功必须验证 payload、stream EOF、
 *          session close 和底层 transport close；所有 I/O 在传入 transport executor。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Testing::Integration::Mux
{
    namespace Net = boost::asio;

    struct HostPort final
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    enum class MuxMode : std::uint8_t
    {
        Smux,
        Yamux,
        H2Mux,
    };

    [[nodiscard]] inline auto ParseMuxMode(std::string_view Value)
        -> std::optional<MuxMode>
    {
        if (Value == "Smux") return MuxMode::Smux;
        if (Value == "Yamux") return MuxMode::Yamux;
        if (Value == "H2Mux") return MuxMode::H2Mux;
        return std::nullopt;
    }

    struct MuxTransferRequest final
    {
        HostPort Target;
        MuxMode Mode{MuxMode::Smux};
        std::vector<std::byte> FirstPayload;
        std::vector<std::byte> SecondPayload;
        std::vector<std::byte> ContinuationPayload;
    };

    [[nodiscard]] inline auto BuildMuxRequest(
        const HostPort &Target,
        std::span<const std::byte> Payload) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result{std::byte{0}, std::byte{0}};
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(Target.Host, Error);
        if (!Error && Address.is_v4())
        {
            Result.push_back(std::byte{1});
            for (const auto Byte : Address.to_v4().to_bytes())
                Result.push_back(std::byte{Byte});
        }
        else if (!Error && Address.is_v6())
        {
            Result.push_back(std::byte{4});
            for (const auto Byte : Address.to_v6().to_bytes())
                Result.push_back(std::byte{Byte});
        }
        else if (!Target.Host.empty() && Target.Host.size() <= 255U)
        {
            Result.push_back(std::byte{3});
            Result.push_back(std::byte{static_cast<unsigned char>(Target.Host.size())});
            for (const auto Byte : Target.Host)
                Result.push_back(std::byte{static_cast<unsigned char>(Byte)});
        }
        else return {};
        Result.push_back(std::byte{static_cast<unsigned char>(Target.Port >> 8U)});
        Result.push_back(std::byte{static_cast<unsigned char>(Target.Port)});
        Result.insert(Result.end(), Payload.begin(), Payload.end());
        return Result;
    }

    [[nodiscard]] inline auto WriteAll(
        Prism::SharedTransmission Transport,
        std::span<const std::byte> Bytes) -> Net::awaitable<bool>
    {
        if (!Transport) co_return false;
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            const auto Written = co_await Transport->WriteSome(Bytes.subspan(Offset));
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > Bytes.size() - Offset) co_return false;
            Offset += Written.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] inline auto ReadExact(
        Prism::SharedTransmission Transport,
        std::span<std::byte> Bytes) -> Net::awaitable<bool>
    {
        if (!Transport) co_return false;
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            const auto Read = co_await Transport->ReadSome(Bytes.subspan(Offset));
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > Bytes.size() - Offset) co_return false;
            Offset += Read.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] inline auto ReadEof(
        Prism::SharedTransmission Transport) -> Net::awaitable<bool>
    {
        std::array<std::byte, 1> Buffer{};
        const auto Read = co_await Transport->ReadSome(Buffer);
        co_return Read.Bytes == 0 && Read.Failure.Code == Prism::Fault::Code::Eof;
    }

    [[nodiscard]] inline auto ReadAndCompare(
        const Prism::SharedTransmission &Transport,
        std::span<const std::byte> Expected) -> Net::awaitable<bool>
    {
        std::vector<std::byte> Actual(Expected.size(), std::byte{0});
        if (!co_await ReadExact(Transport, Actual)) co_return false;
        co_return std::equal(Actual.begin(), Actual.end(), Expected.begin(), Expected.end());
    }

    [[nodiscard]] inline auto ReadAdmission(
        const Prism::SharedTransmission &Transport) -> Net::awaitable<bool>
    {
        std::array<std::byte, 1> Status{};
        co_return co_await ReadExact(Transport, Status) && Status.front() == std::byte{0};
    }

    /** @brief 先等待 mux session 退栈，再取消并关闭 raw owner。 */
    template <typename Client>
    [[nodiscard]] inline auto CloseMux(
        std::shared_ptr<Client> Mux,
        Prism::SharedTransmission Raw) -> Net::awaitable<bool>
    {
        bool Closed = true;
        if (Mux)
        {
            try
            {
                if (const auto Session = Mux->Session()) co_await Session->Close();
            }
            catch (...) { Closed = false; }
        }
        if (Raw)
        {
            const auto Cancelled = Raw->Cancel();
            const auto CloseResult = Raw->Close();
            if (!Cancelled || !CloseResult) Closed = false;
            const auto Drained = co_await Raw->Activity()->Drain();
            if (!Drained) Closed = false;
        }
        co_return Closed;
    }

    template <typename Client>
    [[nodiscard]] inline auto RunMuxClient(
        Prism::SharedTransmission Connection,
        MuxTransferRequest Request) -> Net::awaitable<bool>
    {
        const std::array<std::byte, 2> Envelope{
            std::byte{0}, std::byte{static_cast<std::uint8_t>(Request.Mode)}};
        const auto Raw = Connection;
        auto Mux = std::make_shared<Client>();
        bool Succeeded = false;
        try
        {
            do
            {
                if (!co_await WriteAll(Connection, Envelope) ||
                    !Mux->Connect(std::move(Connection))) break;
                auto First = co_await Mux->OpenStream();
                auto Second = co_await Mux->OpenStream();
                if (!First || !Second) break;
                const auto FirstRequest = BuildMuxRequest(Request.Target, Request.FirstPayload);
                if (FirstRequest.empty() || !co_await WriteAll(First, FirstRequest) ||
                    !co_await ReadAdmission(First) ||
                    !co_await ReadAndCompare(First, Request.FirstPayload)) break;
                const auto SecondRequest = BuildMuxRequest(Request.Target, Request.SecondPayload);
                if (SecondRequest.empty() || !co_await WriteAll(Second, SecondRequest) ||
                    !co_await ReadAdmission(Second) ||
                    !co_await ReadAndCompare(Second, Request.SecondPayload)) break;
                if (!co_await First->WriteShutdown()) break;
                if (!co_await ReadEof(First)) break;
                if (!co_await WriteAll(Second, Request.ContinuationPayload) ||
                    !co_await ReadAndCompare(Second, Request.ContinuationPayload)) break;
                if (!co_await Second->WriteShutdown()) break;
                if (!co_await ReadEof(Second)) break;
                Succeeded = true;
            } while (false);
        }
        catch (...) { Succeeded = false; }
        const auto Closed = co_await CloseMux(Mux, Raw);
        co_return Succeeded && Closed && !Mux->IsOpen();
    }

    class H2MuxClient final : public std::enable_shared_from_this<H2MuxClient>
    {
    public:
        explicit H2MuxClient(Prism::SharedTransmission Raw)
            : Raw_(std::move(Raw)),
              Session_(std::make_shared<Prism::Http2::Session>(Raw_->Executor(), false)),
              Notify_(Raw_->Executor(), 32), DriverDone_(Raw_->Executor(), 1)
        {
        }

        auto BindCallbacks() -> void
        {
            const auto Weak = weak_from_this();
            Session_->OnHeaders = [Weak](const std::int32_t Id,
                                         const Prism::Http2::HeaderList &Headers,
                                         const bool EndStream)
            {
                if (const auto Self = Weak.lock()) Self->HandleHeaders(Id, Headers, EndStream);
            };
            Session_->OnData = [Weak](const std::int32_t Id, std::span<const std::byte> Data)
            {
                if (const auto Self = Weak.lock())
                {
                    Self->Rx_[Id].insert(Self->Rx_[Id].end(), Data.begin(), Data.end());
                    (void)Self->Notify_.try_send(boost::system::error_code{});
                }
            };
            Session_->OnStreamClose = [Weak](const Prism::Http2::StreamReceiveClosure &Closure)
            {
                if (const auto Self = Weak.lock())
                {
                    Self->StreamClosures_.insert_or_assign(Closure.StreamId, Closure);
                    (void)Self->Notify_.try_send(boost::system::error_code{});
                }
            };
        }

        auto Start() -> void
        {
            if (DriverStarted_) return;
            DriverStarted_ = true;
            const auto Self = shared_from_this();
            Net::co_spawn(Raw_->Executor(), RunDriver(Self),
                [Self](std::exception_ptr Failure)
                {
                    Self->DriverFailed_ = static_cast<bool>(Failure);
                    Self->DriverFinished_ = true;
                    (void)Self->DriverDone_.try_send(boost::system::error_code{});
                });
        }

        [[nodiscard]] auto SendSettings() -> Net::awaitable<bool>
        {
            Session_->SendSettings();
            co_return co_await Flush();
        }

        /**
         * @brief 在客户端 HTTP/2 会话打开请求 stream 并 flush 初始帧。
         * @param Headers 头列表；只借用至 Session 同步编码完成。
         * @return stream ID；打开失败保留会话 Failure，测试传输 flush 失败返回 IoError。
         * @details 协程在 Raw executor 上运行并由此 client 持有 Raw/Session。等待可由协程
         *          取消；本 helper 不转移连接所有权，最终 Raw 关闭仍由测试 client owner 完成。
         */
        [[nodiscard]] auto OpenStream(const Prism::Http2::HeaderList &Headers)
            -> Net::awaitable<std::expected<std::int32_t, Prism::Fault::Failure>>
        {
            const auto Id = Session_->OpenStream(Headers, false);
            if (!Id) co_return std::unexpected(Id.error());
            if (!co_await Flush())
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return *Id;
        }

        [[nodiscard]] auto SendData(
            const std::int32_t Id,
            std::span<const std::byte> Data,
            const bool EndStream) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            bool EmptySubmitted = false;
            while (Offset < Data.size() || !EmptySubmitted)
            {
                const auto Count = (std::min)(std::size_t{16U * 1024U}, Data.size() - Offset);
                const auto Chunk = Data.subspan(Offset, Count);
                const auto Last = Offset + Count == Data.size();
                auto Status = Session_->SubmitData(Id, Chunk, EndStream && Last);
                while (Status == Prism::Http2::SubmitDataStatus::Blocked)
                {
                    if (!co_await Flush()) co_return false;
                    const auto Writable = co_await Session_->AwaitWritable(Id, Count);
                    if (!Writable) co_return false;
                    Status = Session_->SubmitData(Id, Chunk, EndStream && Last);
                }
                if (Status != Prism::Http2::SubmitDataStatus::Accepted) co_return false;
                Offset += Count;
                EmptySubmitted = true;
                if (!co_await Flush()) co_return false;
            }
            co_return true;
        }

        [[nodiscard]] auto ReadExact(
            const std::int32_t Id,
            std::span<std::byte> Output) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                auto &Pending = Rx_[Id];
                if (!Pending.empty())
                {
                    const auto Count = (std::min)(Output.size() - Offset, Pending.size());
                    std::copy_n(Pending.begin(), Count,
                        Output.begin() + static_cast<std::ptrdiff_t>(Offset));
                    Pending.erase(Pending.begin(), Pending.begin() + static_cast<std::ptrdiff_t>(Count));
                    Offset += Count;
                    continue;
                }
                if (StreamClosures_.contains(Id) || ConnectionClosed_ || TerminalError_)
                    co_return false;
                boost::system::error_code Error;
                co_await Notify_.async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (ConnectionClosed_ || TerminalError_ || Error) co_return false;
            }
            co_return true;
        }

        [[nodiscard]] auto ReadAndCompare(
            const std::int32_t Id,
            std::span<const std::byte> Expected) -> Net::awaitable<bool>
        {
            std::vector<std::byte> Actual(Expected.size(), std::byte{0});
            if (!co_await ReadExact(Id, Actual)) co_return false;
            co_return std::equal(Actual.begin(), Actual.end(), Expected.begin(), Expected.end());
        }

        [[nodiscard]] auto WaitHeaders(const std::int32_t Id) -> Net::awaitable<bool>
        {
            while (!HeadersSeen_.contains(Id))
            {
                if (ConnectionClosed_ || TerminalError_) co_return false;
                boost::system::error_code Error;
                co_await Notify_.async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (ConnectionClosed_ || TerminalError_ || Error) co_return false;
            }
            co_return HeadersValid_[Id];
        }

        [[nodiscard]] auto ReadAdmission(const std::int32_t Id) -> Net::awaitable<bool>
        {
            std::array<std::byte, 1> Status{};
            co_return co_await ReadExact(Id, Status) && Status.front() == std::byte{0};
        }

        [[nodiscard]] auto WaitClosed(const std::int32_t Id) -> Net::awaitable<bool>
        {
            while (!StreamClosures_.contains(Id))
            {
                if (ConnectionClosed_ || TerminalError_) co_return false;
                boost::system::error_code Error;
                co_await Notify_.async_receive(Net::redirect_error(Net::use_awaitable, Error));
                if (ConnectionClosed_ || TerminalError_ || Error) co_return false;
            }
            const auto Iterator = StreamClosures_.find(Id);
            co_return !TerminalError_ && Iterator != StreamClosures_.end() &&
                Iterator->second.Kind == Prism::Http2::StreamReceiveClosureKind::EndStream &&
                Iterator->second.ErrorCode == Prism::Http2::ErrorNoError;
        }

        [[nodiscard]] auto Close() -> Net::awaitable<bool>
        {
            bool Closed = true;
            try
            {
                if (!ConnectionClosed_ && !TerminalError_)
                {
                    Session_->SendGoaway(0, 0);
                    (void)co_await Flush();
                }
            }
            catch (...) { Closed = false; }
            const auto Shutdown = co_await Raw_->WriteShutdown();
            const auto Cancelled = Raw_->Cancel();
            const auto CloseResult = Raw_->Close();
            if (!Shutdown || !Cancelled || !CloseResult) Closed = false;
            try { co_await WaitDriverFinished(); } catch (...) { Closed = false; }
            const auto DrainResult = co_await Raw_->Activity()->Drain();
            if (!DrainResult || DriverFailed_) Closed = false;
            co_return Closed;
        }

        [[nodiscard]] auto IsOpen() const noexcept -> bool
        { return Raw_->IsOpen() && !ConnectionClosed_; }

    private:
        static auto RunDriver(std::shared_ptr<H2MuxClient> Self) -> Net::awaitable<void>
        {
            try { co_await Self->ReadLoop(); }
            catch (...) { Self->MarkConnectionClosed(std::make_error_code(std::errc::io_error)); }
        }

        auto HandleHeaders(const std::int32_t Id,
                           const Prism::Http2::HeaderList &Headers,
                           const bool EndStream) -> void
        {
            bool StatusOk = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status") { StatusOk = Header.Value == "200"; break; }
            }
            HeadersSeen_[Id] = true;
            HeadersValid_[Id] = StatusOk && !EndStream;
            (void)Notify_.try_send(boost::system::error_code{});
        }

        auto MarkConnectionClosed(const std::error_code &Error) -> void
        {
            if (Error && !TerminalError_) TerminalError_ = Error;
            if (ConnectionClosed_) return;
            ConnectionClosed_ = true;
            Notify_.close();
        }

        [[nodiscard]] auto Flush() -> Net::awaitable<bool>
        {
            std::vector<std::byte> Output;
            while (Session_->Collect(Output))
            {
                if (Output.empty() || !co_await WriteAll(Raw_, Output)) co_return false;
                Output.clear();
            }
            co_return true;
        }

        auto ReadLoop() -> Net::awaitable<void>
        {
            std::array<std::byte, 16384> Buffer{};
            while (Raw_->IsOpen() && !ConnectionClosed_)
            {
                const auto Read = co_await Raw_->ReadSome(Buffer);
                if (Read.Bytes > Buffer.size())
                {
                    MarkConnectionClosed(std::make_error_code(std::errc::message_size));
                    co_return;
                }
                if (Read.Bytes == 0)
                {
                    MarkConnectionClosed(Prism::Fault::ToNative(Read.Failure));
                    co_return;
                }
                std::error_code FeedError;
                if (!Session_->Feed(std::span<const std::byte>(Buffer.data(), Read.Bytes), FeedError))
                {
                    MarkConnectionClosed(FeedError ? FeedError :
                        std::make_error_code(std::errc::protocol_error));
                    co_return;
                }
                (void)Notify_.try_send(boost::system::error_code{});
                if (Read.Failure.Failed())
                {
                    MarkConnectionClosed(Prism::Fault::ToNative(Read.Failure));
                    co_return;
                }
            }
            MarkConnectionClosed({});
        }

        /** @brief 等待帧循环真实 completion；连接关闭状态不替代协程退栈。 */
        auto WaitDriverFinished() -> Net::awaitable<void>
        {
            if (DriverStarted_ && !DriverFinished_)
            {
                co_await DriverDone_.async_receive(Net::use_awaitable);
            }
        }

        Prism::SharedTransmission Raw_;
        std::shared_ptr<Prism::Http2::Session> Session_;
        Net::experimental::channel<void(boost::system::error_code)> Notify_;
        Net::experimental::channel<void(boost::system::error_code)> DriverDone_;
        std::unordered_map<std::int32_t, std::vector<std::byte>> Rx_;
        std::unordered_map<std::int32_t, bool> HeadersSeen_;
        std::unordered_map<std::int32_t, bool> HeadersValid_;
        std::unordered_map<std::int32_t, Prism::Http2::StreamReceiveClosure> StreamClosures_;
        std::error_code TerminalError_;
        bool ConnectionClosed_{false};
        bool DriverStarted_{false}, DriverFinished_{false}, DriverFailed_{false};
    };

    [[nodiscard]] inline auto RunH2MuxClient(
        Prism::SharedTransmission Connection,
        MuxTransferRequest Request) -> Net::awaitable<bool>
    {
        const std::array<std::byte, 2> Envelope{std::byte{0}, std::byte{2}};
        if (!co_await WriteAll(Connection, Envelope))
        {
            Connection->Close();
            co_return false;
        }
        auto Client = std::make_shared<H2MuxClient>(Connection);
        Client->BindCallbacks();
        Client->Start();
        bool Succeeded = false;
        try
        {
            do
            {
                if (!co_await Client->SendSettings()) break;
                const Prism::Http2::HeaderList Headers{
                    {":method", "POST"}, {":path", "/"}, {":scheme", "https"},
                    {":authority", Request.Target.Host}};
                const auto FirstOpened = co_await Client->OpenStream(Headers);
                const auto SecondOpened = co_await Client->OpenStream(Headers);
                if (!FirstOpened || !SecondOpened) break;
                const auto FirstId = *FirstOpened;
                const auto SecondId = *SecondOpened;
                const auto FirstRequest = BuildMuxRequest(Request.Target, Request.FirstPayload);
                if (FirstRequest.empty() || !co_await Client->SendData(FirstId, FirstRequest, false) ||
                    !co_await Client->WaitHeaders(FirstId) || !co_await Client->ReadAdmission(FirstId) ||
                    !co_await Client->ReadAndCompare(FirstId, Request.FirstPayload)) break;
                const auto SecondRequest = BuildMuxRequest(Request.Target, Request.SecondPayload);
                if (SecondRequest.empty() || !co_await Client->SendData(SecondId, SecondRequest, false) ||
                    !co_await Client->WaitHeaders(SecondId) || !co_await Client->ReadAdmission(SecondId) ||
                    !co_await Client->ReadAndCompare(SecondId, Request.SecondPayload)) break;
                if (!co_await Client->SendData(FirstId, {}, true) || !co_await Client->WaitClosed(FirstId)) break;
                if (!co_await Client->SendData(SecondId, Request.ContinuationPayload, false) ||
                    !co_await Client->ReadAndCompare(SecondId, Request.ContinuationPayload)) break;
                if (!co_await Client->SendData(SecondId, {}, true) || !co_await Client->WaitClosed(SecondId)) break;
                Succeeded = true;
            } while (false);
        }
        catch (...) { Succeeded = false; }
        const auto Closed = co_await Client->Close();
        co_return Succeeded && Closed && !Client->IsOpen();
    }
}
