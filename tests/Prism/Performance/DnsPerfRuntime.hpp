/**
 * @file DnsPerfRuntime.hpp
 * @brief DNS fake server/runtime 所有者，供 DNS preflight 与 coalescer 所有者复用。
 */

#pragma once

#include "DnsPerf.hpp"
#include <Prism/Foundation/Fault/Failure.hpp>

namespace DnsPerf
{
    namespace Net = boost::asio;
    namespace Dns = Prism::Network::Dns;
    using GateChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using Config = Prism::Network::Dns::Config;
    inline auto PutU16(std::vector<std::uint8_t> &Output, std::uint16_t Value) -> void;

    struct alignas(64) DnsAlignedProbe final
    {
        std::array<std::byte, 64> Bytes{};
    };

    struct ReadySignal final
    {
        std::promise<bool> Promise;
        std::atomic<bool> Published{false};

        auto Publish(const bool Value) noexcept -> void
        {
            if (Published.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            try
            {
                Promise.set_value(Value);
            }
            catch (...)
            {
            }
        }
    };

    struct ErrorInfo final
    {
        std::string Category{"none"};
        int Value{0};
        std::string Message{"none"};
    };

    class PerfDnsServer : public std::enable_shared_from_this<PerfDnsServer>
    {
    public:
        explicit PerfDnsServer(Net::io_context &IoContext)
            : Ex_(IoContext.get_executor()),
              Udp_(IoContext, Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
            boost::system::error_code ErrorCode;
            Udp_.set_option(Net::socket_base::receive_buffer_size(212992), ErrorCode);
        }

        auto Start(const std::shared_ptr<ReadySignal> &Ready = {}) -> void
        {
            Port_ = Udp_.local_endpoint().port();
            auto self = shared_from_this();
            try
            {
                Net::co_spawn(
                    Ex_,
                    [self, Ready]() { return self->Loop(Ready); },
                    [Ready](std::exception_ptr Failure)
                    {
                        if (Failure && Ready)
                        {
                            Ready->Publish(false);
                        }
                    });
            }
            catch (...)
            {
                if (Ready)
                {
                    Ready->Publish(false);
                }
            }
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        void Close()
        {
            boost::system::error_code ErrorCode;
            Udp_.close(ErrorCode);
            if (FirstResponseGate_)
            {
                (void)FirstResponseGate_->try_send(boost::system::error_code{});
            }
        }

        void HoldFirstResponse(std::shared_ptr<GateChannel> Gate)
        {
            HoldFirstResponse_ = true;
            FirstResponseGate_ = std::move(Gate);
        }

        void ObserveQueries(Net::io_context &Observer, std::shared_ptr<GateChannel> Signal)
        {
            Observer_ = &Observer;
            QuerySignal_ = std::move(Signal);
        }

        void ObserveResponses(Net::io_context &Observer, std::shared_ptr<GateChannel> Signal)
        {
            ResponseObserver_ = &Observer;
            ResponseSignal_ = std::move(Signal);
        }

        void SetEmptyAnswer(const bool Empty)
        {
            EmptyAnswer_ = Empty;
        }

        [[nodiscard]] auto QueryCount() const noexcept -> std::size_t
        {
            return QueryCount_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto ResponseCount() const noexcept -> std::size_t
        {
            return ResponseCount_.load(std::memory_order_acquire);
        }

    private:
        auto SendResponse(std::vector<std::uint8_t> Output,
                          const Net::ip::udp::endpoint Sender) -> Net::awaitable<void>
        {
            const auto Self = shared_from_this();
            boost::system::error_code SendError;
            co_await Self->Udp_.async_send_to(
                Net::buffer(Output), Sender,
                Net::redirect_error(Net::use_awaitable, SendError));
            if (!SendError)
            {
                Self->ResponseCount_.fetch_add(1, std::memory_order_release);
                if (Self->ResponseObserver_ && Self->ResponseSignal_)
                {
                    const auto Signal = Self->ResponseSignal_;
                    Net::post(*Self->ResponseObserver_, [Signal]
                    { (void)Signal->try_send(boost::system::error_code{}); });
                }
            }
        }

        auto Loop(const std::shared_ptr<ReadySignal> &Ready) -> Net::awaitable<void>
        {
            if (Ready)
            {
                Ready->Publish(true);
            }
            std::vector<std::uint8_t> Buffer(4096);
            Net::ip::udp::endpoint Sender;
            for (;;)
            {
                boost::system::error_code ErrorCode;
                const auto Count = co_await Udp_.async_receive_from(
                    Net::buffer(Buffer), Sender, Net::redirect_error(Net::use_awaitable, ErrorCode));
                // 已取消客户端的 ICMP 不可达只影响该端点，服务端继续接收其他合法查询。
                if (ErrorCode == Net::error::connection_reset && Udp_.is_open()) continue;
                if (ErrorCode || Count < 12)
                {
                    std::fprintf(stderr, "dns-fake-receive-close error=%s/%d/%s count=%zu\n",
                        ErrorCode.category().name(), ErrorCode.value(), ErrorCode.message().c_str(), Count);
                    co_return;
                }
                QueryCount_.fetch_add(1, std::memory_order_release);
                if (Observer_ && QuerySignal_)
                {
                    const auto Signal = QuerySignal_;
                    Net::post(*Observer_, [Signal]
                    { (void)Signal->try_send(boost::system::error_code{}); });
                }
                // 问题段结束
                std::size_t Offset = 12;
                while (Offset < static_cast<std::size_t>(Count) && Buffer[Offset] != 0)
                {
                    Offset += static_cast<std::size_t>(Buffer[Offset]) + 1;
                }
                const auto QEnd = Offset + 5;
                if (QEnd > static_cast<std::size_t>(Count))
                {
                    continue;
                }
                std::vector<std::uint8_t> Output;
                PutU16(Output, static_cast<std::uint16_t>((Buffer[0] << 8) | Buffer[1]));
                PutU16(Output, 0x8180u);
                PutU16(Output, 1);
                PutU16(Output, EmptyAnswer_ ? 0 : 1);
                PutU16(Output, 0);
                PutU16(Output, 0);
                Output.insert(Output.end(), Buffer.begin() + 12,
                           Buffer.begin() + static_cast<std::ptrdiff_t>(QEnd));
                if (!EmptyAnswer_)
                {
                    PutU16(Output, 0xC00Cu);
                    PutU16(Output, 1);
                    PutU16(Output, 1);
                    Output.insert(Output.end(), {0, 0, 0, 60, 0, 4, 1, 2, 3, 4});
                }
                if (HoldFirstResponse_ && !FirstResponseHeld_ && FirstResponseGate_)
                {
                    FirstResponseHeld_ = true;
                    boost::system::error_code GateError;
                    co_await FirstResponseGate_->async_receive(
                        Net::redirect_error(Net::use_awaitable, GateError));
                    if (GateError)
                    {
                        co_return;
                    }
                }
                // 响应写入期间继续排空接收队列，避免大量 loopback UDP 客户端在等待发送完成时溢出接收缓冲。
                Net::co_spawn(Ex_, SendResponse(std::move(Output), Sender), Net::detached);
            }
        }

        Net::any_io_executor Ex_;
        Net::ip::udp::socket Udp_;
        std::uint16_t Port_{0};
        Net::io_context *Observer_{nullptr};
        std::shared_ptr<GateChannel> QuerySignal_;
        Net::io_context *ResponseObserver_{nullptr};
        std::shared_ptr<GateChannel> ResponseSignal_;
        std::shared_ptr<GateChannel> FirstResponseGate_;
        std::atomic<std::size_t> QueryCount_{0};
        std::atomic<std::size_t> ResponseCount_{0};
        bool HoldFirstResponse_{false};
        bool FirstResponseHeld_{false};
        bool EmptyAnswer_{false};
    };

    class PerfDnsRuntime final
    {
    public:
        PerfDnsRuntime()
            : Server_(std::make_shared<PerfDnsServer>(ServerIo_))
        {
        }

        auto Start() -> bool
        {
            const auto Ready = std::make_shared<ReadySignal>();
            auto ReadyFuture = Ready->Promise.get_future();
            Server_->Start(Ready);
            Thread_ = std::thread([this] { ServerIo_.run(); });
            Started_ = true;
            if (ReadyFuture.wait_for(std::chrono::seconds(2)) != std::future_status::ready)
            {
                Stop();
                return false;
            }
            if (!ReadyFuture.get())
            {
                Stop();
                return false;
            }
            return true;
        }

        ~PerfDnsRuntime()
        {
            Stop();
        }

        void Stop()
        {
            if (Stopped_)
            {
                return;
            }
            Stopped_ = true;
            if (!Started_)
            {
                return;
            }
            Net::post(ServerIo_, [Server = Server_]
            {
                Server->Close();
            });
            if (Thread_.joinable())
            {
                Thread_.join();
            }
        }

        [[nodiscard]] auto Server() const -> const std::shared_ptr<PerfDnsServer> &
        {
            return Server_;
        }

        [[nodiscard]] auto IoContext() -> Net::io_context &
        {
            return ServerIo_;
        }

    private:
        Net::io_context ServerIo_;
        std::shared_ptr<PerfDnsServer> Server_;
        std::thread Thread_;
        bool Started_{false};
        bool Stopped_{false};
    };

    [[nodiscard]] inline auto MakeErrorInfo(const std::error_code Error) -> ErrorInfo
    {
        if (!Error) return {};
        return {std::string(Error.category().name()), Error.value(), Error.message()};
    }
    [[nodiscard]] inline auto MakeErrorInfo(const Prism::Fault::Failure Failure) -> ErrorInfo
    {
        return MakeErrorInfo(Prism::Fault::ToNative(Failure));
    }
    [[nodiscard]] inline auto MakeExceptionInfo(const std::exception_ptr &Failure) -> ErrorInfo
    {
        if (!Failure) return {};
        try { std::rethrow_exception(Failure); }
        catch (const std::system_error &Error) { return MakeErrorInfo(Error.code()); }
        catch (const boost::system::system_error &Error)
        { return {Error.code().category().name(), Error.code().value(), Error.code().message()}; }
        catch (const std::exception &Error) { return {"std", 0, Error.what()}; }
        catch (...) { return {"unknown", 0, "non-standard exception"}; }
    }
    [[nodiscard]] inline auto IsCancellationCode(const std::error_code Error) noexcept -> bool
    {
        return Error == std::make_error_code(std::errc::operation_canceled) ||
               Error.value() == static_cast<int>(boost::asio::error::operation_aborted);
    }
    [[nodiscard]] inline auto IsCancellationCode(const Prism::Fault::Failure Failure) noexcept -> bool
    {
        return Failure.Code == Prism::Fault::Code::Canceled ||
               IsCancellationCode(Prism::Fault::ToNative(Failure));
    }
    [[nodiscard]] inline auto IsCancellationException(const std::exception_ptr &Failure) noexcept -> bool
    {
        if (!Failure) return false;
        try { std::rethrow_exception(Failure); }
        catch (const std::system_error &Error) { return IsCancellationCode(Error.code()); }
        catch (const boost::system::system_error &Error)
        { return Error.code() == Net::error::operation_aborted ||
                 Error.code() == boost::system::errc::make_error_condition(boost::system::errc::operation_canceled); }
        catch (...) { return false; }
    }
    [[nodiscard]] inline auto TraceHash() noexcept -> std::uint64_t
    {
        constexpr std::string_view Trace =
            "dns-coalescer-v2|qtype=A|waiters=5|flights=2000|rounds=5|owners=1,2,4|"
            "same-domain.perf.example.com|isolated=isolated.%zu.perf.example.com";
        std::uint64_t Hash = 1469598103934665603ULL;
        for (const auto Character : Trace) { Hash ^= static_cast<std::uint8_t>(Character); Hash *= 1099511628211ULL; }
        return Hash;
    }
    inline auto NowNs() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    inline auto PutU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }
    template <typename Awaitable>
    auto RunDnsCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, std::move(Coroutine),
            [&Failure, &IoContext](std::exception_ptr ErrorValue)
            { Failure = std::move(ErrorValue); IoContext.stop(); });
        IoContext.run();
        if (Failure) std::rethrow_exception(Failure);
    }
    template <typename Awaitable>
    [[nodiscard]] inline auto RunDnsCoroutineNatural(Net::io_context &IoContext, Awaitable Coroutine)
        -> bool
    {
        std::exception_ptr Failure;
        Net::co_spawn(IoContext, std::move(Coroutine),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        IoContext.run();
        return !Failure;
    }
    struct ResolverConfigRequest final
    {
        const PerfDnsServer &Server;
        bool CacheEnabled{false};
        std::size_t MaxCacheEntries{10000};
        std::chrono::seconds CacheTtl{120};
        std::chrono::seconds TtlMax{86400};
    };

    [[nodiscard]] inline auto MakeResolverConfig(const ResolverConfigRequest &Request) -> Config
    {
        Config Value;
        Prism::Network::Dns::Server Upstream;
        Upstream.Address = "127.0.0.1";
        Upstream.Port = Request.Server.Port();
        Upstream.TimeoutMs = 2000;
        Value.Servers.push_back(std::move(Upstream));
        Value.DisableIpv6 = true;
        Value.CacheEnabled = Request.CacheEnabled;
        Value.MaxCacheEntries = Request.MaxCacheEntries;
        Value.CacheTtl = Request.CacheTtl;
        Value.TtlMax = static_cast<std::uint32_t>(Request.TtlMax.count());
        return Value;
    }
}

