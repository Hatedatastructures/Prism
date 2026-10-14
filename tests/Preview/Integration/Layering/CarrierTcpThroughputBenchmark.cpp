/**
 * @file CarrierTcpThroughputBenchmark.cpp
 * @brief TLS 伪装 + 内层协议纯传输吞吐实验（v3）。
 * @details Reality 标签对应 SessionIdTool 实验，不是完整 Reality TLS carrier。
 * @details 上一版 Hash 验证已证明数据一致性。本版专注纯传输速率：
 *          预生成数据块（一次生成，重复发送），Server 只读丢弃。
 *          测量真实 TCP + 伪装层 + 内层协议的裸吞吐。
 *          对照：纯 TCP 基线 / 内层直连 / 伪装+内层。
 */

#include "CarrierBenchmarkWsFactory.hpp"
#include "CarrierBenchmarkTransportResult.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <atomic>
#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <expected>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <Preview/Transport/Reliable.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Protocols/Anytls/Anytls.hpp>
#include <Preview/Protocols/Gun/Gun.hpp>
#include "../../../Experiments/Reality/SessionIdToolBenchmarkSupport.hpp"
#include <Preview/Protocols/Restls/Restls.hpp>
#include <Preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <Preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;
    namespace Anytls = Preview::Anytls;
    namespace Gun = Preview::Gun;
    namespace Restls = Preview::Restls;
    namespace Shadowtls = Preview::Shadowtls;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Trusttunnel = Preview::Trusttunnel;
    namespace Vless = Preview::Vless;
    using Preview::Tests::Integration::Layering::CarrierBenchmarkWsFactory;
    using Preview::Tests::Integration::Layering::ToTransportResult;
    using Preview::Tests::Integration::Layering::TransportResult;
    namespace Transport = Preview::Transport;
    using Preview::Error;
    using Preview::SharedTransmission;

    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    constexpr std::size_t BlockBytes = 64 * 1024;

    /// 结果
    struct Result
    {
        bool Linked{false};   ///< 双端联通
        std::size_t Bytes{0}; ///< 实际传输字节
        double Mbps{0};       ///< 吞吐
        bool Timeout{false};  ///< 超时
        bool ProtocolFailed{false};
        bool ClientFin{false};
        bool ServerEof{false};
        bool ClientEof{false};
        bool ServerFin{false};
        bool ClientClosed{false};
        bool ServerClosed{false};
    };

    auto MakeTcpPair(Net::any_io_executor Executor)
        -> Net::awaitable<std::pair<std::shared_ptr<Transport::Reliable>, std::shared_ptr<Transport::Reliable>>>
    {
        Net::ip::tcp::acceptor Acceptor(
            Executor, Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Client = std::make_shared<Transport::Reliable>(Executor);
        const auto ConnectResult = co_await Client->Connect(
            Acceptor.local_endpoint(), std::chrono::milliseconds{5000});
        if (!ConnectResult)
        {
            throw std::system_error(Preview::Fault::ToNative(ConnectResult.error()));
        }
        auto Server = std::make_shared<Transport::Reliable>(Executor);
        boost::system::error_code AcceptError;
        co_await Acceptor.async_accept(
            Server->NativeSocket(), Net::redirect_error(Net::use_awaitable, AcceptError));
        if (AcceptError) throw boost::system::system_error(AcceptError);
        co_return std::make_pair(std::move(Client), std::move(Server));
    }

    template <typename Factory>
    struct ThroughputRunState final
    {
        Net::io_context &IoContext;
        std::shared_ptr<Net::steady_timer> Watchdog;
        Factory ServerFactory;
        Factory ClientFactory;
        std::shared_ptr<Result> ResultValue;
        std::shared_ptr<Transport::Reliable> ClientRaw;
        std::shared_ptr<Transport::Reliable> ServerRaw;
        std::atomic<bool> ServerDone{false};
        std::exception_ptr ServerException;
        CompletionChannel ServerExited;
        bool ServerStarted{false};
        bool ServerExitObserved{false};
        bool ClientCompleted{false};

        ThroughputRunState(Net::io_context &Context, Factory Value,
                           std::shared_ptr<Result> ResultInput)
            : IoContext(Context),
              Watchdog(std::make_shared<Net::steady_timer>(Context.get_executor())),
              ServerFactory(Value), ClientFactory(std::move(Value)),
              ResultValue(std::move(ResultInput)),
              ServerExited(Context.get_executor(), 1)
        {
        }
    };

    template <typename Factory>
    auto CloseThroughputState(const std::shared_ptr<ThroughputRunState<Factory>> &State) -> void
    {
        if (State->ClientRaw) (void)State->ClientRaw->Close();
        if (State->ServerRaw) (void)State->ServerRaw->Close();
    }

    template <typename Factory>
    auto FailThroughput(const std::shared_ptr<ThroughputRunState<Factory>> &State) -> void
    {
        State->ResultValue->ProtocolFailed = true;
        CloseThroughputState(State);
    }

    template <typename Factory>
    auto FinishThroughputRun(const std::shared_ptr<ThroughputRunState<Factory>> &State)
        -> Net::awaitable<void>
    {
        if (State->ServerStarted && !State->ServerExitObserved)
        {
            co_await State->ServerExited.async_receive(Net::use_awaitable);
            State->ServerExitObserved = true;
        }
        if (State->ServerException)
        {
            std::rethrow_exception(State->ServerException);
        }
        State->ClientCompleted = true;
        State->Watchdog->cancel();
    }

    template <typename Factory>
    auto RunThroughputWatchdog(const std::shared_ptr<ThroughputRunState<Factory>> &State)
        -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await State->Watchdog->async_wait(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode == boost::asio::error::operation_aborted)
        {
            co_return;
        }
        State->ResultValue->Timeout = true;
        State->ResultValue->ProtocolFailed = true;
        CloseThroughputState(State);
        State->IoContext.stop();
    }

    template <typename Factory>
    auto RunThroughputServer(const std::shared_ptr<ThroughputRunState<Factory>> &State)
        -> Net::awaitable<void>
    {
        auto ServerTransport = SharedTransmission(State->ServerRaw);
        auto ServerResult = co_await State->ServerFactory.ServerAccept(
            std::move(ServerTransport));
        if (!ServerResult)
        {
            State->ResultValue->ProtocolFailed = true;
            CloseThroughputState(State);
            co_return;
        }
        auto ServerConnection = std::move(*ServerResult);
        auto InnerResult = co_await State->ServerFactory.ServerInner(
            std::move(ServerConnection));
        if (!InnerResult)
        {
            State->ResultValue->ProtocolFailed = true;
            CloseThroughputState(State);
            co_return;
        }
        auto Inner = std::move(*InnerResult);
        State->ResultValue->Linked = true;
        std::vector<std::uint8_t> Buffer(BlockBytes);
        std::size_t Received = 0;
        while (Received < TotalBytes)
        {
            const auto Read = co_await Inner->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()));
            if (Read.Bytes > Buffer.size()) { State->ResultValue->ProtocolFailed = true; break; }
            Received += Read.Bytes;
            if (Received > TotalBytes)
            {
                State->ResultValue->ProtocolFailed = true;
                break;
            }
            if (Read.Failure.Code == Preview::Fault::Code::Eof)
            {
                State->ResultValue->ServerEof = Received == TotalBytes;
                if (!State->ResultValue->ServerEof) State->ResultValue->ProtocolFailed = true;
                break;
            }
            if (Read.Failure.Failed() || Read.Bytes == 0) { State->ResultValue->ProtocolFailed = true; break; }
        }
        if (Received == TotalBytes && !State->ResultValue->ProtocolFailed &&
            !State->ResultValue->ServerEof)
        {
            std::array<std::uint8_t, 1> Drain{};
            const auto Read = co_await Inner->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Drain.data()), Drain.size()));
            State->ResultValue->ServerEof = Read.Bytes == 0 && Read.Failure.Code == Preview::Fault::Code::Eof;
            if (!State->ResultValue->ServerEof) State->ResultValue->ProtocolFailed = true;
        }
        State->ResultValue->Bytes = Received;
        if (State->ResultValue->ServerEof && !State->ResultValue->ProtocolFailed)
        {
            const auto ShutdownResult = co_await Inner->WriteShutdown();
            State->ResultValue->ServerFin = ShutdownResult.has_value();
            if (!ShutdownResult) State->ResultValue->ProtocolFailed = true;
        }
        const auto CloseResult = Inner->Close();
        if (CloseResult)
        {
            const auto DrainResult = co_await Inner->Activity()->Drain();
            State->ResultValue->ServerClosed = DrainResult.has_value();
            if (!DrainResult) State->ResultValue->ProtocolFailed = true;
        }
        else State->ResultValue->ProtocolFailed = true;
    }

    template <typename Factory>
    auto CompleteThroughputServer(
        const std::shared_ptr<ThroughputRunState<Factory>> &State,
        std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            State->ServerException = std::move(Exception);
            State->ResultValue->ProtocolFailed = true;
            CloseThroughputState(State);
        }
        State->ServerDone.store(true, std::memory_order_release);
        (void)State->ServerExited.try_send(boost::system::error_code{});
        if (State->ClientCompleted) State->Watchdog->cancel();
    }

    template <typename Factory>
    auto RunThroughputClient(const std::shared_ptr<ThroughputRunState<Factory>> &State)
        -> Net::awaitable<void>
    {
        std::exception_ptr PendingException;
        try
        {
            auto [ClientRawValue, ServerRawValue] = co_await MakeTcpPair(
                State->IoContext.get_executor());
            State->ClientRaw = std::move(ClientRawValue);
            State->ServerRaw = std::move(ServerRawValue);
            Net::co_spawn(
                State->IoContext,
                RunThroughputServer(State),
                [State](std::exception_ptr Exception)
                { CompleteThroughputServer(State, std::move(Exception)); });
            State->ServerStarted = true;
            auto ClientTransport = SharedTransmission(State->ClientRaw);
            auto ClientResult = co_await State->ClientFactory.ClientConnect(
                std::move(ClientTransport));
            if (!ClientResult)
            {
                FailThroughput(State);
                co_await FinishThroughputRun(State);
                co_return;
            }
            auto ClientConnection = std::move(*ClientResult);
            auto ClientInnerResult = co_await State->ClientFactory.ClientInner(
                std::move(ClientConnection));
            if (!ClientInnerResult)
            {
                FailThroughput(State);
                co_await FinishThroughputRun(State);
                co_return;
            }
            auto ClientConnectionValue = std::move(*ClientInnerResult);
            std::vector<std::uint8_t> Payload(BlockBytes, 0x5A);
            const auto PayloadBytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
            const auto Start = std::chrono::steady_clock::now();
            std::size_t Sent = 0;
            std::size_t YieldCount = 0;
            while (Sent < TotalBytes)
            {
                const auto Chunk = std::min(PayloadBytes.size(), TotalBytes - Sent);
                std::size_t Offset = 0;
                while (Offset < Chunk)
                {
                    const auto WriteWindow = PayloadBytes.first(Chunk).subspan(Offset);
                    const auto Write = co_await ClientConnectionValue->WriteSome(WriteWindow);
                    if (Write.Bytes > WriteWindow.size()) { State->ResultValue->ProtocolFailed = true; break; }
                    Sent += Write.Bytes;
                    Offset += Write.Bytes;
                    if (Write.Failure.Failed() || Write.Bytes == 0) { State->ResultValue->ProtocolFailed = true; break; }
                    if ((++YieldCount & 0x0F) == 0) co_await Net::post(State->IoContext.get_executor(), Net::use_awaitable);
                }
                if (State->ResultValue->ProtocolFailed) break;
            }
            const auto Finish = std::chrono::steady_clock::now();
            const auto Seconds = std::chrono::duration<double>(Finish - Start).count();
            State->ResultValue->Mbps = static_cast<double>(Sent) /
                (1024.0 * 1024.0) / (Seconds > 0 ? Seconds : 1e-9);
            if (Sent == TotalBytes && !State->ResultValue->ProtocolFailed)
            {
                const auto ShutdownResult = co_await ClientConnectionValue->WriteShutdown();
                if (ShutdownResult)
                {
                    State->ResultValue->ClientFin = true;
                    std::array<std::byte, 1> Drain{};
                    const auto Read = co_await ClientConnectionValue->ReadSome(Drain);
                    State->ResultValue->ClientEof = Read.Bytes == 0 && Read.Failure.Code == Preview::Fault::Code::Eof;
                    if (!State->ResultValue->ClientEof) State->ResultValue->ProtocolFailed = true;
                }
                else
                {
                    State->ResultValue->ProtocolFailed = true;
                }
            }
            else
            {
                State->ResultValue->ProtocolFailed = true;
            }
            const auto CloseResult = ClientConnectionValue->Close();
            if (CloseResult)
            {
                const auto DrainResult = co_await ClientConnectionValue->Activity()->Drain();
                State->ResultValue->ClientClosed = DrainResult.has_value();
                if (!DrainResult) State->ResultValue->ProtocolFailed = true;
            }
            else State->ResultValue->ProtocolFailed = true;
            co_await FinishThroughputRun(State);
        }
        catch (...)
        {
            PendingException = std::current_exception();
            FailThroughput(State);
        }
        if (PendingException)
        {
            try
            {
                co_await FinishThroughputRun(State);
            }
            catch (...)
            {
            }
            std::rethrow_exception(PendingException);
        }
    }

    template <typename Factory>
    auto CompleteThroughputClient(
        const std::shared_ptr<ThroughputRunState<Factory>> &State,
        std::exception_ptr Exception) -> void
    {
        if (Exception) FailThroughput(State);
        State->ClientCompleted = true;
        if (!State->ServerStarted || State->ServerExitObserved) State->Watchdog->cancel();
    }

    template <typename Factory>
    auto RunCase(Factory FactoryValue) -> Result
    {
        auto ResultValue = std::make_shared<Result>();
        Net::io_context IoContext;
        auto State = std::make_shared<ThroughputRunState<Factory>>(
            IoContext, std::move(FactoryValue), ResultValue);
        State->Watchdog->expires_after(std::chrono::seconds(60));
        Net::co_spawn(IoContext, RunThroughputWatchdog(State), Net::detached);
        Net::co_spawn(
            IoContext,
            RunThroughputClient(State),
            [State](std::exception_ptr Exception)
            { CompleteThroughputClient(State, std::move(Exception)); });
        IoContext.run();
        return *ResultValue;
    }

    auto ExpectThroughputResult(const Result &Value, const char *Label) -> void
    {
        EXPECT_TRUE(Value.Linked) << Label << " 联通失败";
        EXPECT_FALSE(Value.ProtocolFailed) << Label << " 协议或异常失败";
        EXPECT_FALSE(Value.Timeout) << Label << " watchdog timeout";
        EXPECT_EQ(Value.Bytes, TotalBytes) << Label << " 字节数不完整";
        EXPECT_TRUE(Value.ServerEof) << Label << " server 未观察到 client FIN";
        EXPECT_TRUE(Value.ClientEof) << Label << " client 未观察到 server FIN";
        EXPECT_TRUE(Value.ClientFin) << Label << " client 未发送 FIN";
        EXPECT_TRUE(Value.ServerFin) << Label << " server 未发送 FIN";
        EXPECT_TRUE(Value.ClientClosed) << Label << " client 未最终 Close";
        EXPECT_TRUE(Value.ServerClosed) << Label << " server 未最终 Close";
    }

    // ============ 内层协议适配 ============

    struct InnerVless
    {
        auto ServerInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            auto Result = co_await Vless::Accept(
                std::move(Stream), Vless::ServerConfig{Uuid});
            co_return ToTransportResult(std::move(Result));
        }
        auto ClientInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            auto Result = co_await Vless::Connect(Vless::ConnectParameters{
                std::move(Stream), Vless::ClientConfig{Uuid}, Dst});
            co_return ToTransportResult(std::move(Result));
        }
        std::array<std::uint8_t, 16> Uuid{};
        Vless::Address Dst{};
    };

    struct InnerTrojan
    {
        auto ServerInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            auto Result = co_await Trojan::Accept(
                std::move(Stream), Trojan::ServerConfig{"pw"});
            co_return ToTransportResult(std::move(Result));
        }
        auto ClientInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            Trojan::Address Destination{};
            Destination.Type = Trojan::AddressType::Ipv4;
            Destination.Host = "93.184.216.34";
            Destination.Port = 443;
            auto Result = co_await Trojan::Connect(Trojan::ConnectParameters{
                std::move(Stream), Trojan::ClientConfig{"pw"}, Destination});
            co_return ToTransportResult(std::move(Result));
        }
    };

    struct InnerSocks5
    {
        auto ServerInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Request, Connection] = co_await Socks5::Accept(
                std::move(Stream), Socks5::ServerConfig{});
            (void)Request;
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
        auto ClientInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            Socks5::Address Destination{};
            Destination.Type = Socks5::AddressType::Ipv4;
            Destination.Host = "93.184.216.34";
            Destination.Port = 443;
            auto [ErrorCode, Connection] = co_await Socks5::Connect(
                std::move(Stream), Socks5::ClientConfig{}, Destination);
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
    };

    // ============ 伪装层工厂 ============

    struct DirectFactory
    {
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            co_return ToTransportResult(Error::None, std::move(Upstream));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            co_return ToTransportResult(Error::None, std::move(Upstream));
        }
    };

    struct ShadowtlsFactory
    {
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            auto [ErrorCode, Connection] = co_await Shadowtls::Accept(
                std::move(Upstream), Shadowtls::ServerConfig{"st"});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            std::array<std::uint8_t, 32> ServerRandom{};
            std::array<std::uint8_t, 32> ClientRandom{};
            for (std::size_t Index = 0; Index < 32; ++Index)
            {
                ServerRandom[Index] = static_cast<std::uint8_t>(Index * 3 + 1);
                ClientRandom[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
            }
            auto [ErrorCode, Connection] = co_await Shadowtls::Connect(
                {std::move(Upstream), Shadowtls::ClientConfig{"st"}, ServerRandom, ClientRandom});
            co_return ToTransportResult(ErrorCode, std::move(Connection));
        }
    };

    struct AnytlsFactory
    {
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            auto Connection = co_await Anytls::Accept(
                std::move(Upstream), Anytls::ServerConfig{"at"});
            co_return ToTransportResult(std::move(Connection));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            auto Connection = co_await Anytls::Connect(
                std::move(Upstream), Anytls::ClientConfig{"at"});
            co_return ToTransportResult(std::move(Connection));
        }
    };

    struct TrusttunnelFactory
    {
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            co_return ToTransportResult(co_await Trusttunnel::Accept(
                std::move(Upstream), Trusttunnel::ServerConfig{"u", "p"}));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            co_return ToTransportResult(co_await Trusttunnel::Connect(
                {std::move(Upstream), Trusttunnel::ClientConfig{"u", "p"}, "example.com", 443}));
        }
    };


    struct GunFactory
    {
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            co_return ToTransportResult(co_await Gun::Accept(std::move(Upstream), Gun::Config{}));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            co_return ToTransportResult(co_await Gun::Connect(
                Gun::ConnectRequest{std::move(Upstream), "example.com", {}}));
        }
    };

    struct SessionIdToolFactory
        : Preview::Tests::Experiments::Reality::SessionIdToolBenchmarkFactory
    {
        SessionIdToolFactory()
            : Preview::Tests::Experiments::Reality::SessionIdToolBenchmarkFactory(
              [](Preview::Error ErrorCode, std::string_view Message)
              {
                  if (ErrorCode != Preview::Error::None)
                  {
                      throw std::runtime_error(std::string(Message));
                  }
              })
        {
        }
    };

    struct RestlsFactory
    {
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            std::array<std::uint8_t, 32> ServerRandom{};
            for (std::size_t Index = 0; Index < 32; ++Index)
            {
                ServerRandom[Index] = static_cast<std::uint8_t>(Index * 3 + 1);
            }
            auto Connection = co_await Restls::Accept(
                std::move(Upstream), Restls::ServerConfig{"rs"}, ServerRandom);
            co_return ToTransportResult(std::move(Connection));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            std::array<std::uint8_t, 32> ServerRandom{};
            for (std::size_t Index = 0; Index < 32; ++Index)
            {
                ServerRandom[Index] = static_cast<std::uint8_t>(Index * 3 + 1);
            }
            auto Connection = co_await Restls::Connect(
                std::move(Upstream), Restls::ClientConfig{"rs"}, ServerRandom);
            co_return ToTransportResult(std::move(Connection));
        }
    };

    // ============ 组合体与测试 ============

    template <typename Factory, typename InnerProtocol>
    struct Combo
    {
        Factory Stealth;
        InnerProtocol Inner;
        auto ServerAccept(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            return Stealth.ServerAccept(std::move(Upstream));
        }
        auto ClientConnect(SharedTransmission Upstream) -> Net::awaitable<TransportResult>
        {
            return Stealth.ClientConnect(std::move(Upstream));
        }
        auto ServerInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            return Inner.ServerInner(std::move(Stream));
        }
        auto ClientInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            return Inner.ClientInner(std::move(Stream));
        }
    };

    inline auto MakeVlessInner() -> InnerVless
    {
        InnerVless Value;
        Value.Uuid.fill(0x55);
        Value.Dst.Type = Vless::AddressType::Ipv4;
        Value.Dst.Host = "93.184.216.34";
        Value.Dst.Port = 443;
        return Value;
    }
    inline auto MakeTrojanInner() -> InnerTrojan
    {
        return {};
    }
    inline auto MakeSocks5Inner() -> InnerSocks5
    {
        return {};
    }

#define DEFINE_COMBO_TEST(TestName, FactoryVar, InnerExpr, Label)                                            \
    TEST(StealthNested3, TestName)                                                                           \
    {                                                                                                        \
        auto Stealth = FactoryVar;                                                                           \
        auto InnerValue = InnerExpr;                                                                         \
        using FactoryType = decltype(Stealth);                                                               \
        using InnerType = decltype(InnerValue);                                                              \
        auto ResultValue = RunCase(Combo<FactoryType, InnerType>{Stealth, InnerValue});                    \
        std::printf("%-18s linked=%d mbps=%.1f Bytes=%zu timeout=%d\n", Label, ResultValue.Linked,          \
                    ResultValue.Mbps, ResultValue.Bytes, ResultValue.Timeout);                             \
        ExpectThroughputResult(ResultValue, Label);                                                          \
    }

    DEFINE_COMBO_TEST(DirectVless, DirectFactory{}, MakeVlessInner(), "direct+vless")
    DEFINE_COMBO_TEST(DirectTrojan, DirectFactory{}, MakeTrojanInner(), "direct+trojan")
    DEFINE_COMBO_TEST(DirectSocks5, DirectFactory{}, MakeSocks5Inner(), "direct+socks5")
    DEFINE_COMBO_TEST(ShadowTlsVless, ShadowtlsFactory{}, MakeVlessInner(), "shadowtls+vless")
    DEFINE_COMBO_TEST(RestlsVless, RestlsFactory{}, MakeVlessInner(), "restls+vless")
    DEFINE_COMBO_TEST(AnyTlsVless, AnytlsFactory{}, MakeVlessInner(), "anytls+vless")
    DEFINE_COMBO_TEST(TrustTunnelVless, TrusttunnelFactory{}, MakeVlessInner(), "trusttunnel+vless")
    DEFINE_COMBO_TEST(WsVless, CarrierBenchmarkWsFactory{}, MakeVlessInner(), "ws+vless")
    DEFINE_COMBO_TEST(GunVless, GunFactory{}, MakeVlessInner(), "gun+vless")
    DEFINE_COMBO_TEST(SessionIdToolVless, SessionIdToolFactory{}, MakeVlessInner(), "session-id-tool+vless")
    DEFINE_COMBO_TEST(ShadowTlsTrojan, ShadowtlsFactory{}, MakeTrojanInner(), "shadowtls+trojan")
    DEFINE_COMBO_TEST(RestlsTrojan, RestlsFactory{}, MakeTrojanInner(), "restls+trojan")
    DEFINE_COMBO_TEST(AnyTlsTrojan, AnytlsFactory{}, MakeTrojanInner(), "anytls+trojan")
    DEFINE_COMBO_TEST(TrustTunnelTrojan, TrusttunnelFactory{}, MakeTrojanInner(), "trusttunnel+trojan")
    DEFINE_COMBO_TEST(WsTrojan, CarrierBenchmarkWsFactory{}, MakeTrojanInner(), "ws+trojan")
    DEFINE_COMBO_TEST(GunTrojan, GunFactory{}, MakeTrojanInner(), "gun+trojan")
    DEFINE_COMBO_TEST(SessionIdToolTrojan, SessionIdToolFactory{}, MakeTrojanInner(), "session-id-tool+trojan")
    DEFINE_COMBO_TEST(ShadowTlsSocks5, ShadowtlsFactory{}, MakeSocks5Inner(), "shadowtls+socks5")
    DEFINE_COMBO_TEST(RestlsSocks5, RestlsFactory{}, MakeSocks5Inner(), "restls+socks5")
    DEFINE_COMBO_TEST(AnyTlsSocks5, AnytlsFactory{}, MakeSocks5Inner(), "anytls+socks5")
    DEFINE_COMBO_TEST(TrustTunnelSocks5, TrusttunnelFactory{}, MakeSocks5Inner(), "trusttunnel+socks5")
    DEFINE_COMBO_TEST(WsSocks5, CarrierBenchmarkWsFactory{}, MakeSocks5Inner(), "ws+socks5")
    DEFINE_COMBO_TEST(GunSocks5, GunFactory{}, MakeSocks5Inner(), "gun+socks5")
    DEFINE_COMBO_TEST(SessionIdToolSocks5, SessionIdToolFactory{}, MakeSocks5Inner(), "session-id-tool+socks5")

} // namespace
