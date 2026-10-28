/**
 * @file CarrierIntegrityTest.cpp
 * @brief TLS 伪装 + 内层协议组合完整性实验 v2。
 * @details Reality 标签对应 SessionIdTool 实验，不是完整 Reality TLS carrier。
 * @details 使用真实 TCP loopback socket（有背压、真实调度）：
 *          1. Hash 一致性：客户端生成确定性数据（LCG），服务端
 *             边收边算 FNV1a64，传输后比对双端 Hash
 *          2. 内嵌协议：vless / trojan / socks5 三种内层
 *          3. 吞吐：单向 128MB 大块传输（TCP 真实背压）
 *          4. 并行：多用例并发执行（每用例独立线程 + io_context）
 *          5. 防卡死：每用例 30s watchdog，失败即终止
 */
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
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <thread>
#include <string_view>
#include <vector>
#include "WsFactory.hpp"
#include "CarrierBenchResult.hpp"
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>
#include <Test/Experiments/Prism/Reality/Session/IdBenchSupport.hpp>
#include <Prism/Protocols/Restls/Restls.hpp>
#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;
    namespace Anytls = Prism::Anytls;
    namespace Gun = Prism::Gun;
    namespace Restls = Prism::Restls;
    namespace Shadowtls = Prism::Shadowtls;
    namespace Socks5 = Prism::Socks5;
    namespace Trojan = Prism::Trojan;
    namespace Trusttunnel = Prism::Trusttunnel;
    namespace Vless = Prism::Vless;
    using Prism::Tests::Integration::Layering::CarrierBenchmarkWsFactory;
    using Prism::Tests::Integration::Layering::ToTransportResult;
    using Prism::Tests::Integration::Layering::TransportResult;
    namespace Transport = Prism::Transport;
    using Prism::Error;
    using Prism::SharedTransmission;

    constexpr std::size_t TotalBytes = 128ULL * 1024 * 1024;
    constexpr std::size_t BlockBytes = 64 * 1024;
    auto Fnv1a64(std::span<const std::uint8_t> Data, std::uint64_t Seed = 14695981039346656037ULL)
        -> std::uint64_t
    {
        std::uint64_t Hash = Seed;
        for (const auto Byte : Data)
        {
            Hash ^= Byte;
            Hash *= 1099511628211ULL;
        }
        return Hash;
    }
    auto LcgFill(std::span<std::uint8_t> Buffer, std::uint64_t &State) -> void
    {
        for (auto &Byte : Buffer)
        {
            State = State * 6364136223846793005ULL + 1442695040888963407ULL;
            Byte = static_cast<std::uint8_t>((State >> 33) & 0xFF);
        }
    }
    struct Result
    {
        bool Linked{false};           ///< 双端联通
        bool HashOk{false};           ///< Hash 一致
        std::uint64_t ClientHash{0}; ///< 客户端 Hash
        std::uint64_t ServerHash{0}; ///< 服务端 Hash
        std::size_t Bytes{0};         ///< 实际传输字节
        double Mbps{0};               ///< 吞吐
        bool Timeout{false};          ///< 超时
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
            throw std::system_error(Prism::Fault::ToNative(ConnectResult.error()));
        }
        auto Server = std::make_shared<Transport::Reliable>(Executor);
        boost::system::error_code AcceptError;
        co_await Acceptor.async_accept(
            Server->NativeSocket(), Net::redirect_error(Net::use_awaitable, AcceptError));
        if (AcceptError) throw boost::system::system_error(AcceptError);
        co_return std::make_pair(std::move(Client), std::move(Server));
    }
    template <typename Factory>
    struct IntegrityRunState final
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
        IntegrityRunState(Net::io_context &Context, Factory Value, std::shared_ptr<Result> ResultInput)
            : IoContext(Context), Watchdog(std::make_shared<Net::steady_timer>(Context.get_executor())),
              ServerFactory(Value), ClientFactory(std::move(Value)), ResultValue(std::move(ResultInput)),
              ServerExited(Context.get_executor(), 1)
        {
        }
    };
    template <typename Factory>
    auto CloseIntegrityState(const std::shared_ptr<IntegrityRunState<Factory>> &State) -> void
    {
        if (State->ClientRaw) (void)State->ClientRaw->Close();
        if (State->ServerRaw) (void)State->ServerRaw->Close();
    }
    template <typename Factory>
    auto FailIntegrity(const std::shared_ptr<IntegrityRunState<Factory>> &State) -> void
    {
        State->ResultValue->ProtocolFailed = true;
        CloseIntegrityState(State);
    }

    template <typename Factory>
    auto FinishIntegrityRun(const std::shared_ptr<IntegrityRunState<Factory>> &State) -> Net::awaitable<void>
    {
        if (State->ServerStarted && !State->ServerExitObserved)
        {
            co_await State->ServerExited.async_receive(Net::use_awaitable);
            State->ServerExitObserved = true;
        }
        if (State->ServerException) std::rethrow_exception(State->ServerException);
        State->ClientCompleted = true;
        State->Watchdog->cancel();
    }
    template <typename Factory>
    auto RunIntegrityWatchdog(const std::shared_ptr<IntegrityRunState<Factory>> &State) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        co_await State->Watchdog->async_wait(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode == boost::asio::error::operation_aborted) co_return;
        State->ResultValue->Timeout = true; State->ResultValue->ProtocolFailed = true;
        CloseIntegrityState(State);
        State->IoContext.stop();
    }
    template <typename Factory>
    auto RunIntegrityServer(const std::shared_ptr<IntegrityRunState<Factory>> &State) -> Net::awaitable<void>
    {
        auto ServerTransport = SharedTransmission(State->ServerRaw);
        auto ServerResult = co_await State->ServerFactory.ServerAccept(std::move(ServerTransport));
        if (!ServerResult)
        {
            State->ResultValue->ProtocolFailed = true;
            CloseIntegrityState(State);
            co_return;
        }
        auto ServerConnection = std::move(*ServerResult);
        auto InnerResult = co_await State->ServerFactory.ServerInner(std::move(ServerConnection));
        if (!InnerResult)
        {
            State->ResultValue->ProtocolFailed = true;
            CloseIntegrityState(State);
            co_return;
        }
        auto Inner = std::move(*InnerResult);
        State->ResultValue->Linked = true;
        std::array<std::uint8_t, BlockBytes> Buffer{};
        std::size_t Received = 0;
        std::uint64_t Hash = 14695981039346656037ULL;
        while (Received < TotalBytes)
        {
            const auto Read = co_await Inner->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()));
            if (Read.Bytes > Buffer.size()) { State->ResultValue->ProtocolFailed = true; break; }
            if (Read.Bytes > 0)
            {
                Hash = Fnv1a64(std::span<const std::uint8_t>(Buffer.data(), Read.Bytes), Hash);
                Received += Read.Bytes;
            }
            if (Read.Failure.Code == Prism::Fault::Code::Eof)
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
            State->ResultValue->ServerEof = Read.Bytes == 0 && Read.Failure.Code == Prism::Fault::Code::Eof;
            if (!State->ResultValue->ServerEof) State->ResultValue->ProtocolFailed = true;
        }
        State->ResultValue->ServerHash = Hash;
        State->ResultValue->Bytes = Received;
        if (State->ResultValue->ServerEof && !State->ResultValue->ProtocolFailed)
        {
            const auto ShutdownResult = co_await Inner->WriteShutdown();
            State->ResultValue->ServerFin = ShutdownResult.has_value();
            if (!ShutdownResult) State->ResultValue->ProtocolFailed = true;
        }
        const auto CloseResult = Inner->Close();
        if (CloseResult) {
            const auto DrainResult = co_await Inner->Activity()->Drain();
            State->ResultValue->ServerClosed = DrainResult.has_value();
            if (!DrainResult) State->ResultValue->ProtocolFailed = true;
        } else State->ResultValue->ProtocolFailed = true;
    }
    template <typename Factory>
    auto CompleteIntegrityServer(const std::shared_ptr<IntegrityRunState<Factory>> &State, std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            State->ServerException = std::move(Exception);
            State->ResultValue->ProtocolFailed = true;
            CloseIntegrityState(State);
        }
        State->ServerDone.store(true, std::memory_order_release);
        (void)State->ServerExited.try_send(boost::system::error_code{});
        if (State->ClientCompleted) State->Watchdog->cancel();
    }
    template <typename Factory>
    auto RunIntegrityClient(const std::shared_ptr<IntegrityRunState<Factory>> &State) -> Net::awaitable<void>
    {
        std::exception_ptr PendingException;
        try
        {
            auto [ClientRawValue, ServerRawValue] = co_await MakeTcpPair(State->IoContext.get_executor());
            State->ClientRaw = std::move(ClientRawValue);
            State->ServerRaw = std::move(ServerRawValue);
            Net::co_spawn(
                State->IoContext,
                RunIntegrityServer(State),
                [State](std::exception_ptr Exception)
                { CompleteIntegrityServer(State, std::move(Exception)); });
            State->ServerStarted = true;
            auto ClientTransport = SharedTransmission(State->ClientRaw);
            auto ClientResult = co_await State->ClientFactory.ClientConnect(std::move(ClientTransport));
            if (!ClientResult)
            {
                FailIntegrity(State);
                co_await FinishIntegrityRun(State);
                co_return;
            }
            auto ClientConnection = std::move(*ClientResult);
            auto ClientInnerResult = co_await State->ClientFactory.ClientInner(std::move(ClientConnection));
            if (!ClientInnerResult)
            {
                FailIntegrity(State);
                co_await FinishIntegrityRun(State);
                co_return;
            }
            auto ClientConnectionValue = std::move(*ClientInnerResult);
            const auto Start = std::chrono::steady_clock::now();
            std::array<std::uint8_t, BlockBytes> Buffer{};
            std::size_t Sent = 0;
            std::uint64_t Generator = 0x9E3779B97F4A7C15ULL;
            std::uint64_t Hash = 14695981039346656037ULL;
            std::size_t YieldCount = 0;
            while (Sent < TotalBytes)
            {
                const auto Chunk = std::min(Buffer.size(), TotalBytes - Sent);
                LcgFill(std::span<std::uint8_t>(Buffer).first(Chunk), Generator);
                std::size_t Offset = 0;
                while (Offset < Chunk)
                {
                    const auto WriteWindow = std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Buffer.data() + Offset),
                        Chunk - Offset);
                    const auto Write = co_await ClientConnectionValue->WriteSome(WriteWindow);
                    if (Write.Bytes > WriteWindow.size()) { State->ResultValue->ProtocolFailed = true; break; }
                    if (Write.Bytes > 0)
                    {
                        Hash = Fnv1a64(
                            std::span<const std::uint8_t>(Buffer.data() + Offset, Write.Bytes), Hash);
                        Sent += Write.Bytes;
                        Offset += Write.Bytes;
                    }
                    if (Write.Failure.Failed() || Write.Bytes == 0) { State->ResultValue->ProtocolFailed = true; break; }
                    if ((++YieldCount & 0x0F) == 0) co_await Net::post(State->IoContext.get_executor(), Net::use_awaitable);
                }
                if (State->ResultValue->ProtocolFailed) break;
            }
            const auto Finish = std::chrono::steady_clock::now();
            const auto Seconds = std::chrono::duration<double>(Finish - Start).count();
            State->ResultValue->ClientHash = Hash;
            State->ResultValue->Mbps = static_cast<double>(Sent) /
                (1024.0 * 1024.0) / (Seconds > 0 ? Seconds : 1e-9);
            if (Sent != TotalBytes) State->ResultValue->ProtocolFailed = true;
            if (!State->ResultValue->ProtocolFailed)
            {
                const auto ShutdownResult = co_await ClientConnectionValue->WriteShutdown();
                State->ResultValue->ClientFin = ShutdownResult.has_value();
                if (!ShutdownResult)
                {
                    State->ResultValue->ProtocolFailed = true;
                }
                else
                {
                    std::array<std::byte, 1> Drain{};
                    const auto Read = co_await ClientConnectionValue->ReadSome(Drain);
                    State->ResultValue->ClientEof = Read.Bytes == 0 && Read.Failure.Code == Prism::Fault::Code::Eof;
                    if (!State->ResultValue->ClientEof) State->ResultValue->ProtocolFailed = true;
                }
            }
            const auto CloseResult = ClientConnectionValue->Close();
            if (CloseResult) {
                const auto DrainResult = co_await ClientConnectionValue->Activity()->Drain();
                State->ResultValue->ClientClosed = DrainResult.has_value();
                if (!DrainResult) State->ResultValue->ProtocolFailed = true;
            } else State->ResultValue->ProtocolFailed = true;
            co_await FinishIntegrityRun(State);
            State->ResultValue->HashOk =
                !State->ResultValue->ProtocolFailed &&
                State->ResultValue->ClientHash == State->ResultValue->ServerHash &&
                State->ResultValue->Bytes == TotalBytes && Sent == TotalBytes;
            State->Watchdog->cancel();
        }
        catch (...)
        {
            PendingException = std::current_exception(); FailIntegrity(State);
        }
        if (PendingException)
        {
            try { co_await FinishIntegrityRun(State); } catch (...) {}
            std::rethrow_exception(PendingException);
        }
    }
    template <typename Factory>
    auto RunCase(Factory FactoryValue) -> Result
    {
        auto ResultValue = std::make_shared<Result>();
        Net::io_context IoContext;
        auto State = std::make_shared<IntegrityRunState<Factory>>(IoContext, std::move(FactoryValue), ResultValue);
        State->Watchdog->expires_after(std::chrono::seconds(60));
        Net::co_spawn(IoContext, RunIntegrityWatchdog(State), Net::detached);
        Net::co_spawn(IoContext, RunIntegrityClient(State), [State](std::exception_ptr Exception)
        { if (Exception) FailIntegrity(State); State->ClientCompleted = true;
          if (!State->ServerStarted || State->ServerExitObserved) State->Watchdog->cancel(); });
        IoContext.run();
        return *ResultValue;
    }
    auto ExpectIntegrityResult(const Result &Value, const char *Label) -> void
    {
        EXPECT_TRUE(Value.Linked) << Label << " 联通失败";
        EXPECT_FALSE(Value.ProtocolFailed) << Label << " 协议或异常失败";
        EXPECT_FALSE(Value.Timeout) << Label << " watchdog timeout";
        EXPECT_EQ(Value.Bytes, TotalBytes) << Label << " 字节数不完整";
        EXPECT_TRUE(Value.HashOk) << Label << " Hash 不一致";
        EXPECT_TRUE(Value.ServerEof) << Label << " server 未观察到 client FIN";
        EXPECT_TRUE(Value.ClientEof) << Label << " client 未观察到 server FIN";
        EXPECT_TRUE(Value.ClientFin) << Label << " client 未发送 FIN";
        EXPECT_TRUE(Value.ServerFin) << Label << " server 未发送 FIN";
        EXPECT_TRUE(Value.ClientClosed) << Label << " client 未最终 Close";
        EXPECT_TRUE(Value.ServerClosed) << Label << " server 未最终 Close";
    }
    template <typename InnerConnection>
    struct InnerVless
    {
        auto ServerInner(SharedTransmission Stream) -> Net::awaitable<TransportResult>
        {
            auto Result = co_await Vless::Accept(std::move(Stream), Vless::ServerConfig{Uuid});
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
        : Prism::Tests::Experiments::Reality::SessionIdToolBenchmarkFactory
    {
        SessionIdToolFactory()
            : Prism::Tests::Experiments::Reality::SessionIdToolBenchmarkFactory(
                  [](Prism::Error, std::string_view) {})
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
    struct ComboCase
    {
        const char *Name;
        std::function<Result()> Run;
    };
    auto RunParallel(std::vector<ComboCase> Cases) -> void
    {
        std::printf("\n%-16s %-6s %-6s %-12s %-10s %s\n", "组合", "联通", "Hash", "吞吐MB/s", "字节", "状态");
        std::printf("------------------------------------------------------------------------------------\n");
        constexpr std::size_t BatchSize = 8;
        std::vector<Result> Results(Cases.size());
        for (std::size_t Base = 0; Base < Cases.size(); Base += BatchSize)
        {
            const auto End = std::min(Cases.size(), Base + BatchSize);
            std::vector<std::thread> Threads;
            for (std::size_t Index = Base; Index < End; ++Index)
            {
                Threads.emplace_back([Index, &Cases, &Results]()
                { Results[Index] = Cases[Index].Run(); });
            }
            for (auto &Thread : Threads)
            {
                Thread.join();
            }
        }
        for (std::size_t Index = 0; Index < Cases.size(); ++Index)
        {
            const auto &Value = Results[Index];
            const char *Status = "FAIL";
            if (Value.Timeout)
            {
                Status = "TIMEOUT";
            }
            else if (Value.HashOk)
            {
                Status = "PASS";
            }
            const char *LinkedStatus = "FAIL";
            if (Value.Linked)
            {
                LinkedStatus = "OK";
            }
            const char *HashStatus = "FAIL";
            if (Value.HashOk)
            {
                HashStatus = "OK";
            }
            std::printf("%-16s %-6s %-6s %-12.1f %-10zu %s\n", Cases[Index].Name, LinkedStatus,
                        HashStatus, Value.Mbps, Value.Bytes, Status);
        }
    }
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
    struct IntegrityAggregate final
    {
        int Pass{0};
        int Fail{0};
        template <typename Factory, typename InnerProtocol>
        auto Run(const char *Label, Factory Stealth, InnerProtocol InnerValue) -> void
        {
            using FactoryType = decltype(Stealth);
            using InnerType = decltype(InnerValue);
            const auto Value = RunCase(Combo<FactoryType, InnerType>{Stealth, InnerValue});
            std::printf("%-18s linked=%d hash_ok=%d mbps=%.1f Bytes=%zu timeout=%d\n",
                        Label, Value.Linked, Value.HashOk, Value.Mbps, Value.Bytes, Value.Timeout);
            if (Value.Linked && Value.HashOk && !Value.ProtocolFailed && !Value.Timeout &&
                Value.Bytes == TotalBytes && Value.ServerEof && Value.ClientEof && Value.ClientFin &&
                Value.ServerFin && Value.ClientClosed && Value.ServerClosed)
            {
                ++Pass;
                return;
            }
            ++Fail;
            ExpectIntegrityResult(Value, Label);
        }
    };
    inline auto MakeVlessInner() -> InnerVless<void>
    {
        InnerVless<void> Value;
        Value.Uuid.fill(0x55);
        Value.Dst.Type = Vless::AddressType::Ipv4;
        Value.Dst.Host = "93.184.216.34";
        Value.Dst.Port = 443;
        return Value;
    }
    TEST(StealthNested2, SingleDirectVless)
    {
        DirectFactory Direct;
        auto InnerValue = MakeVlessInner();
        auto ResultValue = RunCase(Combo<DirectFactory, InnerVless<void>>{Direct, InnerValue});
        std::printf("direct+vless: linked=%d hash_ok=%d mbps=%.1f Bytes=%zu timeout=%d\n",
                    ResultValue.Linked, ResultValue.HashOk, ResultValue.Mbps,
                    ResultValue.Bytes, ResultValue.Timeout);
        ExpectIntegrityResult(ResultValue, "direct+vless");
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
    TEST(StealthNested2, DISABLED_##TestName)                                                                \
    {                                                                                                        \
        auto Stealth = FactoryVar;                                                                           \
        auto InnerValue = InnerExpr;                                                                         \
        using FactoryType = decltype(Stealth);                                                               \
        using InnerType = decltype(InnerValue);                                                              \
        auto ResultValue = RunCase(Combo<FactoryType, InnerType>{Stealth, InnerValue});                    \
        std::printf("%-18s linked=%d hash_ok=%d mbps=%.1f Bytes=%zu timeout=%d\n", Label, ResultValue.Linked, \
                    ResultValue.HashOk, ResultValue.Mbps, ResultValue.Bytes, ResultValue.Timeout);         \
        ExpectIntegrityResult(ResultValue, Label);                                                           \
    }
    TEST(StealthNested2, DISABLED_AllHashInProcess)
    {
        IntegrityAggregate Summary;
        ShadowtlsFactory Shadowtls;
        RestlsFactory Restls;
        AnytlsFactory Anytls;
        TrusttunnelFactory Trusttunnel;
        CarrierBenchmarkWsFactory Ws;
        GunFactory Gun;
        SessionIdToolFactory SessionIdTool;
        DirectFactory Direct;
        Summary.Run("shadowtls+vless", Shadowtls, MakeVlessInner());
        Summary.Run("restls+vless", Restls, MakeVlessInner());
        Summary.Run("anytls+vless", Anytls, MakeVlessInner());
        Summary.Run("trusttunnel+vless", Trusttunnel, MakeVlessInner());
        Summary.Run("ws+vless", Ws, MakeVlessInner());
        Summary.Run("gun+vless", Gun, MakeVlessInner());
        Summary.Run("session-id-tool+vless", SessionIdTool, MakeVlessInner());
        Summary.Run("shadowtls+trojan", Shadowtls, MakeTrojanInner());
        Summary.Run("restls+trojan", Restls, MakeTrojanInner());
        Summary.Run("anytls+trojan", Anytls, MakeTrojanInner());
        Summary.Run("trusttunnel+trojan", Trusttunnel, MakeTrojanInner());
        Summary.Run("ws+trojan", Ws, MakeTrojanInner());
        Summary.Run("gun+trojan", Gun, MakeTrojanInner());
        Summary.Run("session-id-tool+trojan", SessionIdTool, MakeTrojanInner());
        Summary.Run("shadowtls+socks5", Shadowtls, MakeSocks5Inner());
        Summary.Run("restls+socks5", Restls, MakeSocks5Inner());
        Summary.Run("anytls+socks5", Anytls, MakeSocks5Inner());
        Summary.Run("trusttunnel+socks5", Trusttunnel, MakeSocks5Inner());
        Summary.Run("ws+socks5", Ws, MakeSocks5Inner());
        Summary.Run("gun+socks5", Gun, MakeSocks5Inner());
        Summary.Run("session-id-tool+socks5", SessionIdTool, MakeSocks5Inner());
        Summary.Run("direct+vless", Direct, MakeVlessInner());
        Summary.Run("direct+trojan", Direct, MakeTrojanInner());
        Summary.Run("direct+socks5", Direct, MakeSocks5Inner());
        std::printf("Hash 验证: %d 组合通过, %d 失败\n", Summary.Pass, Summary.Fail);
        EXPECT_EQ(Summary.Fail, 0) << "存在失败的组合";
    }
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
    DEFINE_COMBO_TEST(DirectVless, DirectFactory{}, MakeVlessInner(), "direct+vless")
    DEFINE_COMBO_TEST(DirectTrojan, DirectFactory{}, MakeTrojanInner(), "direct+trojan")
    DEFINE_COMBO_TEST(DirectSocks5, DirectFactory{}, MakeSocks5Inner(), "direct+socks5")
} // namespace
