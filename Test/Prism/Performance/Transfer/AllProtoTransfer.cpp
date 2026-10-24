/**
 * @file AllProtoTransfer.cpp
 * @brief 全部 TCP 协议传输基准（Release，本机真实 TCP）
 * @details 每个协议 Client Conn ↔ Server Conn 256MB 传输：
 * socks5（透传）/ trojan（透传）/ vless（透传）/ vmess（加密 chunk）
 * / ss2022（加密 chunk）
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#include <Prism/Transport/Reliable.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>

using Clock = std::chrono::steady_clock;
namespace Net = boost::asio;

namespace
{
    [[nodiscard]] auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }

    auto Report(const char *Name, std::size_t Bytes, std::int64_t MedianNanoseconds) -> void
    {
        const double Megabytes = static_cast<double>(Bytes) / (1024.0 * 1024.0);
        const double Seconds = static_cast<double>(MedianNanoseconds) / 1e9;
        std::printf("%-40s %7.1f MB  med=%7.2f ms  => %9.1f MB/s  %5.1f Gbps\n",
                    Name,
                    Megabytes,
                    Seconds * 1000,
                    Megabytes / Seconds,
                    Megabytes / Seconds * 8 / 1000);
    }

    struct BenchOptions final
    {
        std::size_t Total;
        std::size_t Block;
    };

    struct BenchResult final
    {
        std::int64_t ElapsedNanoseconds{0};
        bool Completed{false};
        std::size_t ReadProgress{0};
        std::size_t WriteProgress{0};
        Prism::IoResult ReadResult{};
        Prism::IoResult WriteResult{};
    };

    auto ReportIoFailure(const char *Direction, const Prism::IoResult &Result,
                         const std::size_t Progress) -> void
    {
        if (!Result.Failure.Failed()) return;
        std::fprintf(stderr, "FAIL %s: bytes=%zu progress=%zu code=%d native=%s:%d\n",
                     Direction, Result.Bytes, Progress, static_cast<int>(Result.Failure.Code),
                     Result.Failure.Native.category().name(), Result.Failure.Native.value());
    }

    /// 性能门禁：全部样本数据面完成 + 吞吐下限（防断链静默/死循环挂死/完全退化）
    [[nodiscard]] auto Gate(
        const char *Name,
        std::size_t Bytes,
        const std::array<BenchResult, 3> &Samples) -> bool
    {
        constexpr double MinMbps = 50.0; // 宽松下限（本地 TCP 基线数百 MB/s，防 10x+ 劣化）
        auto Sorted = Samples;
        std::sort(Sorted.begin(), Sorted.end(), [](const BenchResult &Left, const BenchResult &Right)
        {
            return Left.ElapsedNanoseconds < Right.ElapsedNanoseconds;
        });
        Report(Name, Bytes, Sorted[1].ElapsedNanoseconds);
        // 任一运行断链/未完成即 FAIL（部分失败不得被中位数掩盖）
        if (std::any_of(Sorted.begin(), Sorted.end(), [](const BenchResult &Value)
            { return !Value.Completed || Value.ElapsedNanoseconds <= 0; }))
        {
            std::printf("FAIL %s: 存在数据面未完成运行（断链/死循环）\n", Name);
            for (const auto &Sample : Samples)
            {
                ReportIoFailure("read", Sample.ReadResult, Sample.ReadProgress);
                ReportIoFailure("write", Sample.WriteResult, Sample.WriteProgress);
            }
            return false;
        }
        const double MegabitsPerSecond =
            static_cast<double>(Bytes) / (1024.0 * 1024.0) /
            (static_cast<double>(Sorted[1].ElapsedNanoseconds) / 1e9);
        if (MegabitsPerSecond < MinMbps)
        {
            std::printf("FAIL %s: 吞吐 %.1f MB/s < 下限 %.1f MB/s\n",
                        Name,
                        MegabitsPerSecond,
                        MinMbps);
            return false;
        }
        return true;
    }

    template <typename Connection>
    [[nodiscard]] auto ToTransmission(const Prism::Error ErrorCode, Connection ConnectionValue)
        -> std::expected<Prism::SharedTransmission, Prism::Fault::Failure>
    {
        if (ErrorCode != Prism::Error::None)
        {
            return std::unexpected(Prism::Protocol::Common::FailureFromProtocolError(ErrorCode));
        }
        if (!ConnectionValue)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        return Prism::SharedTransmission{std::move(ConnectionValue)};
    }

    template <typename Connection>
    [[nodiscard]] auto ToTransmission(
        std::expected<Connection, Prism::Fault::Failure> Result)
        -> std::expected<Prism::SharedTransmission, Prism::Fault::Failure>
    {
        if (!Result)
        {
            return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        return Prism::SharedTransmission{std::move(*Result)};
    }

    template <typename ConnectFn, typename AcceptFn>
    struct BenchConnectionState final
    {
        Net::io_context &IoContext;
        Net::ip::tcp::acceptor &Acceptor;
        BenchOptions Options;
        std::vector<std::uint8_t> Chunk;
        std::uint16_t Port{0};
        int &Completed;
        ConnectFn ConnectFunction;
        AcceptFn AcceptFunction;
        std::size_t Pending{2};
        std::size_t ReadProgress{0};
        std::size_t WriteProgress{0};
        Prism::IoResult ReadResult{};
        Prism::IoResult WriteResult{};
    };

    template <typename ConnectFn, typename AcceptFn>
    auto RunBenchServer(std::shared_ptr<BenchConnectionState<ConnectFn, AcceptFn>> State)
        -> Net::awaitable<void>
    {
        Net::ip::tcp::socket Socket(State->IoContext);
        boost::system::error_code AcceptError;
        co_await State->Acceptor.async_accept(
            Socket, Net::redirect_error(Net::use_awaitable, AcceptError));
        if (AcceptError)
        {
            State->Completed = 0;
            co_return;
        }
        auto Upstream = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        auto Result = co_await State->AcceptFunction(Upstream);
        if (!Result)
        {
            std::fprintf(stderr, "accept handshake failed: code=%d native=%s:%d\n",
                         static_cast<int>(Result.error().Code),
                         Result.error().Native.category().name(), Result.error().Native.value());
            State->Completed = 0;
            co_return;
        }
        if (!*Result)
        {
            std::fprintf(stderr, "accept handshake returned an empty connection owner\n");
            State->Completed = 0;
            co_return;
        }
        auto Conn = std::move(*Result);
        std::vector<std::uint8_t> Buffer(State->Options.Block);
        while (State->ReadProgress < State->Options.Total)
        {
            State->ReadResult = co_await Conn->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()));
            if (State->ReadResult.Bytes > Buffer.size())
            {
                State->Completed = 0;
                break;
            }
            State->ReadProgress += State->ReadResult.Bytes;
            if (State->ReadResult.Failure.Failed() || State->ReadResult.Bytes == 0)
            {
                State->Completed = 0;
                break;
            }
        }
        (void)Conn->Close();
    }

    template <typename ConnectFn, typename AcceptFn>
    auto RunBenchClient(std::shared_ptr<BenchConnectionState<ConnectFn, AcceptFn>> State)
        -> Net::awaitable<void>
    {
        auto Upstream = std::make_shared<Prism::Transport::Reliable>(
            State->IoContext.get_executor());
        const auto ConnectError = co_await Upstream->Connect(
            Net::ip::tcp::endpoint(Net::ip::address_v4::loopback(), State->Port));
        if (ConnectError)
        {
            State->Completed = 0;
            boost::system::error_code CancelError;
            State->Acceptor.cancel(CancelError);
            co_return;
        }
        auto Result = co_await State->ConnectFunction(Upstream);
        if (!Result)
        {
            std::fprintf(stderr, "connect handshake failed: code=%d native=%s:%d\n",
                         static_cast<int>(Result.error().Code),
                         Result.error().Native.category().name(), Result.error().Native.value());
            State->Completed = 0;
            co_return;
        }
        if (!*Result)
        {
            std::fprintf(stderr, "connect handshake returned an empty connection owner\n");
            State->Completed = 0;
            co_return;
        }
        auto Conn = std::move(*Result);
        while (State->WriteProgress < State->Options.Total)
        {
            const auto WriteBuffer = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(State->Chunk.data()), State->Chunk.size());
            State->WriteResult = co_await Conn->WriteSome(WriteBuffer);
            if (State->WriteResult.Bytes > WriteBuffer.size())
            {
                State->Completed = 0;
                break;
            }
            State->WriteProgress += State->WriteResult.Bytes;
            if (State->WriteResult.Failure.Failed() || State->WriteResult.Bytes == 0)
            {
                State->Completed = 0;
                break;
            }
        }
        if (State->WriteProgress < State->Options.Total)
        {
            State->Completed = 0;
        }
        (void)Conn->Close();
    }

    template <typename ConnectFn, typename AcceptFn>
    auto FinishBench(
        std::shared_ptr<BenchConnectionState<ConnectFn, AcceptFn>> State,
        std::exception_ptr Error) -> void
    {
        if (Error)
        {
            State->Completed = 0;
        }
        --State->Pending;
        if (State->Pending == 0)
        {
            State->IoContext.stop();
        }
    }

    template <typename ConnectFn, typename AcceptFn>
    [[nodiscard]] auto BenchConn(
        BenchOptions Options,
        ConnectFn ConnectFunction,
        AcceptFn AcceptFunction)
        -> BenchResult
    {
        Net::io_context IoContext;
        Net::ip::tcp::acceptor Acceptor(
            IoContext,
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto Port = Acceptor.local_endpoint().port();

        const auto StartNanoseconds = NowNs();
        int Completed = 1; // 数据面完成标志（0 = 断链/未写完，门禁 FAIL）
        auto State = std::make_shared<BenchConnectionState<ConnectFn, AcceptFn>>(
            IoContext,
            Acceptor,
            Options,
            std::vector<std::uint8_t>(Options.Block, 0x5A),
            Port,
            Completed,
            std::move(ConnectFunction),
            std::move(AcceptFunction));
        const auto Complete = [State](std::exception_ptr Error)
        {
            FinishBench(State, Error);
        };
        Net::co_spawn(
            IoContext,
            RunBenchServer(State),
            Complete);
        Net::co_spawn(
            IoContext,
            RunBenchClient(State),
            Complete);
        IoContext.run();
        BenchResult Result;
        Result.ElapsedNanoseconds = Completed == 0 ? 0 : NowNs() - StartNanoseconds;
        Result.Completed = Completed != 0;
        Result.ReadProgress = State->ReadProgress;
        Result.WriteProgress = State->WriteProgress;
        Result.ReadResult = State->ReadResult;
        Result.WriteResult = State->WriteResult;
        return Result;
    }

    using ReliablePtr = std::shared_ptr<Prism::Transport::Reliable>;
    using ProtocolResult = std::expected<Prism::SharedTransmission, Prism::Fault::Failure>;
    using ProtocolOperation = Net::awaitable<ProtocolResult> (*)(ReliablePtr);

    auto ConnectSocks5(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        auto [ErrorCode, Conn] = co_await Prism::Socks5::Connect(
            Upstream, Prism::Socks5::ClientConfig{},
            Prism::Socks5::Address{Prism::Socks5::AddressType::Domain, "t.internal", 443});
        co_return ToTransmission(ErrorCode, std::move(Conn));
    }

    auto AcceptSocks5(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        auto [ErrorCode, Request, Conn] = co_await Prism::Socks5::Accept(
            Upstream, Prism::Socks5::ServerConfig{});
        (void)Request;
        co_return ToTransmission(ErrorCode, std::move(Conn));
    }

    auto ConnectTrojan(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        Prism::Trojan::ClientConfig Config;
        Config.Password = "prism";
        auto Result = co_await Prism::Trojan::Connect(Prism::Trojan::ConnectParameters{
            Upstream,
            Config,
            Prism::Trojan::Address{Prism::Trojan::AddressType::Domain, "t.internal", 443}});
        co_return ToTransmission(std::move(Result));
    }

    auto AcceptTrojan(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        Prism::Trojan::ServerConfig Config;
        Config.Password = "prism";
        auto Result = co_await Prism::Trojan::Accept(Upstream, Config);
        if (!Result) co_return std::unexpected(Result.error());
        if (!Result->Connection)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return Prism::SharedTransmission{std::move(Result->Connection)};
    }

    auto ConnectVless(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        constexpr auto Uuid = std::array<std::uint8_t, 16>{
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        Prism::Vless::ClientConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Prism::Vless::Connect(Prism::Vless::ConnectParameters{
            Upstream,
            Config,
            Prism::Vless::Address{Prism::Vless::AddressType::Domain, "t.internal", 443}});
        co_return ToTransmission(std::move(Result));
    }

    auto AcceptVless(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        constexpr auto Uuid = std::array<std::uint8_t, 16>{
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        Prism::Vless::ServerConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Prism::Vless::Accept(Upstream, Config);
        if (!Result) co_return std::unexpected(Result.error());
        if (!Result->Connection)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return Prism::SharedTransmission{std::move(Result->Connection)};
    }

    auto ConnectVmess(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        constexpr auto Uuid = std::array<std::uint8_t, 16>{
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        Prism::Vmess::ClientConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Prism::Vmess::Connect(Prism::Vmess::ConnectParameters{
            Upstream,
            Config,
            Prism::Vmess::Address{Prism::Vmess::AddressType::Domain, "t.internal", 443}});
        co_return ToTransmission(std::move(Result));
    }

    auto AcceptVmess(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        constexpr auto Uuid = std::array<std::uint8_t, 16>{
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        Prism::Vmess::ServerConfig Config;
        Config.uuid = Uuid;
        auto Result = co_await Prism::Vmess::AcceptSession(Upstream, Config);
        if (!Result) co_return std::unexpected(Result.error());
        auto *Accepted = std::get_if<Prism::Vmess::AcceptedConnection>(&*Result);
        if (!Accepted || !Accepted->Connection)
        {
            (void)Upstream->Close();
            (void)co_await Upstream->Activity()->Drain();
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return Prism::SharedTransmission{std::move(Accepted->Connection)};
    }

    auto ConnectShadowsocks(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        constexpr std::array<std::uint8_t, 16> Psk{
            0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
            0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
        Prism::Shadowsocks2022::ClientConfig Config;
        Config.Psk = Psk;
        auto [ErrorCode, Conn] = co_await Prism::Shadowsocks2022::Connect(
            Upstream, Config,
            Prism::Shadowsocks2022::Address{
                Prism::Shadowsocks2022::AddressType::Domain, "t.internal", 443});
        co_return ToTransmission(ErrorCode, std::move(Conn));
    }

    auto AcceptShadowsocks(ReliablePtr Upstream) -> Net::awaitable<ProtocolResult>
    {
        constexpr std::array<std::uint8_t, 16> Psk{
            0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
            0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
        Prism::Shadowsocks2022::ServerConfig Config;
        Config.Psk = Psk;
        auto [ErrorCode, Request, Conn] = co_await Prism::Shadowsocks2022::Accept(
            Upstream, Config);
        (void)Request;
        co_return ToTransmission(ErrorCode, std::move(Conn));
    }

    struct ProtocolGateRequest final
    {
        const char *Name;
        BenchOptions Options;
        ProtocolOperation Connect;
        ProtocolOperation Accept;
    };

    [[nodiscard]] auto RunProtocolGate(ProtocolGateRequest Request) -> bool
    {
        std::array<BenchResult, 3> Samples{};
        for (std::size_t Index = 0; Index < Samples.size(); ++Index)
        {
            Samples[Index] = BenchConn(Request.Options, Request.Connect, Request.Accept);
        }
        return Gate(Request.Name, Request.Options.Total, Samples);
    }

    [[nodiscard]] auto RunSocks5Phase(const BenchOptions Options) -> bool
    {
        return RunProtocolGate(
            ProtocolGateRequest{"socks5 Conn<->Conn (透传)", Options, ConnectSocks5, AcceptSocks5});
    }

    [[nodiscard]] auto RunTrojanPhase(const BenchOptions Options) -> bool
    {
        return RunProtocolGate(
            ProtocolGateRequest{"trojan Conn<->Conn (透传)", Options, ConnectTrojan, AcceptTrojan});
    }

    [[nodiscard]] auto RunVlessPhase(const BenchOptions Options) -> bool
    {
        return RunProtocolGate(
            ProtocolGateRequest{"vless Conn<->Conn (透传)", Options, ConnectVless, AcceptVless});
    }

    [[nodiscard]] auto RunVmessPhase(const BenchOptions Options) -> bool
    {
        return RunProtocolGate(
            ProtocolGateRequest{"vmess Conn<->Conn (加密16KB)", Options, ConnectVmess, AcceptVmess});
    }

    [[nodiscard]] auto RunShadowsocksPhase(const BenchOptions Options) -> bool
    {
        return RunProtocolGate(
            ProtocolGateRequest{
                "ss2022 Conn<->Conn (加密16KB)", Options, ConnectShadowsocks, AcceptShadowsocks});
    }
} // namespace

auto main() -> int
{
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    constexpr std::size_t TotalBytes = 256ULL * 1024 * 1024;
    constexpr std::size_t BlockBytes = 262144;
    const BenchOptions Options{TotalBytes, BlockBytes};
    if (!RunSocks5Phase(Options) ||
        !RunTrojanPhase(Options) ||
        !RunVlessPhase(Options) ||
        !RunVmessPhase(Options) ||
        !RunShadowsocksPhase(Options))
    {
        return 1;
    }
    std::printf("AllProtoTransfer: ALL PASS\n");
    return 0;
}
