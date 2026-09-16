/**
 * @file InteropRecognition.cpp
 * @brief Preview 双模式识别的真实单端口 listener harness
 * @details 外部 reference client -> TcpListener -> Profile recognition ->
 *          Candidate resolver -> protocol handler -> memory echo。
 *          该程序只负责服务端端点，进程在首个 relay 完成后退出。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Composition/Recognition/SettingsBuilder.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/MemoryStream.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;
    namespace Runtime = Preview::Runtime;
    using Tcp = Net::ip::tcp;

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    struct Options
    {
        std::string Mode{"Deterministic"};
        std::string Protocol{"http"};
        std::string Address{"127.0.0.1:19110"};
    };

    class CompletionSink final : public Preview::Foundation::TrafficSink
    {
    public:
        auto Report(std::string_view, std::size_t, std::size_t) -> void override
        {
            Completed_.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto Completed() const noexcept -> bool
        {
            return Completed_.load(std::memory_order_acquire);
        }

    private:
        std::atomic_bool Completed_{false};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        if (Value.empty())
        {
            return std::nullopt;
        }
        std::uint32_t Port = 0;
        const auto *Begin = Value.data();
        const auto *End = Begin + Value.size();
        const auto [Parsed, Error] = std::from_chars(Begin, End, Port);
        if (Error != std::errc{} || Parsed != End || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        if (Value.starts_with('['))
        {
            const auto Closing = Value.find(']');
            if (Closing == std::string_view::npos || Closing + 2 > Value.size() ||
                Value[Closing + 1] != ':')
            {
                return std::nullopt;
            }
            const auto Port = ParsePort(Value.substr(Closing + 2));
            if (!Port)
            {
                return std::nullopt;
            }
            return HostPort{std::string(Value.substr(1, Closing - 1)), *Port};
        }
        const auto Separator = Value.find_last_of(':');
        if (Separator == std::string_view::npos || Separator == 0)
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Separator + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Separator)), *Port};
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> Options
    {
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-mode")
            {
                Result.Mode = Value;
            }
            else if (Key == "-protocol")
            {
                Result.Protocol = Value;
            }
            else if (Key == "-addr")
            {
                Result.Address = Value;
            }
        }
        return Result;
    }

    auto EchoMemory(std::shared_ptr<Preview::MemoryStream> Peer) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            std::error_code ReadError;
            const auto Count = co_await Peer->async_read_some(Buffer, ReadError);
            if (ReadError || Count == 0)
            {
                break;
            }
            std::size_t Offset = 0;
            while (Offset < Count)
            {
                std::error_code WriteError;
                const auto WriteWindow = std::span<const std::byte>(Buffer).subspan(
                    Offset, Count - Offset);
                const auto Written = co_await Peer->async_write_some(WriteWindow, WriteError);
                if (WriteError || Written == 0)
                {
                    Peer->Close();
                    co_return;
                }
                Offset += Written;
            }
        }
        Peer->Close();
    }

    [[nodiscard]] auto MakeMemoryDial(Net::any_io_executor Executor)
        -> Preview::Middleware::Builtin::DialMiddleware::DialFn
    {
        return [Executor](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            auto [UpstreamValue, PeerValue] = Preview::MakeMemoryPair(Executor);
            auto Upstream = std::make_shared<Preview::MemoryStream>(std::move(UpstreamValue));
            auto Peer = std::make_shared<Preview::MemoryStream>(std::move(PeerValue));
            Net::co_spawn(Executor, EchoMemory(Peer), Net::detached);
            co_return std::pair{Preview::Fault::Code::Success,
                                std::static_pointer_cast<Preview::Transmission>(Upstream)};
        };
    }

    [[nodiscard]] auto BuildSessionOptions(const Options &OptionsValue,
                                            Net::any_io_executor Executor,
                                            CompletionSink &Sink)
        -> std::optional<Runtime::SessionOptions>
    {
        std::vector<Composition::CandidateBinding> Bindings;
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Budget.MaxCandidates = 2;
        if (OptionsValue.Mode == "Deterministic" &&
            (OptionsValue.Protocol == "http" || OptionsValue.Protocol == "socks5"))
        {
            BuilderOptions.Mode = Core::RecognitionMode::Deterministic;
            Bindings.push_back(Composition::CandidateFactory::MakeHttp(1));
            Bindings.push_back(Composition::CandidateFactory::MakeSocks5(2));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "vless")
        {
            constexpr std::array<std::uint8_t, 16> Uuid{
                0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Bindings.push_back(Composition::CandidateFactory::MakeVless(
                1, Preview::Vless::ServerConfig{Uuid}));
            Bindings.push_back(Composition::CandidateFactory::MakeVmess(
                2, Preview::Vmess::ServerConfig{Uuid}));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "trojan")
        {
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Bindings.push_back(Composition::CandidateFactory::MakeTrojan(
                1, Preview::Trojan::ServerConfig{"prism"}));
            Bindings.push_back(Composition::CandidateFactory::MakeVmess(
                2, Preview::Vmess::ServerConfig{}));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "vmess")
        {
            constexpr std::array<std::uint8_t, 16> Uuid{
                0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Bindings.push_back(Composition::CandidateFactory::MakeVmess(
                1, Preview::Vmess::ServerConfig{Uuid}));
            Bindings.push_back(Composition::CandidateFactory::MakeTrojan(
                2, Preview::Trojan::ServerConfig{"prism"}));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "ss2022")
        {
            constexpr std::array<std::uint8_t, 16> Uuid{
                0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Preview::Shadowsocks2022::ServerConfig Config;
            Config.password = "5n5ESu953i/pjIp02oZvHA==";
            Bindings.push_back(Composition::CandidateFactory::MakeSs2022(1, std::move(Config)));
            Bindings.push_back(Composition::CandidateFactory::MakeVmess(
                2, Preview::Vmess::ServerConfig{Uuid}));
        }
        else
        {
            std::fprintf(stderr, "FAIL: unsupported recognition mode/protocol pair\n");
            return std::nullopt;
        }

        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(BuilderOptions));
        if (!Built)
        {
            const auto Error = Core::ToStringView(Built.error());
            std::fprintf(stderr, "FAIL: recognition profile build (%s)\n",
                         std::string(Error).c_str());
            return std::nullopt;
        }

        Runtime::SessionOptions Result;
        Result.Profile = Built->Profile;
        Result.ResolveCandidate = Built->Resolver;
        Result.RelayIdleTimeout = std::chrono::seconds(5);
        Result.Dial = MakeMemoryDial(Executor);
        Result.traffic = &Sink;
        return Result;
    }

    auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed listener address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: listener address is not an IP literal\n");
            co_return 2;
        }

        const auto Executor = co_await Net::this_coro::executor;
        CompletionSink Sink;
        const auto SessionOptions = BuildSessionOptions(OptionsValue, Executor, Sink);
        if (!SessionOptions)
        {
            co_return 2;
        }
        auto Factory = Composition::MakeSessionFactory(*SessionOptions);
        Runtime::TcpListener Listener(Runtime::TcpListener::Options{
            Executor, std::move(Factory), 1, 8});
        const auto ListenEndpoint = Tcp::endpoint(Address, Listen->Port);
        const auto StartResult = co_await Listener.Start(ListenEndpoint);
        if (StartResult != Preview::Fault::Code::Success)
        {
            std::fprintf(stderr, "FAIL: listener start\n");
            co_return 1;
        }

        std::printf("READY: Preview %s %s recognition listener on %s\n",
                    OptionsValue.Mode.c_str(), OptionsValue.Protocol.c_str(),
                    OptionsValue.Address.c_str());
        std::fflush(stdout);

        Net::steady_timer Timer(Executor);
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (!Sink.Completed() && std::chrono::steady_clock::now() < Deadline)
        {
            Timer.expires_after(std::chrono::milliseconds(50));
            boost::system::error_code TimerError;
            co_await Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
        }
        Listener.Stop();
        if (!Sink.Completed())
        {
            std::fprintf(stderr, "FAIL: recognition listener timed out\n");
            co_return 1;
        }
        std::printf("PASS: Preview %s %s single-port recognition echo\n",
                    OptionsValue.Mode.c_str(), OptionsValue.Protocol.c_str());
        co_return 0;
    }

} // namespace

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [OptionsValue, &Io, &ExitCode]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunServer(OptionsValue);
        Io.stop();
    };
    auto OnComplete = [&Io](std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            try
            {
                std::rethrow_exception(Exception);
            }
            catch (const std::exception &Error)
            {
                std::fprintf(stderr, "FAIL: recognition listener exception: %s\n", Error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "FAIL: recognition listener exception: unknown\n");
            }
        }
        Io.stop();
    };
    Net::co_spawn(Io, Run(), std::move(OnComplete));
    Io.run();
    return ExitCode;
}
