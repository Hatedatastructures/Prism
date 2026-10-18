#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file InteropRecognition.cpp
 * @brief Prism 双模式识别的真实单端口 listener harness
 * @details 外部 reference client -> TcpListener -> Profile recognition ->
 *          Candidate resolver -> protocol handler -> memory echo。
 *          该程序只负责服务端端点，进程在首个 relay 完成后退出。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
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
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Runtime/Listener.hpp>
#include <Prism/Runtime/SessionAdmissionTestSupport.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Transport/MemoryStream.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;
    namespace Runtime = Prism::Runtime;
    using Tcp = Net::ip::tcp;

    auto EchoMemory(std::shared_ptr<Prism::MemoryStream> Peer) -> Net::awaitable<void>;

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

    class CompletionSink final : public Prism::Foundation::TrafficSink
    {
    public:
        auto Report(Prism::Foundation::TrafficEvent) noexcept -> void override
        {
            Completed_.store(true, std::memory_order_release);
        }

        auto Retire(Prism::Foundation::TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        { (void)Owner; co_return std::expected<void, Prism::Fault::Failure>{}; }

        [[nodiscard]] auto Completed() const noexcept -> bool
        {
            return Completed_.load(std::memory_order_acquire);
        }

        auto StartEcho(Net::any_io_executor Executor,
                       std::shared_ptr<Prism::MemoryStream> Peer) -> void
        {
            EchoState StateValue{
                std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Executor, 1),
                std::make_shared<std::exception_ptr>()};
            Echo_ = std::make_shared<EchoState>(std::move(StateValue));
            Net::co_spawn(
                Executor,
                EchoMemory(std::move(Peer)),
                [State = Echo_](std::exception_ptr ErrorValue)
                {
                    if (ErrorValue && !*State->Failure)
                    {
                        *State->Failure = ErrorValue;
                    }
                    (void)State->Done->try_send(boost::system::error_code{});
                });
        }

        auto WaitEcho() -> Net::awaitable<void>
        {
            const auto State = Echo_;
            if (!State)
            {
                co_return;
            }
            boost::system::error_code ErrorCode;
            (void)co_await State->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                throw std::system_error(ErrorCode);
            }
            if (*State->Failure)
            {
                std::rethrow_exception(*State->Failure);
            }
        }

    private:
        struct EchoState final
        {
            std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
            std::shared_ptr<std::exception_ptr> Failure;
        };

        std::atomic_bool Completed_{false};
        std::shared_ptr<EchoState> Echo_;
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

    auto EchoMemory(std::shared_ptr<Prism::MemoryStream> Peer) -> Net::awaitable<void>
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

    [[nodiscard]] auto MakeMemoryDial(Net::any_io_executor Executor,
                                      std::shared_ptr<CompletionSink> Sink)
        -> Prism::Middleware::Builtin::DialMiddleware::DialFn
    {
        return [Executor, Sink = std::move(Sink)](const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            auto [UpstreamValue, PeerValue] = Prism::MakeMemoryPair(Executor);
            auto Upstream = std::make_shared<Prism::MemoryStream>(std::move(UpstreamValue));
            auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerValue));
            Sink->StartEcho(Executor, std::move(Peer));
            co_return std::static_pointer_cast<Prism::Transmission>(Upstream);
        };
    }

    [[nodiscard]] auto BuildSessionOptions(const Options &OptionsValue,
                                            Net::any_io_executor Executor,
                                            std::shared_ptr<CompletionSink> Sink)
        -> std::optional<Runtime::SessionOptions>
    {
        std::vector<Composition::CandidateBinding> Bindings;
        auto UseState = Prism::Testing::MakeProtocolIngressUseState();
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Budget.MaxCandidates = 2;
        if (OptionsValue.Mode == "Deterministic" &&
            (OptionsValue.Protocol == "http" || OptionsValue.Protocol == "socks5"))
        {
            BuilderOptions.Mode = Core::RecognitionMode::Deterministic;
            Bindings.push_back(Composition::CandidateFactory::MakeHttp(Prism::Composition::Recognition::CandidateOptions{1}));
            Bindings.push_back(Composition::CandidateFactory::MakeSocks5(Composition::CandidateOptions{2}, Prism::Testing::MakeSocks5Binding({})));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "vless")
        {
            constexpr std::array<std::uint8_t, 16> Uuid{
                0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Bindings.push_back(Prism::Testing::MakeVlessCandidate(
                Prism::Composition::Recognition::CandidateOptions{1},
                Prism::Vless::ServerConfig{Uuid}, UseState));
            Bindings.push_back(Prism::Testing::MakeVmessCandidate(
                Prism::Composition::Recognition::CandidateOptions{2},
                Prism::Vmess::ServerConfig{Uuid}, UseState));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "trojan")
        {
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Bindings.push_back(Prism::Testing::MakeTrojanCandidate(
                Prism::Composition::Recognition::CandidateOptions{1},
                Prism::Trojan::ServerConfig{"prism"}, UseState));
            Bindings.push_back(Prism::Testing::MakeVmessCandidate(
                Prism::Composition::Recognition::CandidateOptions{2},
                Prism::Vmess::ServerConfig{}, UseState));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "vmess")
        {
            constexpr std::array<std::uint8_t, 16> Uuid{
                0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Bindings.push_back(Prism::Testing::MakeVmessCandidate(
                Prism::Composition::Recognition::CandidateOptions{1},
                Prism::Vmess::ServerConfig{Uuid}, UseState));
            Bindings.push_back(Prism::Testing::MakeTrojanCandidate(
                Prism::Composition::Recognition::CandidateOptions{2},
                Prism::Trojan::ServerConfig{"prism"}, UseState));
        }
        else if (OptionsValue.Mode == "MixedTrial" && OptionsValue.Protocol == "ss2022")
        {
            constexpr std::array<std::uint8_t, 16> Uuid{
                0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
            BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
            Prism::Shadowsocks2022::ServerConfig Config;
            Config.Psk = {
                0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
            Bindings.push_back(Composition::CandidateFactory::MakeSs2022(Composition::CandidateOptions{1}, Prism::Testing::MakeSs2022Binding(std::move(Config))));
            Bindings.push_back(Prism::Testing::MakeVmessCandidate(
                Prism::Composition::Recognition::CandidateOptions{2},
                Prism::Vmess::ServerConfig{Uuid}, UseState));
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
        Result.Services->Profile = Built->Profile;
        Result.Services->ResolveCandidate = Built->Resolver;
        Result.Services->GenerationUseState = std::move(UseState);
        Result.Services->RelayIdleTimeout = std::chrono::seconds(5);
        Result.Services->Dial = MakeMemoryDial(Executor, Sink);
        Result.Services->Traffic = std::move(Sink);
        return Result;
    }

    /// 关闭 listener 并等待 accept、session registry 和 memory echo 全部退场。
    auto DrainRecognitionOwner(Runtime::TcpListener &Listener,
                               const std::shared_ptr<CompletionSink> &Sink)
        -> Net::awaitable<void>
    {
        std::exception_ptr FirstError;
        Listener.Stop();
        try
        {
            co_await Listener.Shutdown();
        }
        catch (...)
        {
            FirstError = std::current_exception();
        }
        try
        {
            co_await Sink->WaitEcho();
        }
        catch (...)
        {
            if (!FirstError)
            {
                FirstError = std::current_exception();
            }
        }
        if (FirstError)
        {
            std::rethrow_exception(FirstError);
        }
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
        auto Sink = std::make_shared<CompletionSink>();
        const auto SessionOptions = BuildSessionOptions(OptionsValue, Executor, Sink);
        if (!SessionOptions)
        {
            co_return 2;
        }
        auto Factory = [OptionsValue = *SessionOptions](Prism::Runtime::SessionAdmission Admission)
            -> std::shared_ptr<Runtime::Session>
        {
            auto Options = OptionsValue;
            Options.SourceIp = std::move(Admission.SourceIp);
            return std::make_shared<Runtime::Session>(std::move(Options));
        };
        Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Executor;
        ListenerOptions.Factory = std::move(Factory);
        ListenerOptions.WorkerCount = 1U;
        ListenerOptions.MaxConnections = 8U;
        ListenerOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            Prism::GenerationId{1});
        Runtime::TcpListener Listener(std::move(ListenerOptions));
        const auto ListenEndpoint = Tcp::endpoint(Address, Listen->Port);
        const auto StartResult = co_await Listener.Start(ListenEndpoint);
        if (StartResult != Prism::Fault::Code::Success)
        {
            std::fprintf(stderr, "FAIL: listener start\n");
            co_return 1;
        }

        std::printf("READY: Prism %s %s recognition listener on %s\n",
                    OptionsValue.Mode.c_str(), OptionsValue.Protocol.c_str(),
                    OptionsValue.Address.c_str());
        std::fflush(stdout);

        Net::steady_timer Timer(Executor);
        const auto Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (!Sink->Completed() && std::chrono::steady_clock::now() < Deadline)
        {
            Timer.expires_after(std::chrono::milliseconds(50));
            boost::system::error_code TimerError;
            co_await Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
        }
        co_await DrainRecognitionOwner(Listener, Sink);
        if (!Sink->Completed())
        {
            std::fprintf(stderr, "FAIL: recognition listener timed out\n");
            co_return 1;
        }
        std::printf("PASS: Prism %s %s single-port recognition echo\n",
                    OptionsValue.Mode.c_str(), OptionsValue.Protocol.c_str());
        co_return 0;
    }

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        ExitCode = co_await RunServer(OptionsValue);
    }

} // namespace

auto main(int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(Io, RunInterop(OptionsValue, ExitCode),
                  [&Failure](std::exception_ptr Exception) { Failure = std::move(Exception); });
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: recognition listener exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: recognition listener exception: unknown\n");
        }
        return 1;
    }
    return ExitCode;
}
