/**
 * @file InteropShadowtls.cpp
 * @brief Prism ShadowTLS v3 server 与外部 Go/mihomo client 的互操作端点
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <Prism/Protocols/Shadowtls/Shadowtls.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/Reliable.hpp>

#include <algorithm>
#include <array>

namespace
{
    namespace Net = boost::asio;
    namespace Transport = Prism::Transport;
    namespace Shadowtls = Prism::Shadowtls;
    namespace Network = Prism::Network;
    using Tcp = Net::ip::tcp;
    using SharedTransmission = Prism::SharedTransmission;

    constexpr std::string_view Payload{"prism-shadowtls-external-payload"};

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        std::uint32_t Port = 0;
        const auto [End, Ec] = std::from_chars(Value.data(), Value.data() + Value.size(), Port);
        if (Value.empty() || Ec != std::errc{} || End != Value.data() + Value.size() || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto ParseHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        const auto Colon = Value.rfind(':');
        if (Colon == std::string_view::npos || Colon == 0 || Colon + 1 >= Value.size())
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Colon + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Colon)), *Port};
    }

    struct Options
    {
        std::string Address{"127.0.0.1:19096"};
        std::string Target{"127.0.0.1:19097"};
        std::string Password{"relay-password"};
    };

    auto DialShadowtlsTarget(Network::Target Target)
        -> Net::awaitable<std::expected<SharedTransmission, Prism::Fault::Failure>>
    {
        const auto Address = Network::IpAddress(Target.Host);
        if (!Address)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Tcp::socket TargetSocket(co_await Net::this_coro::executor);
        boost::system::error_code ConnectError;
        co_await TargetSocket.async_connect(Tcp::endpoint(*Address, Target.Port),
            Net::redirect_error(Net::use_awaitable, ConnectError));
        if (ConnectError)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(ConnectError)));
        }
        co_return std::make_shared<Transport::Reliable>(std::move(TargetSocket));
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-target")
            {
                Result.Target = Value;
            }
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else
            {
                return std::nullopt;
            }
        }
        return Result;
    }

    auto ReadExact(const SharedTransmission &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Read = co_await Transport->ReadSome(Buffer.subspan(Offset));
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Read.Bytes;
        }
        co_return true;
    }

    auto WriteAll(const SharedTransmission &Transport, std::span<const std::byte> Buffer)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Written = co_await Transport->WriteSome(Buffer.subspan(Offset));
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Written.Bytes;
        }
        co_return true;
    }

    struct ShadowtlsSessionRequest final
    {
        SharedTransmission Inbound;
        Options OptionsValue;
        Net::ip::address TargetAddress;
        std::uint16_t TargetPort;
    };

    auto RunShadowtlsSession(ShadowtlsSessionRequest Request)
        -> Net::awaitable<int>
    {
        Prism::Composition::Recognition::ShadowtlsCarrierOptions CarrierOptions;
        CarrierOptions.HandshakeDest = Request.TargetAddress.to_string() + ":" +
            std::to_string(Request.TargetPort);
        CarrierOptions.Password = Request.OptionsValue.Password;
        CarrierOptions.Dial = [](const Network::Target& Target)
        {
            return DialShadowtlsTarget(Target);
        };
        auto Carrier = Prism::Composition::Recognition::MakeConfiguredShadowtlsServerAccept(
            std::move(CarrierOptions));
        if (!Carrier)
        {
            (void)Request.Inbound->Close();
            std::fprintf(stderr, "FAIL: ShadowTLS carrier configuration error=%d\n",
                static_cast<int>(Carrier.error()));
            co_return 1;
        }
        Prism::Composition::Recognition::TlsCandidateOptions CandidateOptions;
        CandidateOptions.Id = 1;
        CandidateOptions.Name = "shadowtls";
        CandidateOptions.Scheme = "shadowtls";
        CandidateOptions.ServerNames = {"target"};
        CandidateOptions.Alpn = {"h2", "http/1.1"};
        CandidateOptions.Carrier = Prism::Composition::Recognition::TlsCarrier::Shadowtls;
        auto Binding = Prism::Composition::Recognition::TlsCandidateFactory::Make(
            std::move(CandidateOptions), std::move(*Carrier));
        Prism::Recognition::ProfileSpec ProfileSpec;
        ProfileSpec.ConfiguredCandidate = 1;
        ProfileSpec.Candidates.push_back(std::move(Binding.Spec));
        const auto Compiled = Prism::Recognition::Profile::Compile(std::move(ProfileSpec));
        if (!Compiled)
        {
            (void)Request.Inbound->Close();
            std::fprintf(stderr, "FAIL: ShadowTLS recognition profile compile\n");
            co_return 1;
        }
        auto BytePool = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8U});
        Prism::Recognition::Pipeline Pipeline(*Compiled, std::move(BytePool));
        auto Recognition = co_await Pipeline.Recognize(Request.Inbound);
        if (!Recognition.success ||
            Recognition.Status != Prism::Recognition::RecognitionStatus::Accepted ||
            !Recognition.transport)
        {
            if (Recognition.transport)
            {
                (void)Recognition.transport->Close();
            }
            std::fprintf(stderr, "FAIL: ShadowTLS recognition status=%d\n",
                         static_cast<int>(Recognition.Status));
            co_return 1;
        }
        auto Result = std::move(Recognition.transport);
        std::array<std::byte, Payload.size()> Buffer{};
        if (!co_await ReadExact(Result, Buffer))
        {
            (void)Result->Close();
            std::fprintf(stderr, "FAIL: ShadowTLS inner read\n");
            co_return 1;
        }
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        if (!std::equal(Buffer.begin(), Buffer.end(), PayloadBytes.begin()))
        {
            (void)Result->Close();
            std::fprintf(stderr, "FAIL: ShadowTLS inner payload mismatch\n");
            co_return 1;
        }
        if (!co_await WriteAll(Result, Buffer))
        {
            (void)Result->Close();
            std::fprintf(stderr, "FAIL: ShadowTLS inner write\n");
            co_return 1;
        }
        (void)Result->Close();
        std::printf("PASS: Prism ShadowTLS server -> Go/mihomo client (%zu bytes)\n",
                    Payload.size());
        co_return 0;
    }

    auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = ParseHostPort(OptionsValue.Address);
        const auto Target = ParseHostPort(OptionsValue.Target);
        if (!Listen || !Target)
        {
            std::fprintf(stderr, "FAIL: malformed ShadowTLS endpoint\n");
            co_return 2;
        }
        boost::system::error_code Ec;
        const auto ListenAddress = Net::ip::make_address(Listen->Host, Ec);
        if (Ec)
        {
            std::fprintf(stderr, "FAIL: ShadowTLS listen address: %s\n", Ec.message().c_str());
            co_return 2;
        }
        const auto TargetAddress = Net::ip::make_address(Target->Host, Ec);
        if (Ec)
        {
            std::fprintf(stderr, "FAIL: ShadowTLS target address: %s\n", Ec.message().c_str());
            co_return 2;
        }

        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        auto Protocol = Tcp::v4();
        if (!ListenAddress.is_v4())
        {
            Protocol = Tcp::v6();
        }
        Acceptor.open(Protocol, Ec);
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Ec);
        Acceptor.bind(Tcp::endpoint(ListenAddress, Listen->Port), Ec);
        Acceptor.listen(Net::socket_base::max_listen_connections, Ec);
        if (Ec)
        {
            std::fprintf(stderr, "FAIL: ShadowTLS listen: %s\n", Ec.message().c_str());
            co_return 1;
        }
        std::printf("READY: Prism ShadowTLS server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);

        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Ec));
        if (Ec)
        {
            co_return 1;
        }
        auto Inbound = std::make_shared<Transport::Reliable>(std::move(Socket));
        const auto Result = co_await RunShadowtlsSession(
            ShadowtlsSessionRequest{
                Inbound, OptionsValue, TargetAddress, Target->Port});
        boost::system::error_code CloseError;
        Acceptor.close(CloseError);
        co_return Result;
    }

} // namespace

auto main(int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed ShadowTLS options\n");
        return 2;
    }
    Net::io_context Context;
    int ExitCode = 1;
    std::exception_ptr Failure;
    auto Run = [&Context, &ExitCode, OptionsValue = *Options]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunServer(OptionsValue);
    };
    auto OnComplete = [&Context, &Failure](std::exception_ptr Error) -> void
    {
        Failure = std::move(Error);
    };
    Net::co_spawn(Context, Run(), std::move(OnComplete));
    Context.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: ShadowTLS server exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: ShadowTLS server exception\n");
        }
        return 1;
    }
    return ExitCode;
}
