/**
 * @file InteropVmess.cpp
 * @brief Preview VMess 服务端与独立 sing-vmess 客户端的外部互操作端点
 * @details 接受 readiness 探测后继续等待真实 VMess 握手；TCP 会话逐字节
 *          回显，UDP 命令按 chunk 数据报回显。端点在两个有效会话结束后
 *          收口，供矩阵 runner 获取确定的进程退出状态。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Mode{"server"};
        std::string Address{"127.0.0.1:19083"};
        std::array<std::uint8_t, 16> Uuid{
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
            0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
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
            if (std::string_view(Argv[Index]) == "-mode")
            {
                Result.Mode = Argv[Index + 1];
            }
            else if (std::string_view(Argv[Index]) == "-addr")
            {
                Result.Address = Argv[Index + 1];
            }
        }
        return Result;
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed VMess server address\n");
            co_return 2;
        }
        const auto Executor = co_await Net::this_coro::executor;
        Preview::Network::Dialer::Dialer Dialer(Executor);
        const Preview::Vmess::ClientConfig Config{OptionsValue.Uuid};
        const Preview::Vmess::Address Target{
            Preview::Vmess::AddressType::Domain, "example.com", 443};

        {
            std::error_code DialError;
            auto DialOperation = Dialer.Connect(Server->Host, Server->Port, DialError);
            auto Raw = co_await std::move(DialOperation);
            if (!Raw)
            {
                std::fprintf(stderr, "FAIL: VMess TCP dial: %s\n", DialError.message().c_str());
                co_return 1;
            }
            auto ConnectOperation = Preview::Vmess::Connect(
                Preview::Vmess::ConnectParameters{
                    std::move(Raw),
                    Config,
                    Target,
                    static_cast<std::uint8_t>(Preview::Vmess::Command::Tcp)});
            auto [HandshakeError, Conn] = co_await std::move(ConnectOperation);
            if (HandshakeError != Preview::Error::None || !Conn)
            {
                std::fprintf(stderr, "FAIL: VMess TCP handshake (%u)\n",
                             static_cast<unsigned>(HandshakeError));
                co_return 1;
            }
            constexpr std::string_view Text{"prism-vmess-external-tcp-payload"};
            const auto Payload = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Text.data()), Text.size());
            std::error_code WriteError;
            auto WriteOperation = Conn->async_write_some(Payload, WriteError);
            const auto Written = co_await std::move(WriteOperation);
            if (Written != Payload.size() || WriteError)
            {
                Conn->Close();
                co_return 1;
            }
            std::vector<std::byte> Echo(Text.size());
            std::size_t Done = 0;
            while (Done < Echo.size())
            {
                std::error_code ReadError;
                const auto ReadBuffer = std::span<std::byte>(Echo).subspan(Done);
                auto ReadOperation = Conn->async_read_some(ReadBuffer, ReadError);
                const auto Read = co_await std::move(ReadOperation);
                if (ReadError || Read == 0)
                {
                    Conn->Close();
                    co_return 1;
                }
                Done += Read;
            }
            Conn->Close();
            if (std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
            {
                std::fprintf(stderr, "FAIL: VMess TCP echo mismatch\n");
                co_return 1;
            }
        }

        {
            std::error_code DialError;
            auto DialOperation = Dialer.Connect(Server->Host, Server->Port, DialError);
            auto Raw = co_await std::move(DialOperation);
            if (!Raw)
            {
                std::fprintf(stderr, "FAIL: VMess UDP dial: %s\n", DialError.message().c_str());
                co_return 1;
            }
            auto PacketOperation = Preview::Vmess::ConnectPacket(
                std::move(Raw), Config, Target);
            auto [HandshakeError, Datagram] = co_await std::move(PacketOperation);
            if (HandshakeError != Preview::Error::None || !Datagram)
            {
                std::fprintf(stderr, "FAIL: VMess UDP handshake (%u)\n",
                             static_cast<unsigned>(HandshakeError));
                co_return 1;
            }
            constexpr std::string_view Text{"prism-vmess-external-udp-payload"};
            const auto Payload = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size());
            auto SendOperation = Datagram->AsyncSendTo(Payload);
            const auto SendError = co_await std::move(SendOperation);
            if (SendError != Preview::Error::None)
            {
                Datagram->Close();
                co_return 1;
            }
            std::vector<std::uint8_t> Echo;
            auto ReceiveOperation = Datagram->AsyncReceiveFrom(Echo);
            const auto ReceiveError = co_await std::move(ReceiveOperation);
            bool EchoMatches = ReceiveError == Preview::Error::None;
            if (EchoMatches && Echo.size() != Payload.size())
            {
                EchoMatches = false;
            }
            if (EchoMatches && !std::equal(Echo.begin(), Echo.end(), Payload.begin()))
            {
                EchoMatches = false;
            }
            if (!EchoMatches)
            {
                Datagram->Close();
                std::fprintf(stderr, "FAIL: VMess UDP echo mismatch\n");
                co_return 1;
            }
            Datagram->Close();
        }
        std::printf("PASS: Preview VMess client -> sing-vmess reference server TCP+UDP\n");
        co_return 0;
    }

    [[nodiscard]] auto EchoStream(Preview::Vmess::SharedConn Conn) -> Net::awaitable<void>
    {
        std::array<std::byte, 16 * 1024> Buffer{};
        while (true)
        {
            std::error_code ReadError;
            auto ReadOperation = Conn->async_read_some(Buffer, ReadError);
            const auto Count = co_await std::move(ReadOperation);
            if (ReadError || Count == 0)
            {
                break;
            }
            std::size_t Offset = 0;
            while (Offset < Count)
            {
                std::error_code WriteError;
                const auto WriteBuffer = std::span<const std::byte>(Buffer).subspan(Offset, Count - Offset);
                auto WriteOperation = Conn->async_write_some(WriteBuffer, WriteError);
                const auto Written = co_await std::move(WriteOperation);
                if (WriteError || Written == 0)
                {
                    Conn->Close();
                    co_return;
                }
                Offset += Written;
            }
        }
        Conn->Close();
    }

    [[nodiscard]] auto EchoDatagrams(Preview::Vmess::SharedConn Conn) -> Net::awaitable<void>
    {
        while (true)
        {
            std::vector<std::uint8_t> Payload;
            auto ReadOperation = Conn->AsyncReceiveDatagram(Payload);
            const auto ReadError = co_await std::move(ReadOperation);
            if (ReadError != Preview::Error::None)
            {
                break;
            }
            auto SendOperation = Conn->AsyncSendDatagram(Payload);
            const auto SendError = co_await std::move(SendOperation);
            if (SendError != Preview::Error::None)
            {
                break;
            }
        }
        Conn->Close();
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket, const Options &OptionsValue)
        -> Net::awaitable<bool>
    {
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const Preview::Vmess::ServerConfig Config{OptionsValue.Uuid};
        auto AcceptOperation = Preview::Vmess::Accept(Raw, Config);
        auto [HandshakeError, Request, Conn] = co_await std::move(AcceptOperation);
        if (HandshakeError != Preview::Error::None || !Conn)
        {
            Raw->Close();
            co_return false;
        }
        if (static_cast<Preview::Vmess::Command>(Request.Cmd) == Preview::Vmess::Command::Udp)
        {
            co_await EchoDatagrams(Conn);
        }
        else
        {
            co_await EchoStream(Conn);
        }
        co_return true;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: listen address is not an IP literal\n");
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        auto Protocol = Tcp::v6();
        if (Address.is_v4())
        {
            Protocol = Tcp::v4();
        }
        Acceptor.open(Protocol, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: acceptor open: %s\n", Error.message().c_str());
            co_return 1;
        }
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: acceptor bind: %s\n", Error.message().c_str());
            co_return 1;
        }
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: acceptor listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Preview VMess server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);

        std::size_t Sessions = 0;
        while (Sessions < 2)
        {
            boost::system::error_code AcceptError;
            auto AcceptOperation = Acceptor.async_accept(
                Net::redirect_error(Net::use_awaitable, AcceptError));
            auto Socket = co_await std::move(AcceptOperation);
            if (AcceptError)
            {
                co_return 1;
            }
            if (co_await ServeConnection(std::move(Socket), OptionsValue))
            {
                ++Sessions;
            }
        }
        co_return 0;
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    Net::io_context Io;
    int ExitCode = 1;
    Net::co_spawn(
        Io,
        [OptionsValue, &Io, &ExitCode]() -> Net::awaitable<void>
        {
            auto Operation = RunServer(OptionsValue);
            if (OptionsValue.Mode == "client")
            {
                Operation = RunClient(OptionsValue);
            }
            ExitCode = co_await std::move(Operation);
            Io.stop();
        },
        [&Io](const std::exception_ptr &Exception)
        {
        if (Exception)
        {
                try
                {
                    std::rethrow_exception(Exception);
                }
                catch (const std::exception &Error)
                {
                    std::fprintf(stderr, "FAIL: VMess interop coroutine exception: %s\n", Error.what());
                }
                catch (...)
                {
                    std::fprintf(stderr, "FAIL: VMess interop coroutine exception: unknown\n");
                }
            }
            Io.stop();
        });
    Io.run();
    return ExitCode;
}
