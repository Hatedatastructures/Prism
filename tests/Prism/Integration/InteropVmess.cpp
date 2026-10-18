/**
 * @file InteropVmess.cpp
 * @brief Prism VMess 服务端与独立 sing-vmess 客户端的外部互操作端点
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
#include <variant>
#include <vector>

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Transport/Reliable.hpp>

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

    /** @brief 发送 VMess interop 负载并返回完整 typed 进度。 */
    [[nodiscard]] auto WriteVmessPayload(
        Prism::Vmess::SharedConn Conn,
        std::span<const std::byte> Payload) -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Progress{};
        while (Progress.Bytes < Payload.size())
        {
            const auto Remaining = Payload.subspan(Progress.Bytes);
            const auto Write = co_await Conn->WriteSome(Remaining);
            if (Write.Bytes > Remaining.size())
            {
                Progress.Failure = {Prism::Fault::Code::InvalidArgument, Write.Failure.Native};
                co_return Progress;
            }
            Progress.Bytes += Write.Bytes;
            Progress.Failure = Write.Failure;
            if (Progress.Failure.Failed())
            {
                co_return Progress;
            }
            if (Write.Bytes == 0)
            {
                Progress.Failure = {Prism::Fault::Code::WouldBlock};
                co_return Progress;
            }
        }
        co_return Progress;
    }

    /** @brief 读取固定长度 VMess echo 并保留部分字节和首个 Failure。 */
    [[nodiscard]] auto ReadVmessEcho(
        Prism::Vmess::SharedConn Conn,
        std::span<std::byte> Echo) -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Progress{};
        while (Progress.Bytes < Echo.size())
        {
            const auto Remaining = Echo.subspan(Progress.Bytes);
            const auto Read = co_await Conn->ReadSome(Remaining);
            if (Read.Bytes > Remaining.size())
            {
                Progress.Failure = {Prism::Fault::Code::InvalidArgument, Read.Failure.Native};
                co_return Progress;
            }
            Progress.Bytes += Read.Bytes;
            Progress.Failure = Read.Failure;
            if (Progress.Failure.Failed())
            {
                co_return Progress;
            }
            if (Read.Bytes == 0)
            {
                Progress.Failure = {Prism::Fault::Code::WouldBlock};
                co_return Progress;
            }
        }
        co_return Progress;
    }

    struct VmessClientRequest final
    {
        Prism::Network::Dialer::Dialer &Dialer;
        Prism::Network::Target DialTarget;
        Prism::Vmess::ClientConfig Config;
        Prism::Vmess::Address Target;
    };

    [[nodiscard]] auto RunTcpClient(VmessClientRequest Request) -> Net::awaitable<int>
    {
        auto DialResult = co_await Request.Dialer.Connect(Request.DialTarget);
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: VMess TCP dial: code=%d native=%s:%d\n",
                         static_cast<int>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
            co_return 1;
        }
        auto ConnectResult = co_await Prism::Vmess::Connect(
            Prism::Vmess::ConnectParameters{
                std::move(*DialResult), Request.Config, Request.Target,
                Prism::Vmess::Command::Tcp});
        if (!ConnectResult)
        {
            const auto Native = Prism::Fault::ToNative(ConnectResult.error());
            std::fprintf(stderr, "FAIL: VMess TCP handshake (%u): %s\n",
                         static_cast<unsigned>(ConnectResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Conn = std::move(*ConnectResult);
        constexpr std::string_view Text{"prism-vmess-external-tcp-payload"};
        const auto Payload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Text.data()), Text.size());
        const auto Write = co_await WriteVmessPayload(Conn, Payload);
        if (Write.Bytes != Payload.size() || Write.Failure.Failed())
        {
            Conn->Close();
            co_return 1;
        }
        std::vector<std::byte> Echo(Text.size());
        const auto Read = co_await ReadVmessEcho(Conn, Echo);
        if (Read.Bytes != Echo.size() || Read.Failure.Failed())
        {
            Conn->Close();
            co_return 1;
        }
        Conn->Close();
        if (std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: VMess TCP echo mismatch\n");
            co_return 1;
        }
        co_return 0;
    }

    [[nodiscard]] auto RunUdpClient(VmessClientRequest Request) -> Net::awaitable<int>
    {
        auto DialResult = co_await Request.Dialer.Connect(Request.DialTarget);
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: VMess UDP dial: code=%d native=%s:%d\n",
                         static_cast<int>(Failure.Code), Failure.Native.category().name(),
                         Failure.Native.value());
            co_return 1;
        }
        auto DatagramResult = co_await Prism::Vmess::ConnectPacket(
            std::move(*DialResult), Request.Config, Request.Target);
        if (!DatagramResult)
        {
            const auto Native = Prism::Fault::ToNative(DatagramResult.error());
            std::fprintf(stderr, "FAIL: VMess UDP handshake (%u): %s\n",
                         static_cast<unsigned>(DatagramResult.error().Code), Native.message().c_str());
            co_return 1;
        }
        auto Datagram = std::move(*DatagramResult);
        constexpr std::string_view Text{"prism-vmess-external-udp-payload"};
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size());
        const auto SendError = co_await Datagram->AsyncSendDatagram(Payload);
        if (SendError.Failure.Failed())
        {
            Datagram->Close();
            co_return 1;
        }
        std::vector<std::uint8_t> Echo;
        const auto ReceiveError = co_await Datagram->AsyncReceiveDatagram(Echo);
        const bool EchoMatches = ReceiveError.Failure.Succeeded() && Echo.size() == Payload.size() &&
            std::equal(Echo.begin(), Echo.end(), Payload.begin());
        Datagram->Close();
        if (!EchoMatches)
        {
            std::fprintf(stderr, "FAIL: VMess UDP echo mismatch\n");
            co_return 1;
        }
        co_return 0;
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
        Prism::Network::Dialer::Dialer Dialer(Executor);
        VmessClientRequest Request{
            Dialer,
            Prism::Network::Target{
                Prism::Network::ParseHost(Server->Host).value_or(Prism::Network::Host{}),
                Server->Port},
            Prism::Vmess::ClientConfig{OptionsValue.Uuid},
            Prism::Vmess::Address{Prism::Vmess::AddressType::Domain, "example.com", 443}};
        if (co_await RunTcpClient(Request) != 0 || co_await RunUdpClient(Request) != 0)
        {
            co_return 1;
        }
        std::printf("PASS: Prism VMess client -> sing-vmess reference server TCP+UDP\n");
        co_return 0;
    }

    [[nodiscard]] auto EchoStream(Prism::Vmess::SharedConn Conn) -> Net::awaitable<bool>
    {
        std::array<std::byte, 16 * 1024> Buffer{};
        while (true)
        {
            const auto Read = co_await Conn->ReadSome(Buffer);
            if (Read.Bytes > Buffer.size())
            {
                Conn->Close();
                co_return false;
            }
            std::size_t Offset = 0;
            while (Offset < Read.Bytes)
            {
                const auto WriteBuffer = std::span<const std::byte>(Buffer).subspan(Offset, Read.Bytes - Offset);
                const auto Written = co_await Conn->WriteSome(WriteBuffer);
                if (Written.Bytes > WriteBuffer.size())
                {
                    Conn->Close();
                    co_return false;
                }
                Offset += Written.Bytes;
                if (Written.Failure.Failed() || Written.Bytes == 0)
                {
                    Conn->Close();
                    co_return false;
                }
            }
            if (Read.Failure.Failed())
            {
                Conn->Close();
                co_return Read.Failure.Code == Prism::Fault::Code::Eof &&
                          !Read.Failure.Native;
            }
            if (Read.Bytes == 0)
            {
                Conn->Close();
                co_return false;
            }
        }
    }

    [[nodiscard]] auto EchoDatagrams(Prism::Vmess::SharedDgram Connection) -> Net::awaitable<void>
    {
        while (true)
        {
            std::vector<std::uint8_t> Payload;
            const auto Read = co_await Connection->AsyncReceiveDatagram(Payload);
            if (Read.Failure.Failed()) break;
            const auto Sent = co_await Connection->AsyncSendDatagram(Payload);
            if (Sent.Failure.Failed()) break;
        }
        Connection->Close();
    }

    [[nodiscard]] auto ServeConnection(Tcp::socket Socket, const Options &OptionsValue)
        -> Net::awaitable<bool>
    {
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        const Prism::Vmess::ServerConfig Config{OptionsValue.Uuid};
        auto AcceptOperation = Prism::Vmess::AcceptSession(Raw, Config);
        auto AcceptResult = co_await std::move(AcceptOperation);
        if (!AcceptResult)
        {
            const auto Native = Prism::Fault::ToNative(AcceptResult.error());
            const auto Close = Raw->Close();
            const auto Drain = co_await Raw->Activity()->Drain();
            if (!Close || !Drain) std::fprintf(stderr, "FAIL: VMess reject close drain\n");
            std::fprintf(stderr, "FAIL: VMess server handshake (%u): %s\n",
                         static_cast<unsigned>(AcceptResult.error().Code), Native.message().c_str());
            co_return false;
        }
        if (auto *Datagram = std::get_if<Prism::Vmess::AcceptedDatagram>(&*AcceptResult))
        {
            if (!Datagram->Connection)
            {
                const auto Close = Raw->Close();
                const auto Drain = co_await Raw->Activity()->Drain();
                if (!Close || !Drain)
                    std::fprintf(stderr, "FAIL: empty VMess datagram close drain\n");
                std::fprintf(stderr, "FAIL: VMess AcceptSession returned an empty datagram owner\n");
                co_return false;
            }
            co_await EchoDatagrams(std::move(Datagram->Connection));
            co_return true;
        }
        auto *Stream = std::get_if<Prism::Vmess::AcceptedConnection>(&*AcceptResult);
        if (!Stream || !Stream->Connection)
        {
            const auto Close = Raw->Close();
            const auto Drain = co_await Raw->Activity()->Drain();
            if (!Close || !Drain) std::fprintf(stderr, "FAIL: VMess stream close drain\n");
            std::fprintf(stderr, "FAIL: VMess AcceptSession returned an empty stream owner\n");
            co_return false;
        }
        co_return co_await EchoStream(std::move(Stream->Connection));
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
        std::printf("READY: Prism VMess server on %s\n", OptionsValue.Address.c_str());
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

    /** @brief 收口 VMess interop coroutine 的异常并停止驱动器。 */
    auto CompleteVmessInterop(
        Net::io_context& IoContext,
        const std::exception_ptr& Exception) -> void
    {
        if (Exception)
        {
            try
            {
                std::rethrow_exception(Exception);
            }
            catch (const std::exception& Error)
            {
                std::fprintf(stderr, "FAIL: VMess interop coroutine exception: %s\n", Error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "FAIL: VMess interop coroutine exception: unknown\n");
            }
        }
        IoContext.stop();
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
        [&Io](const std::exception_ptr& Exception)
        {
            CompleteVmessInterop(Io, Exception);
        });
    Io.run();
    return ExitCode;
}
