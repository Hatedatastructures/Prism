/**
 * @file InteropPrismL4.cpp
 * @brief L4 生产对拍：Prism 客户端 → 生产 Prism 服务端
 * @details 当前 Prism Integration 客户端连接已启动的 Prism 服务端
 *          （build/src/Prism.exe），验证协议互通：
 *          - 协议：socks5 / vless / trojan / vmess
 *          - 模式：echo（正确凭据 + 回环 echo 校验）
 *                 authfail（错误凭据，期望握手失败或无回显；超时不算通过）
 *                 echoserver（仅启动固定端口 echo，供 SS2022 等对拍复用）
 *          - 目标：内嵌 TCP echo 服务器（Prism 反向拨号回本机）
 * @param -Address Prism 监听地址（默认 127.0.0.1:18081）
 * @param -Protocol 协议名（socks5|vless|trojan|vmess，必填；echoserver 模式忽略）
 * @param -Mode 测试模式（echo|authfail|echoserver，默认 echo）
 * @param -port echoserver 模式监听端口（默认 19090）
 */

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <thread>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    namespace Network = Prism::Network;
    namespace Shadowsocks2022 = Prism::Shadowsocks2022;
    namespace Socks5 = Prism::Socks5;
    namespace Trojan = Prism::Trojan;
    namespace Vless = Prism::Vless;
    namespace Vmess = Prism::Vmess;
    using Prism::Error;
    using Prism::SharedTransmission;

    using EchoDone = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct EchoOwner final
    {
        std::shared_ptr<Tcp::acceptor> Acceptor;
        std::shared_ptr<EchoDone> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    /// 与 configuration.json 一致的 UUID（VMess/VLESS）
    constexpr std::string_view UuidString = "123e4567-e89b-12d3-a456-426614174000";
    /// 与 configuration.json 一致的 SOCKS5 密码
    constexpr std::string_view SocksPassword = "prism";
    /// 与 configuration.json 一致的 Trojan 密码
    constexpr std::string_view TrojanPassword = "prism";
    /// 认证失败时使用的错误密码
    constexpr std::string_view WrongPassword = "wrong-password-123";
    /// 单次测试超时（authfail 模式：超时不作为拒绝证据，判定为 FAIL 并打印 WARN）
    constexpr std::chrono::milliseconds CaseTimeout{5000};
    /// 回显载荷
    const std::string Payload = "prism-l4-interop-payload-0123456789";

    /// 用例结果
    enum class CaseResult : std::uint8_t
    {
        EchoOk,
        HandshakeFailed,
        EchoFailed,
        TimedOut,
    };

    struct Options
    {
        std::string Address{"127.0.0.1:18081"};
        std::string Protocol;
        std::string Mode{"echo"};
        std::uint16_t EchoPort{19090};
        bool AuthFail{false};
    };

    /// 解析参数（-key value）
    auto ParseArgs(int argc, char *argv[]) -> Options
    {
        Options opts;
        for (int i = 1; i + 1 < argc; i += 2)
        {
            const std::string key = argv[i];
            const std::string val = argv[i + 1];
            if (key == "-addr")
            {
                opts.Address = val;
            }
            else if (key == "-proto")
            {
                opts.Protocol = val;
            }
            else if (key == "-mode")
            {
                opts.Mode = val;
            }
            else if (key == "-port")
            {
                opts.EchoPort = static_cast<std::uint16_t>(std::stoi(val));
            }
        }
        opts.AuthFail = (opts.Mode == "authfail");
        return opts;
    }

    /// 解析 "host:port"
    auto SplitHostPort(const std::string &Address) -> std::pair<std::string, std::uint16_t>
    {
        const auto colon = Address.find_last_of(':');
        if (colon == std::string::npos)
        {
            return {"", 0};
        }
        return {Address.substr(0, colon), static_cast<std::uint16_t>(std::stoi(Address.substr(colon + 1)))};
    }

    /// TCP 回显服务（detached，EOF 或错误即退出）
    auto EchoServer(Tcp::socket sock) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        boost::system::error_code ec;
        while (true)
        {
            const auto n = co_await sock.async_read_some(
                Net::buffer(buf), Net::redirect_error(Net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            co_await sock.async_write_some(Net::buffer(buf, n),
                                           Net::redirect_error(Net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
        }
        boost::system::error_code close_ec;
        sock.close(close_ec);
    }

    /// 接受循环：每个连接派生 echo 协程
    auto EchoAcceptorLoop(EchoOwner Owner) -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ec;
            auto sock = co_await Owner.Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, ec));
            if (ec)
            {
                co_return;
            }
            auto Failure = Owner.Failure;
            Net::co_spawn(
                Owner.Acceptor->get_executor(), EchoServer(std::move(sock)),
                [Failure](const std::exception_ptr &ErrorValue)
                {
                    if (ErrorValue && !*Failure)
                    {
                        *Failure = ErrorValue;
                    }
                });
        }
    }

    auto StartEchoOwner(Net::io_context &Io, const std::uint16_t Port = 0)
        -> EchoOwner
    {
        EchoOwner Owner;
        Owner.Acceptor = std::make_shared<Tcp::acceptor>(
            Io.get_executor(), Net::ip::tcp::endpoint(Net::ip::tcp::v4(), Port));
        Owner.Done = std::make_shared<EchoDone>(Io.get_executor(), 1);
        Owner.Failure = std::make_shared<std::exception_ptr>();
        Net::co_spawn(
            Io.get_executor(), EchoAcceptorLoop(Owner),
            [Owner](const std::exception_ptr &ErrorValue)
            {
                if (ErrorValue && !*Owner.Failure)
                {
                    *Owner.Failure = ErrorValue;
                }
                (void)Owner.Done->try_send(
                    boost::system::error_code{}, true);
            });
        return Owner;
    }

    auto StopEchoOwner(EchoOwner &Owner) -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        Owner.Acceptor->close(ErrorCode);
        (void)co_await Owner.Done->async_receive(Net::use_awaitable);
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
    }

    /// 解析 UUID 字符串为 16 字节
    auto ParseUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};
        if (!Vmess::ParseUuid(UuidString, out))
        {
            std::fprintf(stderr, "bad uuid string\n");
        }
        return out;
    }

    struct L4HandshakeRequest final
    {
        SharedTransmission Raw;
        std::uint16_t EchoPort;
        const Options &OptionsValue;
        const std::array<std::uint8_t, 16> &Uuid;
    };

    using L4HandshakeResult = std::expected<SharedTransmission, Prism::Fault::Failure>;

    auto ConnectSocks5(L4HandshakeRequest Request) -> Net::awaitable<L4HandshakeResult>
    {
        Socks5::ClientConfig Config;
        Config.EnableAuth = true;
        Config.Username = "prism";
        Config.Password = std::string(
            Request.OptionsValue.AuthFail ? WrongPassword : SocksPassword);
        auto Result = co_await Socks5::Connect(Socks5::ConnectParameters{
            std::move(Request.Raw), Config,
            Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", Request.EchoPort}});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        co_return SharedTransmission(std::move(*Result));
    }

    auto ConnectSs2022(L4HandshakeRequest Request) -> Net::awaitable<L4HandshakeResult>
    {
        constexpr std::array<std::uint8_t, 16> Psk{
            0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
            0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
        Shadowsocks2022::ClientConfig Config;
        Config.Psk = Psk;
        if (Request.OptionsValue.AuthFail)
        {
            Config.Psk.fill(0x77);
        }
        auto Result = co_await Shadowsocks2022::Connect(
            std::move(Request.Raw), Config,
            Shadowsocks2022::Address{
                Shadowsocks2022::AddressType::Ipv4, "127.0.0.1", Request.EchoPort});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        if (!*Result)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        co_return SharedTransmission(std::move(*Result));
    }

    auto ConnectVless(L4HandshakeRequest Request) -> Net::awaitable<L4HandshakeResult>
    {
        Vless::ClientConfig Config;
        Config.uuid = Request.Uuid;
        if (Request.OptionsValue.AuthFail)
        {
            Config.uuid.fill(0xAB);
        }
        auto Result = co_await Vless::Connect({
            std::move(Request.Raw), Config,
            Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", Request.EchoPort},
            Vless::Command::Tcp});
        if (!Result) co_return std::unexpected(Result.error());
        if (!*Result)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return SharedTransmission(std::move(*Result));
    }

    auto ConnectTrojan(L4HandshakeRequest Request) -> Net::awaitable<L4HandshakeResult>
    {
        Trojan::ClientConfig Config;
        Config.Password = std::string(
            Request.OptionsValue.AuthFail ? WrongPassword : TrojanPassword);
        auto Result = co_await Trojan::Connect({
            std::move(Request.Raw), Config,
            Trojan::Address{Trojan::AddressType::Ipv4, "127.0.0.1", Request.EchoPort},
            Trojan::Command::Connect});
        if (!Result) co_return std::unexpected(Result.error());
        if (!*Result)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return SharedTransmission(std::move(*Result));
    }

    auto ConnectVmess(L4HandshakeRequest Request) -> Net::awaitable<L4HandshakeResult>
    {
        Vmess::ClientConfig Config;
        Config.uuid = Request.Uuid;
        if (Request.OptionsValue.AuthFail)
        {
            Config.uuid.fill(0xCD);
        }
        auto Result = co_await Vmess::Connect(Vmess::ConnectParameters{
            std::move(Request.Raw), Config,
            Vmess::Address{Vmess::AddressType::Ipv4, "127.0.0.1", Request.EchoPort},
            Vmess::Command::Tcp});
        if (!Result) co_return std::unexpected(Result.error());
        if (!*Result)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        co_return SharedTransmission(std::move(*Result));
    }

    auto ConnectProtocol(L4HandshakeRequest Request)
        -> Net::awaitable<L4HandshakeResult>
    {
        if (Request.OptionsValue.Protocol == "socks5")
        {
            co_return co_await ConnectSocks5(std::move(Request));
        }
        if (Request.OptionsValue.Protocol == "ss2022")
        {
            co_return co_await ConnectSs2022(std::move(Request));
        }
        if (Request.OptionsValue.Protocol == "vless")
        {
            co_return co_await ConnectVless(std::move(Request));
        }
        if (Request.OptionsValue.Protocol == "trojan")
        {
            co_return co_await ConnectTrojan(std::move(Request));
        }
        if (Request.OptionsValue.Protocol == "vmess")
        {
            co_return co_await ConnectVmess(std::move(Request));
        }
        co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
    }

    /// 执行一次协议 Connect + 写载荷 + 读回显
    /// @return 用例结果（不打印；判定交给调用方）
    auto RunEchoCase(SharedTransmission Raw, const std::uint16_t EchoPort,
                     const Options &OptionsValue) -> Net::awaitable<CaseResult>
    {
        const auto Uuid = ParseUuid();
        auto ConnectResult = co_await ConnectProtocol(
            L4HandshakeRequest{std::move(Raw), EchoPort, OptionsValue, Uuid});
        if (!ConnectResult || !*ConnectResult)
        {
            co_return CaseResult::HandshakeFailed;
        }
        auto Proxy = std::move(*ConnectResult);
        auto &Carrier = static_cast<Prism::Transmission &>(*Proxy);
        const auto Written = co_await Carrier.WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        if (Written.Failure.Failed())
        {
            (void)Proxy->Close();
            co_return CaseResult::EchoFailed;
        }
        std::array<std::byte, 256> Buffer{};
        std::size_t Received = 0;
        while (Received < Payload.size())
        {
            const auto Part = co_await Carrier.ReadSome(
                std::span<std::byte>(Buffer).subspan(Received));
            if (Part.Failure.Failed() || Part.Bytes == 0)
            {
                break;
            }
            Received += Part.Bytes;
        }
        const auto EchoOk = Received == Payload.size() &&
                            std::memcmp(Buffer.data(), Payload.data(), Received) == 0;
        (void)Proxy->Close();
        co_return EchoOk ? CaseResult::EchoOk : CaseResult::EchoFailed;
    }

    struct L4AttemptRequest final
    {
        Net::any_io_executor Executor;
        const Options &OptionsValue;
        std::uint16_t EchoPort;
    };

    auto RunL4Attempt(L4AttemptRequest Request) -> Net::awaitable<CaseResult>
    {
        const auto [Host, Port] = SplitHostPort(Request.OptionsValue.Address);
        Network::Dialer::Dialer Dialer(Request.Executor);
        auto DialResult = co_await Dialer.Connect({Prism::Network::ParseHost(Host).value_or(Prism::Network::Host{}), Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: Prism L4 dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return CaseResult::HandshakeFailed;
        }
        co_return co_await RunEchoCase(
            std::move(*DialResult), Request.EchoPort, Request.OptionsValue);
    }

    /// 整个测试用例（带超时；超时取消挂起的连接）
    auto RunCase(Net::any_io_executor Executor, const Options &OptionsValue,
                 const std::uint16_t EchoPort) -> Net::awaitable<CaseResult>
    {
        using boost::asio::experimental::awaitable_operators::operator||;

        const auto [Host, Port] = SplitHostPort(OptionsValue.Address);
        if (Host.empty() || Port == 0)
        {
            co_return CaseResult::HandshakeFailed;
        }
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(CaseTimeout);
        const auto Result = co_await (
            RunL4Attempt(L4AttemptRequest{Executor, OptionsValue, EchoPort}) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            co_return CaseResult::TimedOut;
        }
        co_return std::get<0>(Result);
    }

    struct L4MainFlow final
    {
        Net::io_context &Io;
        Options OptionsValue;
        EchoOwner Echo;
        std::uint16_t EchoPort;
        CaseResult &Outcome;
    };

    auto RunL4MainFlow(L4MainFlow Flow) -> Net::awaitable<void>
    {
        std::exception_ptr FirstError;
        try
        {
            Flow.Outcome = co_await RunCase(
                Flow.Io.get_executor(), Flow.OptionsValue, Flow.EchoPort);
        }
        catch (...)
        {
            FirstError = std::current_exception();
        }
        try
        {
            co_await StopEchoOwner(Flow.Echo);
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
} // namespace

auto main(const int Argc, char *Argv[]) -> int
{
    const auto OptionsValue = ParseArgs(Argc, Argv);

    try
    {
        Net::io_context ioc;

        // echoserver 模式：只启动固定端口 echo 并常驻，供 SS2022 等对拍复用
        if (OptionsValue.Mode == "echoserver")
        {
            auto Echo = StartEchoOwner(ioc, OptionsValue.EchoPort);
            std::thread runner([&] { ioc.run(); });
            runner.detach();
            std::fprintf(stderr, "echo Server on 127.0.0.1:%u (Run until killed)\n",
                         static_cast<unsigned>(OptionsValue.EchoPort));
            for (;;)
            {
                std::this_thread::sleep_for(std::chrono::hours(1));
            }
        }

        if (OptionsValue.Protocol.empty() ||
            (OptionsValue.Protocol != "socks5" && OptionsValue.Protocol != "vless" &&
             OptionsValue.Protocol != "trojan" && OptionsValue.Protocol != "vmess" &&
             OptionsValue.Protocol != "ss2022"))
        {
            std::fprintf(stderr,
                         "usage: InteropPrismL4 -addr host:port -proto socks5|vless|trojan|vmess|ss2022 "
                         "[-mode echo|authfail] | -mode echoserver -port N\n");
            return 2;
        }

        // 内嵌 echo 服务器（Prism 反向拨号目标）
        auto Echo = StartEchoOwner(ioc);
        const auto EchoPort = Echo.Acceptor->local_endpoint().port();

        CaseResult outcome = CaseResult::TimedOut;
        std::exception_ptr Failure;
        Net::co_spawn(ioc, RunL4MainFlow(L4MainFlow{
            ioc, OptionsValue, std::move(Echo), EchoPort, outcome}),
            [&Failure](const std::exception_ptr &ErrorValue)
        {
            Failure = ErrorValue;
        });
        ioc.run();
        if (Failure)
        {
            std::fprintf(stderr, "FAIL: exception in case\n");
            return 1;
        }

        bool pass = false;
        if (OptionsValue.AuthFail)
        {
            if (outcome == CaseResult::TimedOut)
            {
                // 超时不能作为拒绝证据：服务端认证后挂死同样表现为超时
                std::fprintf(stderr,
                             "WARN: L4 interop %s (authfail): outcome=TimedOut, "
                             "cannot distinguish rejection from Server hang\n",
                             OptionsValue.Protocol.c_str());
            }
            else
            {
                pass = (outcome != CaseResult::EchoOk);
            }
        }
        else
        {
            pass = (outcome == CaseResult::EchoOk);
        }
        if (pass)
        {
            std::printf("PASS: L4 interop %s (%s)\n", OptionsValue.Protocol.c_str(), OptionsValue.Mode.c_str());
            return 0;
        }
        std::fprintf(stderr, "FAIL: L4 interop %s (%s): outcome=%d\n",
                     OptionsValue.Protocol.c_str(), OptionsValue.Mode.c_str(), static_cast<int>(outcome));
        return 1;
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", e.what());
        return 1;
    }
}
