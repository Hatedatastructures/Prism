/**
 * @file InteropPrismL4.cpp
 * @brief L4 生产对拍：Preview 客户端 → 生产 Prism 服务端
 * @details 用 tests/common 的 Preview 协议客户端连接真实 psm 服务端
 *          （Build/src/Prism.exe），验证协议互通：
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
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <thread>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Net/Dialer/Dialer.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>

namespace
{
    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    namespace Network = Preview::Network;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Vless = Preview::Vless;
    namespace Vmess = Preview::Vmess;
    using Preview::Error;
    using Preview::SharedTransmission;

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
    auto EchoAcceptorLoop(std::shared_ptr<Tcp::acceptor> acceptor) -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ec;
            auto sock = co_await acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, ec));
            if (ec)
            {
                co_return;
            }
            Net::co_spawn(acceptor->get_executor(),
                          [sock = std::move(sock)]() mutable -> Net::awaitable<void>
                          {
                              co_await EchoServer(std::move(sock));
                          },
                          [](const std::exception_ptr &ep)
                          {
                              if (ep)
                              {
                                  std::fprintf(stderr, "echo Server Error\n");
                              }
                          });
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

    /// 执行一次协议 Connect + 写载荷 + 读回显
    /// @return 用例结果（不打印；判定交给调用方）
    auto RunEchoCase(SharedTransmission raw, const std::uint16_t EchoPort,
                       const Options &opts) -> Net::awaitable<CaseResult>
    {
        const auto uuid = ParseUuid();
        Error err{Error::None};
        SharedTransmission proxy;

        if (opts.Protocol == "socks5")
        {
            Socks5::ClientConfig cfg;
            cfg.EnableAuth = true;
            cfg.username = "prism";
            if (opts.AuthFail)
            {
                cfg.password = std::string(WrongPassword);
            }
            else
            {
                cfg.password = std::string(SocksPassword);
            }
            auto [e, c] = co_await Socks5::Connect(
                std::move(raw), cfg,
                Socks5::Address{Socks5::AddressType::Ipv4, "127.0.0.1", EchoPort});
            err = e;
            proxy = std::move(c);
        }
        else if (opts.Protocol == "ss2022")
        {
            // 标准配置 PSK：base64 "5n5ESu953i/pjIp02oZvHA==" 解码（与 Prism/configuration.json 一致）
            constexpr std::array<std::uint8_t, 16> psk{
                0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
            Shadowsocks2022::ClientConfig cfg;
            cfg.UsePsk = true;
            if (opts.AuthFail)
            {
                cfg.Psk.fill(0x77);
            }
            else
            {
                cfg.Psk = psk;
            }
            auto [e, c] = co_await Shadowsocks2022::Connect(
                std::move(raw), cfg,
                Shadowsocks2022::Address{Shadowsocks2022::AddressType::Ipv4, "127.0.0.1", EchoPort});
            err = e;
            proxy = std::move(c);
        }
        else if (opts.Protocol == "vless")
        {
            Vless::ClientConfig cfg;
            std::array<std::uint8_t, 16> bad_uuid{};
            bad_uuid.fill(0xAB);
            if (opts.AuthFail)
            {
                cfg.uuid = bad_uuid;
            }
            else
            {
                cfg.uuid = uuid;
            }
            auto [e, c] = co_await Vless::Connect({
                std::move(raw), cfg,
                Vless::Address{Vless::AddressType::Ipv4, "127.0.0.1", EchoPort},
                Vless::Command::Tcp});
            err = e;
            proxy = std::move(c);
        }
        else if (opts.Protocol == "trojan")
        {
            Trojan::ClientConfig cfg;
            if (opts.AuthFail)
            {
                cfg.password = std::string(WrongPassword);
            }
            else
            {
                cfg.password = std::string(TrojanPassword);
            }
            auto [e, c] = co_await Trojan::Connect({
                std::move(raw), cfg,
                Trojan::Address{Trojan::AddressType::Ipv4, "127.0.0.1", EchoPort},
                Trojan::Command::Connect});
            err = e;
            proxy = std::move(c);
        }
        else if (opts.Protocol == "vmess")
        {
            Vmess::ClientConfig cfg;
            std::array<std::uint8_t, 16> bad_uuid{};
            bad_uuid.fill(0xCD);
            if (opts.AuthFail)
            {
                cfg.uuid = bad_uuid;
            }
            else
            {
                cfg.uuid = uuid;
            }
            auto [e, c] = co_await Vmess::Connect({
                std::move(raw), cfg,
                Vmess::Address{Vmess::AddressType::Ipv4, "127.0.0.1", EchoPort},
                static_cast<std::uint8_t>(Vmess::Command::Tcp)});
            err = e;
            proxy = std::move(c);
        }
        else
        {
            co_return CaseResult::HandshakeFailed;
        }

        if (err != Error::None || !proxy)
        {
            co_return CaseResult::HandshakeFailed;
        }

        std::error_code ec;
        co_await proxy->AsyncWrite(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()),
            ec);
        if (ec)
        {
            proxy->Close();
            co_return CaseResult::EchoFailed;
        }

        std::array<std::byte, 256> buf{};
        std::size_t got = 0;
        while (got < Payload.size())
        {
            const auto n = co_await proxy->async_read_some(
                std::span<std::byte>(buf).subspan(got), ec);
            if (ec || n == 0)
            {
                break;
            }
            got += n;
        }

        const auto Ok = (got == Payload.size()) &&
                        (std::memcmp(buf.data(), Payload.data(), got) == 0);
        proxy->Close();
        if (Ok)
        {
            co_return CaseResult::EchoOk;
        }
        co_return CaseResult::EchoFailed;
    }

    /// 整个测试用例（带超时；超时取消挂起的连接）
    auto RunCase(Net::any_io_executor ex, const Options &opts,
                  const std::uint16_t EchoPort) -> Net::awaitable<CaseResult>
    {
        using boost::asio::experimental::awaitable_operators::operator||;

        const auto [host, port] = SplitHostPort(opts.Address);
        if (host.empty() || port == 0)
        {
            co_return CaseResult::HandshakeFailed;
        }

        auto do_test = [&]() -> Net::awaitable<CaseResult>
        {
            std::error_code ec;
            Network::Dialer::Dialer Dialer(ex);
            auto raw = co_await Dialer.Connect(host, port, ec);
            if (ec || !raw)
            {
                co_return CaseResult::HandshakeFailed;
            }
            co_return co_await RunEchoCase(std::move(raw), EchoPort, opts);
        };

        Net::steady_timer watchdog(ex);
        watchdog.expires_after(CaseTimeout);
        const auto Result = co_await (do_test() || watchdog.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            co_return CaseResult::TimedOut;
        }
        co_return std::get<0>(Result);
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
            auto acceptor = std::make_shared<Tcp::acceptor>(
                ioc.get_executor(), Net::ip::tcp::endpoint(Net::ip::tcp::v4(), OptionsValue.EchoPort));
            Net::co_spawn(ioc.get_executor(), EchoAcceptorLoop(acceptor),
                          [](const std::exception_ptr &ep)
                          {
                              if (ep)
                              {
                                  std::fprintf(stderr, "acceptor loop Error\n");
                              }
                          });
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
        auto acceptor = std::make_shared<Tcp::acceptor>(
            ioc.get_executor(), Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto EchoPort = acceptor->local_endpoint().port();
        Net::co_spawn(ioc.get_executor(), EchoAcceptorLoop(acceptor),
                      [](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              std::fprintf(stderr, "acceptor loop Error\n");
                          }
                      });

        CaseResult outcome = CaseResult::TimedOut;
        Net::co_spawn(ioc, [&]() -> Net::awaitable<void>
        {
            outcome = co_await RunCase(ioc.get_executor(), OptionsValue, EchoPort);
            ioc.stop();
        }, [](const std::exception_ptr &ep)
        {
            if (ep)
            {
                std::fprintf(stderr, "FAIL: exception in case\n");
            }
        });
        ioc.run();

        boost::system::error_code close_ec;
        acceptor->close(close_ec);

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
