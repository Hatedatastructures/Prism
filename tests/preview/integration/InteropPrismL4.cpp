/**
 * @file InteropPrismL4.cpp
 * @brief L4 生产对拍：preview 客户端 → 生产 Prism 服务端
 * @details 用 tests/common 的 preview 协议客户端连接真实 psm 服务端
 *          （build/src/Prism.exe），验证协议互通：
 *          - 协议：socks5 / vless / trojan / vmess
 *          - 模式：echo（正确凭据 + 回环 echo 校验）
 *                 authfail（错误凭据，期望握手失败或无回显；超时不算通过）
 *                 echoserver（仅启动固定端口 echo，供 SS2022 等对拍复用）
 *          - 目标：内嵌 TCP echo 服务器（Prism 反向拨号回本机）
 * @param -addr Prism 监听地址（默认 127.0.0.1:18081）
 * @param -proto 协议名（socks5|vless|trojan|vmess，必填；echoserver 模式忽略）
 * @param -mode 测试模式（echo|authfail|echoserver，默认 echo）
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

#include <common/core/error.hpp>
#include <common/core/net/dialer/dialer.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/socks5/socks5.hpp>
#include <common/protocols/shadowsocks2022/shadowsocks2022.hpp>
#include <common/protocols/trojan/trojan.hpp>
#include <common/protocols/vless/vless.hpp>
#include <common/protocols/vmess/codec.hpp>
#include <common/protocols/vmess/vmess.hpp>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using namespace preview;

    /// 与 configuration.json 一致的 UUID（VMess/VLESS）
    constexpr std::string_view k_uuid_str = "123e4567-e89b-12d3-a456-426614174000";
    /// 与 configuration.json 一致的 SOCKS5 密码
    constexpr std::string_view k_socks_password = "prism";
    /// 与 configuration.json 一致的 Trojan 密码
    constexpr std::string_view k_trojan_password = "prism";
    /// 认证失败时使用的错误密码
    constexpr std::string_view k_wrong_password = "wrong-password-123";
    /// 单次测试超时（authfail 模式：超时不作为拒绝证据，判定为 FAIL 并打印 WARN）
    constexpr std::chrono::milliseconds k_case_timeout{5000};
    /// 回显载荷
    const std::string k_payload = "prism-l4-interop-payload-0123456789";

    /// 用例结果
    enum class case_result : std::uint8_t
    {
        echo_ok,
        handshake_failed,
        echo_failed,
        timed_out,
    };

    struct options
    {
        std::string addr{"127.0.0.1:18081"};
        std::string proto;
        std::string mode{"echo"};
        std::uint16_t echo_port{19090};
        bool auth_fail{false};
    };

    /// 解析参数（-key value）
    auto parse_args(int argc, char *argv[]) -> options
    {
        options opts;
        for (int i = 1; i + 1 < argc; i += 2)
        {
            const std::string key = argv[i];
            const std::string val = argv[i + 1];
            if (key == "-addr")
            {
                opts.addr = val;
            }
            else if (key == "-proto")
            {
                opts.proto = val;
            }
            else if (key == "-mode")
            {
                opts.mode = val;
            }
            else if (key == "-port")
            {
                opts.echo_port = static_cast<std::uint16_t>(std::stoi(val));
            }
        }
        opts.auth_fail = (opts.mode == "authfail");
        return opts;
    }

    /// 解析 "host:port"
    auto split_host_port(const std::string &addr) -> std::pair<std::string, std::uint16_t>
    {
        const auto colon = addr.find_last_of(':');
        if (colon == std::string::npos)
        {
            return {"", 0};
        }
        return {addr.substr(0, colon), static_cast<std::uint16_t>(std::stoi(addr.substr(colon + 1)))};
    }

    /// TCP 回显服务（detached，EOF 或错误即退出）
    auto echo_server(tcp::socket sock) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        boost::system::error_code ec;
        while (true)
        {
            const auto n = co_await sock.async_read_some(
                net::buffer(buf), net::redirect_error(net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            co_await sock.async_write_some(net::buffer(buf, n),
                                           net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
        }
        boost::system::error_code close_ec;
        sock.close(close_ec);
    }

    /// 接受循环：每个连接派生 echo 协程
    auto echo_acceptor_loop(std::shared_ptr<tcp::acceptor> acceptor) -> net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ec;
            auto sock = co_await acceptor->async_accept(
                net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return;
            }
            net::co_spawn(acceptor->get_executor(),
                          [sock = std::move(sock)]() mutable -> net::awaitable<void>
                          {
                              co_await echo_server(std::move(sock));
                          },
                          [](const std::exception_ptr &ep)
                          {
                              if (ep)
                              {
                                  std::fprintf(stderr, "echo server error\n");
                              }
                          });
        }
    }

    /// 解析 UUID 字符串为 16 字节
    auto parse_uuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> out{};
        if (!vmess::parse_uuid(k_uuid_str, out))
        {
            std::fprintf(stderr, "bad uuid string\n");
        }
        return out;
    }

    /// 执行一次协议 connect + 写载荷 + 读回显
    /// @return 用例结果（不打印；判定交给调用方）
    auto run_echo_case(shared_transmission raw, const std::uint16_t echo_port,
                       const options &opts) -> net::awaitable<case_result>
    {
        const auto uuid = parse_uuid();
        error err{error::none};
        shared_transmission proxy;

        if (opts.proto == "socks5")
        {
            socks5::client_config cfg;
            cfg.enable_auth = true;
            cfg.username = "prism";
            cfg.password = opts.auth_fail ? std::string(k_wrong_password) : std::string(k_socks_password);
            auto [e, c] = co_await socks5::connect(
                std::move(raw), cfg,
                socks5::address{socks5::address_type::ipv4, "127.0.0.1", echo_port});
            err = e;
            proxy = std::move(c);
        }
        else if (opts.proto == "ss2022")
        {
            // 标准配置 PSK：base64 "5n5ESu953i/pjIp02oZvHA==" 解码（与 Prism/configuration.json 一致）
            constexpr std::array<std::uint8_t, 16> psk{
                0xE6, 0x7E, 0x44, 0x4A, 0xEF, 0x79, 0xDE, 0x2F,
                0xE9, 0x8C, 0x8A, 0x74, 0xDA, 0x86, 0x6F, 0x1C};
            shadowsocks2022::client_config cfg;
            cfg.use_psk = true;
            if (opts.auth_fail)
            {
                cfg.psk.fill(0x77);
            }
            else
            {
                cfg.psk = psk;
            }
            auto [e, c] = co_await shadowsocks2022::connect(
                std::move(raw), cfg,
                shadowsocks2022::address{shadowsocks2022::address_type::ipv4, "127.0.0.1", echo_port});
            err = e;
            proxy = std::move(c);
        }
        else if (opts.proto == "vless")
        {
            vless::client_config cfg;
            std::array<std::uint8_t, 16> bad_uuid{};
            bad_uuid.fill(0xAB);
            cfg.uuid = opts.auth_fail ? bad_uuid : uuid;
            auto [e, c] = co_await vless::connect(
                std::move(raw), cfg,
                vless::address{vless::address_type::ipv4, "127.0.0.1", echo_port},
                vless::command::tcp);
            err = e;
            proxy = std::move(c);
        }
        else if (opts.proto == "trojan")
        {
            trojan::client_config cfg;
            cfg.password = opts.auth_fail ? std::string(k_wrong_password) : std::string(k_trojan_password);
            auto [e, c] = co_await trojan::connect(
                std::move(raw), cfg,
                trojan::address{trojan::address_type::ipv4, "127.0.0.1", echo_port},
                trojan::command::connect);
            err = e;
            proxy = std::move(c);
        }
        else if (opts.proto == "vmess")
        {
            vmess::client_config cfg;
            std::array<std::uint8_t, 16> bad_uuid{};
            bad_uuid.fill(0xCD);
            cfg.uuid = opts.auth_fail ? bad_uuid : uuid;
            auto [e, c] = co_await vmess::connect(
                std::move(raw), cfg,
                vmess::address{vmess::address_type::ipv4, "127.0.0.1", echo_port},
                vmess::command::tcp);
            err = e;
            proxy = std::move(c);
        }
        else
        {
            co_return case_result::handshake_failed;
        }

        if (err != error::none || !proxy)
        {
            co_return case_result::handshake_failed;
        }

        std::error_code ec;
        co_await proxy->async_write(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(k_payload.data()), k_payload.size()),
            ec);
        if (ec)
        {
            proxy->close();
            co_return case_result::echo_failed;
        }

        std::array<std::byte, 256> buf{};
        std::size_t got = 0;
        while (got < k_payload.size())
        {
            const auto n = co_await proxy->async_read_some(
                std::span<std::byte>(buf).subspan(got), ec);
            if (ec || n == 0)
            {
                break;
            }
            got += n;
        }

        const auto ok = (got == k_payload.size()) &&
                        (std::memcmp(buf.data(), k_payload.data(), got) == 0);
        proxy->close();
        co_return ok ? case_result::echo_ok : case_result::echo_failed;
    }

    /// 整个测试用例（带超时；超时取消挂起的连接）
    auto run_case(net::any_io_executor ex, const options &opts,
                  const std::uint16_t echo_port) -> net::awaitable<case_result>
    {
        using boost::asio::experimental::awaitable_operators::operator||;

        const auto [host, port] = split_host_port(opts.addr);
        if (host.empty() || port == 0)
        {
            co_return case_result::handshake_failed;
        }

        auto do_test = [&]() -> net::awaitable<case_result>
        {
            std::error_code ec;
            network::dialer::dialer dialer(ex);
            auto raw = co_await dialer.connect(host, port, ec);
            if (ec || !raw)
            {
                co_return case_result::handshake_failed;
            }
            co_return co_await run_echo_case(std::move(raw), echo_port, opts);
        };

        net::steady_timer watchdog(ex);
        watchdog.expires_after(k_case_timeout);
        const auto result = co_await (do_test() || watchdog.async_wait(net::use_awaitable));
        if (result.index() == 1)
        {
            co_return case_result::timed_out;
        }
        co_return std::get<0>(result);
    }
} // namespace

int main(const int argc, char *argv[])
{
    const auto opts = parse_args(argc, argv);

    try
    {
        net::io_context ioc;

        // echoserver 模式：只启动固定端口 echo 并常驻，供 SS2022 等对拍复用
        if (opts.mode == "echoserver")
        {
            auto acceptor = std::make_shared<tcp::acceptor>(
                ioc.get_executor(), tcp::endpoint(tcp::v4(), opts.echo_port));
            net::co_spawn(ioc.get_executor(), echo_acceptor_loop(acceptor),
                          [](const std::exception_ptr &ep)
                          {
                              if (ep)
                              {
                                  std::fprintf(stderr, "acceptor loop error\n");
                              }
                          });
            std::thread runner([&] { ioc.run(); });
            runner.detach();
            std::fprintf(stderr, "echo server on 127.0.0.1:%u (run until killed)\n",
                         static_cast<unsigned>(opts.echo_port));
            for (;;)
            {
                std::this_thread::sleep_for(std::chrono::hours(1));
            }
        }

        if (opts.proto.empty() ||
            (opts.proto != "socks5" && opts.proto != "vless" &&
             opts.proto != "trojan" && opts.proto != "vmess" &&
             opts.proto != "ss2022"))
        {
            std::fprintf(stderr,
                         "usage: InteropPrismL4 -addr host:port -proto socks5|vless|trojan|vmess|ss2022 "
                         "[-mode echo|authfail] | -mode echoserver -port N\n");
            return 2;
        }

        // 内嵌 echo 服务器（Prism 反向拨号目标）
        auto acceptor = std::make_shared<tcp::acceptor>(
            ioc.get_executor(), tcp::endpoint(tcp::v4(), 0));
        const auto echo_port = acceptor->local_endpoint().port();
        net::co_spawn(ioc.get_executor(), echo_acceptor_loop(acceptor),
                      [](const std::exception_ptr &ep)
                      {
                          if (ep)
                          {
                              std::fprintf(stderr, "acceptor loop error\n");
                          }
                      });

        case_result outcome = case_result::timed_out;
        net::co_spawn(ioc, [&]() -> net::awaitable<void>
        {
            outcome = co_await run_case(ioc.get_executor(), opts, echo_port);
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
        if (opts.auth_fail)
        {
            if (outcome == case_result::timed_out)
            {
                // 超时不能作为拒绝证据：服务端认证后挂死同样表现为超时
                std::fprintf(stderr,
                             "WARN: L4 interop %s (authfail): outcome=timed_out, "
                             "cannot distinguish rejection from server hang\n",
                             opts.proto.c_str());
            }
            else
            {
                pass = (outcome != case_result::echo_ok);
            }
        }
        else
        {
            pass = (outcome == case_result::echo_ok);
        }
        if (pass)
        {
            std::printf("PASS: L4 interop %s (%s)\n", opts.proto.c_str(), opts.mode.c_str());
            return 0;
        }
        std::fprintf(stderr, "FAIL: L4 interop %s (%s): outcome=%d\n",
                     opts.proto.c_str(), opts.mode.c_str(), static_cast<int>(outcome));
        return 1;
    }
    catch (const std::exception &e)
    {
        std::fprintf(stderr, "FAIL: exception: %s\n", e.what());
        return 1;
    }
}
