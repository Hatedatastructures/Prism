/**
 * @file RuntimeTestHelpers.hpp
 * @brief runtime E2E 测试公共样板（RunCoro / echo 上游 / 链路状态等）
 * @details 收敛 tests/preview/core/runtime 下 19 个测试文件的逐字重复样板。
 *          仅测试代码使用，不属于生产库；命名空间与 TestRunner/MockTransport
 *          同层（Preview::Testing），以 <common/RuntimeTestHelpers.hpp> 引用。
 * @note AcceptEchoUpstream 的 acceptor 以 shared_ptr 捕获进 detached 协程——
 *       禁止退回局部变量 + 引用捕获的写法（函数返回即悬垂，use-after-scope）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Net/Dialer/Dialer.hpp>
#include <common/Core/Transmission.hpp>

namespace Preview::Testing
{
    namespace net = boost::asio;

    /**
     * @brief 驱动协程直至完成（异常暂存，ioc.run() 返回后透传）
     * @param ioc 驱动用的 io_context
     * @param coro 待驱动的协程
     * @note 异常不得在完成回调内重抛——会冲出 ioc.run() 导致 std::terminate。
     */
    inline auto RunCoro(net::io_context &ioc, auto coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /**
     * @brief TCP echo 服务器：读到的数据原样写回（循环直至 EOF/错误）
     * @param sock 已接受的连接（所有权移交）
     */
    inline auto TcpEchoServer(net::ip::tcp::socket Sock) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> buf{};
        boost::system::error_code ec;
        while (true)
        {
            const auto N = co_await Sock.async_read_some(
                net::buffer(buf), net::redirect_error(net::use_awaitable, ec));
            if (ec || N == 0)
            {
                break;
            }
            co_await Sock.async_write_some(net::buffer(buf, N),
                                           net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
        }
    }

    /**
     * @brief UDP echo 服务器：收到的数据报原样回发来源端点
     * @param sock 已绑定的 UDP socket（所有权移交）
     */
    inline auto UdpEchoServer(net::ip::udp::socket Sock) -> net::awaitable<void>
    {
        std::array<std::byte, 65535> buf{};
        boost::system::error_code ec;
        while (true)
        {
            net::ip::udp::endpoint src;
            const auto N = co_await Sock.async_receive_from(
                net::buffer(buf), src, net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
            co_await Sock.async_send_to(net::buffer(buf, N), src,
                                        net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                break;
            }
        }
    }

    /**
     * @brief 启动回环 echo 上游（accept 循环，每连接一个 echo 协程）
     * @param ioc 驱动 io_context
     * @return 监听端口
     * @note acceptor 以 shared_ptr 按值捕获进 detached 协程，协程存活期间
     *       对象不析构——禁止改回局部变量 + 引用捕获（use-after-scope）。
     */
    [[nodiscard]] inline auto StartTcpEchoUpstream(net::io_context &ioc) -> std::uint16_t
    {
        auto Acc = std::make_shared<net::ip::tcp::acceptor>(
            ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto Port = Acc->local_endpoint().port();
        net::co_spawn(
            Acc->get_executor(),
            [Acc]() -> net::awaitable<void>
            {
                while (true)
                {
                    boost::system::error_code ec;
                    auto Sock = co_await Acc->async_accept(
                        net::redirect_error(net::use_awaitable, ec));
                    if (ec)
                    {
                        co_return;
                    }
                    net::co_spawn(Acc->get_executor(), TcpEchoServer(std::move(Sock)),
                                  net::detached);
                }
            },
            net::detached);
        return Port;
    }

    /**
     * @brief 回环上游 accept 循环（调用方持有 acceptor；每连接一个 echo 协程）
     * @param acceptor 调用方创建并持有的监听器（生命周期覆盖整个协程）
     * @note detached 派发时必须保证 acceptor 存活至 ioc.run() 结束
     *       （TEST 函数体局部声明即可）；或改用 StartTcpEchoUpstream。
     */
    inline auto AcceptEchoLoop(net::ip::tcp::acceptor &acceptor) -> net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ec;
            auto Sock =
                co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return;
            }
            co_await TcpEchoServer(std::move(Sock));
        }
    }

    /**
     * @brief 上游：接受后立即关闭（模拟上游中断）
     * @param acceptor 调用方持有监听器
     */
    inline auto AcceptAndClose(net::ip::tcp::acceptor &acceptor) -> net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ec;
            auto Sock =
                co_await acceptor.async_accept(net::redirect_error(net::use_awaitable, ec));
            if (ec)
            {
                co_return;
            }
            Sock.close();
        }
    }

    /**
     * @brief 半关闭尾部读取：与看门狗竞速，超时兜底关闭避免挂死
     * @param sock 数据面传输
     * @param buf 读取缓冲
     * @param ec 错误码输出（超时为 timed_out）
     * @return 实际读取字节数（超时为 0）
     */
    inline auto TailReadGuarded(const Preview::SharedTransmission &Sock,
                                  std::span<std::byte> buf, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        net::steady_timer wd(Sock->Executor());
        wd.expires_after(std::chrono::milliseconds(500));
        auto Result =
            co_await (Sock->async_read_some(buf, ec) || wd.async_wait(net::use_awaitable));
        if (Result.index() == 1)
        {
            Sock->Close();
            ec = std::make_error_code(std::errc::timed_out);
            co_return 0;
        }
        co_return std::get<0>(std::move(Result));
    }

    /**
     * @struct ChainState
     * @brief 协议纵向链路测试共享状态（记录客户端请求目标 + echo 端口）
     */
    struct ChainState
    {
        net::any_io_executor executor;      ///< 拨号执行器
        std::uint16_t EchoPort{0};         ///< 回环上游端口
        std::string RequestedHost;         ///< 客户端请求的目标 host
        std::string RequestedPort;         ///< 客户端请求的目标 port
    };

    using ChainStatePtr = std::shared_ptr<ChainState>;

    /**
     * @brief 连接纵向链路测试的回环上游（记录请求目标后拨 127.0.0.1:EchoPort）
     * @param state 共享状态（请求目标写入 Requested_*）
     * @param target 客户端请求的目标
     * @return 拨号结果（失败为 unreachable）
     */
    [[nodiscard]] inline auto DialUpstream(const ChainStatePtr &state,
                                            const Preview::Network::Target &target)
        -> net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
    {
        state->RequestedHost = target.Host;
        state->RequestedPort = target.Port;
        std::error_code ec;
        Preview::Network::Dialer::Dialer Dialer(state->executor);
        auto Upstream = co_await Dialer.Connect("127.0.0.1", state->EchoPort, ec);
        if (ec || !Upstream)
        {
            co_return std::pair{Preview::Fault::Code::HostNoreply,
                                Preview::SharedTransmission{}};
        }
        co_return std::pair{Preview::Fault::Code::Success, std::move(Upstream)};
    }

    /**
     * @struct ConnectResult
     * @brief 纵向链路运行结果（错误码 + 回显数据 + 上游记录的请求目标）
     */
    struct ConnectResult
    {
        Preview::Error Err{Preview::Error::None}; ///< 握手/数据面错误码
        std::string Echo;                         ///< 回显数据
        std::string Host;                         ///< 上游记录的请求 host
        std::string Port;                         ///< 上游记录的请求 port
    };

    /**
     * @struct TrafficRecorder
     * @brief 流量统计桩（校验 relay/udp 数据面结束后上报）
     */
    struct TrafficRecorder : Preview::Middleware::Context::TrafficSink
    {
        std::string Identity; ///< 最近一次上报的身份
        std::size_t Up{0};    ///< 累计上行字节
        std::size_t Down{0};  ///< 累计下行字节
        int Calls{0};         ///< 上报次数

        void Report(std::string_view id, std::size_t u, std::size_t d) override
        {
            Identity = std::string(id);
            Up += u;
            Down += d;
            ++Calls;
        }
    };

    /// 固定测试 UUID 字节数（vless/vmess 通用 16 字节）
    inline constexpr std::size_t UuidLen = 16;

    /**
     * @brief 构造固定测试 UUID（字节填充 1..16，确定性）
     */
    [[nodiscard]] inline auto MakeUuid() -> std::array<std::uint8_t, UuidLen>
    {
        std::array<std::uint8_t, UuidLen> u{};
        for (std::size_t I = 0; I < u.size(); ++I)
        {
            u[I] = static_cast<std::uint8_t>(I + 1);
        }
        return u;
    }

    /**
     * @brief 字节数组转十六进制字符串（VMess/VLESS 认证身份格式）
     * @param bytes 输入字节
     * @return 小写十六进制串（长度 ×2）
     */
    [[nodiscard]] inline auto ToHex(const std::array<std::uint8_t, UuidLen> &bytes)
        -> std::string
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out(bytes.size() * 2, '0');
        for (std::size_t I = 0; I < bytes.size(); ++I)
        {
            out[I * 2] = digits[bytes[I] >> 4];
            out[I * 2 + 1] = digits[bytes[I] & 0x0f];
        }
        return out;
    }
} // namespace Preview::Testing
