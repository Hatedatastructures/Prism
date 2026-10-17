/**
 * @file RuntimeTestHelpers.hpp
 * @brief runtime E2E 测试公共样板（RunCoro / echo 上游 / 链路状态等）
 * @details 为当前 Runtime 和协议集成测试共享真实 echo 与拥有型链路状态。
 *          仅测试代码使用，不属于生产库；Runtime fixtures 位于 Preview::Testing，
 *          与 Psm::Testing::ProductionMockTransport 明确分属两套类型体系。
 * @note AcceptEchoUpstream 的 acceptor 以 shared_ptr 捕获进 detached 协程——
 *       禁止退回局部变量 + 引用捕获的写法（函数返回即悬垂，use-after-scope）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/write.hpp>
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
#include <variant>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>

namespace Preview::Testing
{
    namespace net = boost::asio;

    /**
     * @brief 驱动协程直至完成（异常暂存，Ioc.run() 返回后透传）
     * @param Ioc 驱动用的 io_context
     * @param Coro 待驱动的协程
     * @note 异常不得在完成回调内重抛——会冲出 Ioc.run() 导致 std::terminate。
     */
    inline auto RunCoro(net::io_context &Ioc, auto Coro) -> void
    {
        std::exception_ptr Exception;
        net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error) { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief TCP echo 服务器：读到的数据原样写回（循环直至 EOF/错误）
     * @param Sock 已接受的连接（所有权移交）
     */
    inline auto TcpEchoServer(net::ip::tcp::socket Sock) -> net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        boost::system::error_code ErrorCode;
        while (true)
        {
            const auto N = co_await Sock.async_read_some(
                net::buffer(Buffer), net::redirect_error(net::use_awaitable, ErrorCode));
            if (N != 0)
            {
                boost::system::error_code WriteError;
                co_await net::async_write(Sock, net::buffer(Buffer, N),
                    net::redirect_error(net::use_awaitable, WriteError));
                if (WriteError)
                {
                    break;
                }
            }
            if (ErrorCode || N == 0)
            {
                break;
            }
        }
    }

    /**
     * @brief UDP echo 服务器：收到的数据报原样回发来源端点
     * @param Sock 已绑定的 UDP socket（所有权移交）
     */
    inline auto UdpEchoServer(net::ip::udp::socket Sock) -> net::awaitable<void>
    {
        std::array<std::byte, 65535> Buffer{};
        boost::system::error_code ErrorCode;
        while (true)
        {
            net::ip::udp::endpoint Source;
            const auto N = co_await Sock.async_receive_from(
                net::buffer(Buffer), Source, net::redirect_error(net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                break;
            }
            co_await Sock.async_send_to(net::buffer(Buffer, N), Source,
                                        net::redirect_error(net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                break;
            }
        }
    }

    /**
     * @brief 运行共享 acceptor 的 TCP echo 接受循环
     * @param Acc 由协程持有的监听器
     * @details 每条连接派发一个独立 echo 协程；共享所有权覆盖 detached 循环的生命周期。
     */
    inline auto TcpEchoAcceptLoop(std::shared_ptr<net::ip::tcp::acceptor> Acc)
        -> net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ErrorCode;
            auto Sock = co_await Acc->async_accept(
                net::redirect_error(net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            net::co_spawn(Acc->get_executor(), TcpEchoServer(std::move(Sock)), net::detached);
        }
    }

    /**
     * @brief 启动回环 echo 上游（accept 循环，每连接一个 echo 协程）
     * @param Ioc 驱动 io_context
     * @return 监听端口
     * @note acceptor 由 detached 接受协程按值持有，避免函数返回后监听器悬垂。
     */
    [[nodiscard]] inline auto StartTcpEchoUpstream(net::io_context &Ioc) -> std::uint16_t
    {
        auto Acc = std::make_shared<net::ip::tcp::acceptor>(
            Ioc, net::ip::tcp::endpoint(net::ip::tcp::v4(), 0));
        const auto Port = Acc->local_endpoint().port();
        net::co_spawn(Acc->get_executor(), TcpEchoAcceptLoop(Acc), net::detached);
        return Port;
    }

    /**
     * @brief 回环上游 accept 循环（调用方持有 acceptor；每连接一个 echo 协程）
     * @param Acceptor 调用方创建并持有的监听器（生命周期覆盖整个协程）
     * @note detached 派发时必须保证 acceptor 存活至 Ioc.run() 结束
     *       （TEST 函数体局部声明即可）；或改用 StartTcpEchoUpstream。
     */
    inline auto AcceptEchoLoop(net::ip::tcp::acceptor &Acceptor) -> net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ErrorCode;
            auto Sock =
                co_await Acceptor.async_accept(net::redirect_error(net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            co_await TcpEchoServer(std::move(Sock));
        }
    }

    /**
     * @brief 上游：接受后立即关闭（模拟上游中断）
     * @param Acceptor 调用方持有监听器
     */
    inline auto AcceptAndClose(net::ip::tcp::acceptor &Acceptor) -> net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code ErrorCode;
            auto Sock =
                co_await Acceptor.async_accept(net::redirect_error(net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                co_return;
            }
            Sock.close();
        }
    }

    /**
     * @brief 半关闭尾部读取：与看门狗竞速，超时兜底关闭避免挂死
     * @param Sock 数据面传输
     * @param Buffer 读取缓冲
     * @param ErrorCode 错误码输出（超时为 timed_out）
     * @return 实际读取字节数（超时为 0）
     */
    struct TailReadOutcome final
    {
        bool TimedOut{false};
        Preview::IoResult Result{};
    };

    /** @brief 返回尾部读取的 typed 结果；超时与 peer close 保持可区分。 */
    inline auto TailReadOutcomeGuarded(const Preview::SharedTransmission &Sock,
                                       std::span<std::byte> Buffer)
        -> net::awaitable<TailReadOutcome>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        net::steady_timer Watchdog(Sock->Executor());
        Watchdog.expires_after(std::chrono::milliseconds(500));
        auto Result =
            co_await (Sock->ReadSome(Buffer) || Watchdog.async_wait(net::use_awaitable));
        if (Result.index() == 1)
        {
            (void)Sock->Close();
            co_return TailReadOutcome{true, {0, {Preview::Fault::Code::Timeout}}};
        }
        co_return TailReadOutcome{false, std::get<0>(std::move(Result))};
    }

    inline auto TailReadGuarded(const Preview::SharedTransmission &Sock,
                                std::span<std::byte> Buffer, std::error_code &ErrorCode)
        -> net::awaitable<std::size_t>
    {
        const auto Outcome = co_await TailReadOutcomeGuarded(Sock, Buffer);
        if (Outcome.TimedOut)
        {
            ErrorCode = std::make_error_code(std::errc::timed_out);
            co_return 0;
        }
        ErrorCode = Preview::Fault::ToNative(Outcome.Result.Failure);
        co_return Outcome.Result.Bytes;
    }

    /**
     * @struct ChainState
     * @brief 协议纵向链路测试共享状态（记录客户端请求目标 + echo 端口）
     */
    struct ChainState
    {
        net::any_io_executor Executor;      ///< 拨号执行器
        std::uint16_t EchoPort{0};         ///< 回环上游端口
        std::string RequestedHost;         ///< 客户端请求的目标 host
        std::string RequestedPort;         ///< 客户端请求的目标 port
    };

    using ChainStatePtr = std::shared_ptr<ChainState>;

    /**
     * @brief 连接纵向链路测试的回环上游（记录请求目标后拨 127.0.0.1:EchoPort）
     * @param State 共享状态（请求目标写入 Requested_*）
     * @param Target 客户端请求的目标
     * @return 拨号结果（失败为 unreachable）
     */
    [[nodiscard]] inline auto DialUpstream(const ChainStatePtr &State,
                                            const Preview::Network::Target &Target)
        -> net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        const auto Text = Preview::Network::ToText(Target.Host);
        State->RequestedHost = Text.View();
        State->RequestedPort = std::to_string(Target.Port);
        Preview::Network::Dialer::Dialer Dialer(State->Executor);
        co_return co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), State->EchoPort});
    }

    /**
     * @brief 在测试正式协议边界把协议错误转换为领域失败。
     * @param Value 协议私有错误码；本函数同步读取，不保留输入。
     * @return 只保留映射后的 Fault 分类；协议解析错误没有伪造原生 cause。
     */
    [[nodiscard]] inline auto FailureFromProtocolError(const Preview::Error Value) noexcept
        -> Preview::Fault::Failure
    {
        return {Preview::Fault::ToCode(Preview::make_error_code(Value)), {}};
    }

    /**
     * @struct ConnectResult
     * @brief 纵向链路运行结果（唯一 typed 失败 + 回显数据 + 上游记录的请求目标）
     */
    struct ConnectResult
    {
        Preview::Fault::Failure Failure{}; ///< 唯一业务失败值；成功要求 Code::Success 且无 Native。
        std::string Echo;                  ///< 回显数据
        std::string Host;                  ///< 上游记录的请求 host
        std::string Port;                  ///< 上游记录的请求 port
    };

    /**
     * @struct TrafficRecorder
     * @brief 流量统计桩（校验 relay/udp 数据面结束后上报）
     */
    struct TrafficRecorder : Preview::Foundation::TrafficSink
    {
        Preview::Foundation::TrafficEvent LastEvent{}; ///< 最近一次上报的数值事件
        std::size_t Up{0};    ///< 累计上行字节
        std::size_t Down{0};  ///< 累计下行字节
        int Calls{0};         ///< Completed 终结上报次数
        int ByteCalls{0};     ///< Bytes 增量上报次数
        int RetirementCalls{0}; ///< 动态统计 owner 退休回执次数
        Preview::Foundation::TrafficRetirement LastRetirement{
            Preview::Foundation::SessionTrafficOwner{}};

        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            LastEvent = Event;
            Up += Event.Up;
            Down += Event.Down;
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Completed) ++Calls;
            else ++ByteCalls;
        }

        /** @brief 桩显式记录已接管的退休输入；不承担生产计数器的聚合或资源关闭。 */
        auto Retire(Preview::Foundation::TrafficRetirement Owner)
            -> net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            LastRetirement = std::move(Owner);
            ++RetirementCalls;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
    };

    /// 固定测试 UUID 字节数（vless/vmess 通用 16 字节）
    inline constexpr std::size_t UuidLen = 16;

    /**
     * @brief 构造固定测试 UUID（字节填充 1..16，确定性）
     */
    [[nodiscard]] inline auto MakeUuid() -> std::array<std::uint8_t, UuidLen>
    {
        std::array<std::uint8_t, UuidLen> Value{};
        for (std::size_t I = 0; I < Value.size(); ++I)
        {
            Value[I] = static_cast<std::uint8_t>(I + 1);
        }
        return Value;
    }

    /**
     * @brief 字节数组转十六进制字符串（VMess/VLESS 认证身份格式）
     * @param Bytes 输入字节
     * @return 小写十六进制串（长度 ×2）
     */
    [[nodiscard]] inline auto ToHex(const std::array<std::uint8_t, UuidLen> &Bytes)
        -> std::string
    {
        static constexpr char Digits[] = "0123456789abcdef";
        std::string Output(Bytes.size() * 2, '0');
        for (std::size_t I = 0; I < Bytes.size(); ++I)
        {
            Output[I * 2] = Digits[Bytes[I] >> 4];
            Output[I * 2 + 1] = Digits[Bytes[I] & 0x0f];
        }
        return Output;
    }
} // namespace Preview::Testing
