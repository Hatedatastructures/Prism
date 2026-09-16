/**
 * @file NetworkingStressTest.cpp
 * @brief 网络层压力测试（T5-10 D7，smoke 版）
 * @details 覆盖：
 *          - TCP 连接风暴：并发 50 连接 × 10 轮，全部 echo 成功
 *          - UDP Relay 长跑：1000 包双向往返
 *          - stress helper：Gate 汇合 / LeakTracker 泄漏探测
 * @note smoke 参数（短时）；完整长跑在 CI/手动扩展轮次
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <memory>
#include <string>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Net/UdpRelay.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Unreliable.hpp>
#include <TestSupport/Stress/StressHelper.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    /// 长跑缩放因子：NGX_STRESS_DURATION=秒 → 轮次放大（默认 1 = smoke）
    auto StressScale() -> int
    {
        const auto *env = std::getenv("NGX_STRESS_DURATION");
        if (!env)
        {
            return 1;
        }
        const auto sec = std::atoi(env);
        if (sec <= 0)
        {
            return 1;
        }
        return (std::max)(1, sec / 5); // 每 5 秒扩 1 倍
    }

    /// TCP echo 服务器
    auto TcpEchoServer(Tcp::socket Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        boost::system::error_code ErrorCode;
        while (true)
        {
            const auto n = co_await Socket.async_read_some(Net::buffer(Buffer),
                                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode || n == 0)
            {
                break;
            }
            co_await Socket.async_write_some(Net::buffer(Buffer, n),
                                           Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode)
            {
                break;
            }
        }
    }

    TEST(NetworkStress, TcpConnectionStorm)
    {
        constexpr int ConnectionsPerRound = 50;
        const auto rounds = 10 * StressScale();
        const auto Total = ConnectionsPerRound * rounds;

        Net::io_context IoContext;
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                Tcp::acceptor Acceptor(IoContext, Tcp::endpoint(Tcp::v4(), 0));
                const auto Port = Acceptor.local_endpoint().port();

                Net::co_spawn(
                    IoContext.get_executor(),
                    [&]() -> Net::awaitable<void>
                    {
                        while (true)
                        {
                            boost::system::error_code ErrorCode;
                            auto Socket = co_await Acceptor.async_accept(
                                Net::redirect_error(Net::use_awaitable, ErrorCode));
                            if (ErrorCode)
                            {
                                co_return;
                            }
                            Net::co_spawn(IoContext.get_executor(), TcpEchoServer(std::move(Socket)),
                                          Net::detached);
                        }
                    },
                    Net::detached);

                // 风暴：并发连接 × 多轮
                std::atomic<int> Ok{0};
                Preview::Stress::Gate GateValue(IoContext.get_executor(), Total);
                for (int Round = 0; Round < rounds; ++Round)
                {
                    for (int Index = 0; Index < ConnectionsPerRound; ++Index)
                    {
                        Net::co_spawn(
                            IoContext.get_executor(),
                            [&, Index]() -> Net::awaitable<void>
                            {
                                std::error_code ErrorCode;
                                Preview::Network::Dialer::Dialer Dialer(IoContext.get_executor());
                                auto Conn = co_await Dialer.Connect("127.0.0.1", Port, ErrorCode);
                                if (ErrorCode || !Conn)
                                {
                                    GateValue.Arrive();
                                    co_return;
                                }
                                const std::string Message = "storm-" + std::to_string(Index);
                                co_await Conn->async_write_some(
                                    std::span<const std::byte>(
                                        reinterpret_cast<const std::byte *>(Message.data()), Message.size()),
                                    ErrorCode);
                                std::array<std::byte, 64> Buffer{};
                                const auto n = co_await Conn->async_read_some(Buffer, ErrorCode);
                                if (!ErrorCode && std::string_view(reinterpret_cast<const char *>(Buffer.data()),
                                                            n) == Message)
                                {
                                    ++Ok;
                                }
                                Conn->Close();
                                GateValue.Arrive();
                            },
                            Net::detached);
                    }
                }
                co_await GateValue.Wait();
                EXPECT_EQ(Ok, Total);
                Acceptor.close();
            },
            [&](std::exception_ptr e) { Exception = e; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(NetworkStress, UdpRelayLongRun)
    {
        const auto PacketCount = 1000 * StressScale();
        Net::io_context IoContext;

        auto a = std::make_shared<Preview::Transport::Unreliable>(IoContext.get_executor());
        auto b = std::make_shared<Preview::Transport::Unreliable>(IoContext.get_executor());
        boost::system::error_code OuterErrorCode;
        a->NativeSocket().open(Net::ip::udp::v4(), OuterErrorCode);
        a->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OuterErrorCode);
        b->NativeSocket().open(Net::ip::udp::v4(), OuterErrorCode);
        b->NativeSocket().bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OuterErrorCode);

        Net::co_spawn(
            IoContext.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Preview::Network::Udp::RelayOptions OptionsValue;
                OptionsValue.IdleTimeout = std::chrono::milliseconds(5000);
                Preview::Network::Udp::UdpRelay Relay(a, b, OptionsValue);
                co_await Relay.Run();
            },
            Net::detached);

        // 端 A/B 客户端（echo 型）
        Net::ip::udp::socket ClientSocketA(IoContext.get_executor());
        Net::ip::udp::socket ClientSocketB(IoContext.get_executor());
        ClientSocketA.open(Net::ip::udp::v4(), OuterErrorCode);
        ClientSocketA.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OuterErrorCode);
        ClientSocketB.open(Net::ip::udp::v4(), OuterErrorCode);
        ClientSocketB.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), OuterErrorCode);
        const auto ClientEndpoint = ClientSocketA.local_endpoint();
        const auto ClientBEndpoint = ClientSocketB.local_endpoint();
        const auto RelayEndpointA = a->NativeSocket().local_endpoint();
        const auto RelayEndpointB = b->NativeSocket().local_endpoint();

        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                // 建立动态关联（ClientSocketA/ClientSocketB 各发首包配对）
                const std::string LearnPayload = "l";
                co_await ClientSocketA.async_send_to(Net::buffer(LearnPayload.data(), LearnPayload.size()), RelayEndpointA,
                                          Net::redirect_error(Net::use_awaitable, OuterErrorCode));
                co_await ClientSocketB.async_send_to(Net::buffer(LearnPayload.data(), LearnPayload.size()), RelayEndpointB,
                                          Net::redirect_error(Net::use_awaitable, OuterErrorCode));
                // 等配对后的学习包转发到 ClientSocketA
                {
                    std::array<std::byte, 8> Buffer{};
                    Net::ip::udp::endpoint Source;
                    co_await ClientSocketA.async_receive_from(Net::buffer(Buffer), Source,
                                                   Net::redirect_error(Net::use_awaitable, OuterErrorCode));
                }

                // ClientSocketB 侧回显（收 B 中继数据 → 回发）
                Net::co_spawn(
                    IoContext.get_executor(),
                    [&]() -> Net::awaitable<void>
                    {
                        for (int Index = 0; Index < PacketCount; ++Index)
                        {
                            std::array<std::byte, 64> Buffer{};
                            Net::ip::udp::endpoint Source;
                            boost::system::error_code ErrorCode;
                            const auto n = co_await ClientSocketB.async_receive_from(
                                Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, ErrorCode));
                            if (n > 0)
                            {
                                co_await ClientSocketB.async_send_to(Net::buffer(Buffer, n), Source,
                                                          Net::redirect_error(Net::use_awaitable, ErrorCode));
                            }
                        }
                    },
                    Net::detached);

                // ClientSocketA 侧：发 1000 包 → 等回显
                int Received = 0;
                for (int Index = 0; Index < PacketCount; ++Index)
                {
                    const std::string Message = "udp-" + std::to_string(Index);
                    co_await ClientSocketA.async_send_to(Net::buffer(Message.data(), Message.size()), RelayEndpointA,
                                              Net::redirect_error(Net::use_awaitable, OuterErrorCode));
                    std::array<std::byte, 64> Buffer{};
                    Net::ip::udp::endpoint Source;
                    const auto n = co_await ClientSocketA.async_receive_from(
                        Net::buffer(Buffer), Source, Net::redirect_error(Net::use_awaitable, OuterErrorCode));
                    if (n == Message.size() &&
                        std::string_view(reinterpret_cast<const char *>(Buffer.data()), n) == Message)
                    {
                        ++Received;
                    }
                }
                EXPECT_EQ(Received, PacketCount);
            },
            [&](std::exception_ptr e) { Exception = e; IoContext.stop(); });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(NetworkStress, LeakTrackerDetectsRelease)
    {
        auto Object = std::make_shared<int>(42);
        Preview::Stress::LeakTracker Tracker;
        Tracker.Track(Object);
        EXPECT_EQ(Tracker.Total(), 1);
        EXPECT_FALSE(Tracker.AllReleased());
        Object.reset();
        EXPECT_TRUE(Tracker.AllReleased());
    }

    TEST(NetworkStress, GateSynchronizes)
    {
        Net::io_context IoContext;
        Preview::Stress::Gate GateValue(IoContext.get_executor(), 3);
        std::atomic<int> Arrived{0};

        Net::co_spawn(IoContext,
                      [&]() -> Net::awaitable<void>
                      {
                          for (int Index = 0; Index < 3; ++Index)
                          {
                              ++Arrived;
                              GateValue.Arrive();
                          }
                          co_await GateValue.Wait();
                          EXPECT_EQ(Arrived, 3);
                      },
                      [&](std::exception_ptr e)
                      {
                          if (e)
                          {
                              std::rethrow_exception(e);
                          }
                          IoContext.stop();
                      });
        IoContext.run();
    }

} // namespace
