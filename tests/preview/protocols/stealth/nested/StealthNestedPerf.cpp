/**
 * @file StealthNestedPerf.cpp
 * @brief TLS 伪装方案 + 内层代理协议组合测试（联通性 + 数据一致性 + 性能）
 * @details 外层伪装（shadowtls/restls/anytls/trusttunnel/ws/gun/reality）
 *          内层套 vless/trojan/socks5：验证多层套接的正确性与开销。
 *          每用例：双端握手 → 64MB 传输 → 固定 payload 校验 → 吞吐/延迟。
 * @note 传输介质是 MemoryStream；这里测量的是协议装饰器和内存管道开销，
 *       不代表 TCP/QUIC 内核、背压或真实网络吞吐。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <TestSupport/Benchmark/Bench.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Protocols/Anytls/Anytls.hpp>
#include <preview/Protocols/Gun/Gun.hpp>
#include <preview/Protocols/Reality/Reality.hpp>
#include <preview/Protocols/Restls/Restls.hpp>
#include <preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Anytls = Preview::Anytls;
    namespace Gun = Preview::Gun;
    namespace Reality = Preview::Reality;
    namespace Restls = Preview::Restls;
    namespace Shadowtls = Preview::Shadowtls;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Trusttunnel = Preview::Trusttunnel;
    namespace Vless = Preview::Vless;
    namespace Ws = Preview::Ws;
    using Preview::BenchOptions;
    using Preview::BenchReport;
    using Preview::BenchThroughputTx;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code)>;

    struct NestedRunState
    {
        explicit NestedRunState(Net::any_io_executor Executor)
            : ServerCompletion(std::make_shared<CompletionChannel>(Executor, 1)),
              WatchdogCompletion(std::make_shared<CompletionChannel>(Executor, 1)),
              Watchdog(std::make_shared<Net::steady_timer>(Executor))
        {
        }

        SharedTransmission ClientEndpoint;
        SharedTransmission ServerEndpoint;
        std::shared_ptr<CompletionChannel> ServerCompletion;
        std::shared_ptr<CompletionChannel> WatchdogCompletion;
        std::shared_ptr<Net::steady_timer> Watchdog;
        std::exception_ptr ServerException;
        std::exception_ptr WatchdogException;
        BenchReport Report{};
        bool Linked{false};
        bool Failed{false};
        bool PayloadMismatch{false};
        bool TimedOut{false};
        bool Completed{false};
    };

    auto CloseNestedEndpoints(const std::shared_ptr<NestedRunState> &State) -> void
    {
        if (State->ClientEndpoint)
        {
            State->ClientEndpoint->Close();
        }
        if (State->ServerEndpoint)
        {
            State->ServerEndpoint->Close();
        }
    }

    [[nodiscard]] auto WaitForCompletion(
        const std::shared_ptr<CompletionChannel> &Completion)
        -> Net::awaitable<void>
    {
        boost::system::error_code ErrorCode;
        auto Receive = Completion->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_await std::move(Receive);
    }

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr Error)
                      {
                          Exception = Error;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakeDestination() -> Vless::Address
    {
        Vless::Address Destination{};
        Destination.Type = Vless::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    auto MakeUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        Uuid.fill(0x55);
        return Uuid;
    }

    auto MakeRandom32() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(Index * 3 + 1);
        }
        return Random;
    }

    template <typename Connection>
    auto ToTransmission(Error ErrorCode, Connection ConnectionValue) -> SharedTransmission
    {
        if (ErrorCode == Error::None)
        {
            return SharedTransmission(std::move(ConnectionValue));
        }
        return {};
    }

    /**
     * @brief 组合测试运行器：伪装层(Factory) 套 内层 vless
     * @tparam Factory 伪装层工厂（提供 Connect/Accept，接收 SharedTransmission）
     * @param Name 方案名（打印用）
     * @details 结构：memory_pair → 伪装 Conn 对 → vless Conn 对 → 64MB 传输。
     *          MemoryStream 不提供真实 socket 背压，结果只用于协议层相对比较。
     */
    template <typename Factory>
    auto RunNestedVless(Net::io_context &IoContext, Factory FactoryValue, const char *Name) -> void
    {
        constexpr std::size_t TotalBytes = 64 * 1024 * 1024;
        constexpr std::size_t BlockBytes = 64 * 1024;
        auto State = std::make_shared<NestedRunState>(IoContext.get_executor());
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        State->ClientEndpoint = std::make_shared<MemoryStream>(std::move(ClientMemory));
        State->ServerEndpoint = std::make_shared<MemoryStream>(std::move(ServerMemory));

        State->Watchdog->expires_after(std::chrono::seconds(10));
        auto WatchdogCoroutine = [State]() -> Net::awaitable<void>
        {
            boost::system::error_code ErrorCode;
            co_await State->Watchdog->async_wait(
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (ErrorCode == Net::error::operation_aborted)
            {
                co_return;
            }
            if (ErrorCode)
            {
                State->WatchdogException = std::make_exception_ptr(
                    std::system_error(ErrorCode));
                co_return;
            }
            if (!State->Completed)
            {
                State->TimedOut = true;
                CloseNestedEndpoints(State);
            }
        };
        auto OnWatchdogComplete = [State](std::exception_ptr Exception) -> void
        {
            if (Exception)
            {
                State->WatchdogException = std::move(Exception);
            }
            (void)State->WatchdogCompletion->try_send(
                boost::system::error_code{});
        };
        Net::co_spawn(
            IoContext,
            WatchdogCoroutine(),
            std::move(OnWatchdogComplete));

        auto Root = [&]() -> Net::awaitable<void>
        {
            auto ServerCoroutine = [&]() -> Net::awaitable<void>
            {
                auto [ServerError, ServerConnection] = co_await FactoryValue.ServerAccept(
                    State->ServerEndpoint);
                if (ServerError != Error::None || !ServerConnection)
                {
                    State->Failed = true;
                    EXPECT_TRUE(false)
                        << Name << ": stealth Accept Failed err=" << static_cast<int>(ServerError);
                    CloseNestedEndpoints(State);
                    co_return;
                }
                auto [InnerError, Request, ServerConnectionValue] = co_await Vless::Accept(
                    std::move(ServerConnection),
                    Vless::ServerConfig{MakeUuid()});
                const auto ExpectedTarget = MakeDestination();
                if (InnerError != Error::None || !ServerConnectionValue)
                {
                    State->Failed = true;
                    EXPECT_TRUE(false) << Name << ": vless Accept Failed";
                    CloseNestedEndpoints(State);
                    co_return;
                }
                if (Request.Target.Host != ExpectedTarget.Host ||
                    Request.Target.Port != ExpectedTarget.Port)
                {
                    State->Failed = true;
                    EXPECT_TRUE(false) << Name << ": VLESS target mismatch";
                    CloseNestedEndpoints(State);
                    co_return;
                }
                State->Linked = true;
                std::array<std::byte, 128 * 1024> Buffer{};
                while (true)
                {
                    std::error_code ReadError;
                    const auto Count = co_await ServerConnectionValue->async_read_some(
                        Buffer,
                        ReadError);
                    if (ReadError || Count == 0)
                    {
                        break;
                    }
                    for (std::size_t Index = 0; Index < Count; ++Index)
                    {
                        if (Buffer[Index] != std::byte{0x5a})
                        {
                            State->PayloadMismatch = true;
                            State->Failed = true;
                            break;
                        }
                    }
                    if (State->Failed)
                    {
                        break;
                    }
                    std::size_t Offset = 0;
                    while (Offset < Count)
                    {
                        std::error_code WriteError;
                        const auto WriteWindow = std::span<const std::byte>(Buffer).subspan(
                            Offset,
                            Count - Offset);
                        const auto Written = co_await ServerConnectionValue->async_write_some(
                            WriteWindow,
                            WriteError);
                        if (WriteError || Written == 0 || Written > Count - Offset)
                        {
                            State->Failed = true;
                            break;
                        }
                        Offset += Written;
                    }
                    if (State->Failed)
                    {
                        break;
                    }
                }
                ServerConnectionValue->Close();
            };
            auto OnServerComplete = [State](std::exception_ptr Exception) -> void
            {
                if (Exception)
                {
                    State->ServerException = std::move(Exception);
                    State->Failed = true;
                    CloseNestedEndpoints(State);
                }
                (void)State->ServerCompletion->try_send(
                    boost::system::error_code{});
            };
            Net::co_spawn(
                IoContext,
                ServerCoroutine(),
                std::move(OnServerComplete));

            auto Finalize = [State]() -> Net::awaitable<void>
            {
                State->Completed = true;
                CloseNestedEndpoints(State);
                State->Watchdog->cancel();
                co_await WaitForCompletion(State->ServerCompletion);
                co_await WaitForCompletion(State->WatchdogCompletion);
                if (State->ServerException)
                {
                    std::rethrow_exception(State->ServerException);
                }
                if (State->WatchdogException)
                {
                    std::rethrow_exception(State->WatchdogException);
                }
            };

            auto [ClientError, ClientConnection] = co_await FactoryValue.ClientConnect(
                State->ClientEndpoint);
            if (ClientError != Error::None || !ClientConnection)
            {
                State->Failed = true;
                EXPECT_TRUE(false)
                    << Name << ": stealth Connect Failed err=" << static_cast<int>(ClientError);
                co_await Finalize();
                co_return;
            }
            auto [InnerError, ClientConnectionValue] = co_await Vless::Connect(
                std::move(ClientConnection),
                Vless::ClientConfig{MakeUuid()},
                MakeDestination());
            if (InnerError != Error::None || !ClientConnectionValue)
            {
                State->Failed = true;
                EXPECT_TRUE(false)
                    << Name << ": vless Connect Failed err=" << static_cast<int>(InnerError);
                co_await Finalize();
                co_return;
            }
            BenchOptions BenchValue;
            BenchValue.Total = TotalBytes;
            BenchValue.Block = BlockBytes;
            State->Report = co_await BenchThroughputTx(
                *ClientConnectionValue,
                *ClientConnectionValue,
                BenchValue);
            ClientConnectionValue->Close();
            co_await Finalize();
        };
        RunCoroutine(IoContext, Root());

        if (!State->Failed)
        {
            EXPECT_TRUE(State->Linked) << Name << ": 双层握手联通失败";
            EXPECT_EQ(State->Report.Bytes, TotalBytes) << Name << ": 传输字节数不一致";
            EXPECT_FALSE(State->PayloadMismatch) << Name << ": payload 内容不一致";
        }
        const char *Status = "FAIL";
        if (State->Linked && !State->Failed)
        {
            Status = "OK";
        }
        std::printf("%-12s 联通=%s  Bytes=%zu(期望 %zu)  吞吐=%.1f MB/s  延迟(ms) avg=%.3f p50=%.3f p95=%.3f "
                    "p99=%.3f\n",
                    Name, Status, State->Report.Bytes, TotalBytes, State->Report.Mbps,
                    State->Report.LatencyAvg, State->Report.LatencyP50,
                    State->Report.LatencyP95, State->Report.LatencyP99);
    }

    // ---------- 各伪装层工厂 ----------

    struct shadowtls_factory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            const auto ServerRandom = MakeRandom32();
            const auto ClientRandom = MakeRandom32();
            auto [ErrorCode, Connection] = co_await Shadowtls::Connect(
                {std::move(Upstream), Shadowtls::ClientConfig{"st_password"}, ServerRandom, ClientRandom});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Connection] = co_await Shadowtls::Accept(
                std::move(Upstream),
                Shadowtls::ServerConfig{"st_password"});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    struct restls_factory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            const auto ServerRandom = MakeRandom32();
            auto [ErrorCode, Connection] = co_await Restls::Connect(
                std::move(Upstream),
                Restls::ClientConfig{"rs_password"},
                ServerRandom);
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            const auto ServerRandom = MakeRandom32();
            auto [ErrorCode, Connection] = co_await Restls::Accept(
                std::move(Upstream),
                Restls::ServerConfig{"rs_password"},
                ServerRandom);
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    struct anytls_factory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Connection] = co_await Anytls::Connect(
                std::move(Upstream),
                Anytls::ClientConfig{"at_password"});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Connection] = co_await Anytls::Accept(
                std::move(Upstream),
                Anytls::ServerConfig{"at_password"});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    struct trusttunnel_factory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Connection] = co_await Trusttunnel::Connect(
                {std::move(Upstream), Trusttunnel::ClientConfig{"tu_user", "tu_pass"}, "example.com", 443});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Target, Connection] = co_await Trusttunnel::Accept(
                std::move(Upstream),
                Trusttunnel::ServerConfig{"tu_user", "tu_pass"});
            (void)Target;
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    struct ws_factory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Connection] = co_await Ws::Connect(
                std::move(Upstream),
                Ws::ClientConfig{"example.com"});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Key, Connection] = co_await Ws::Accept(
                std::move(Upstream), Ws::ServerConfig{});
            (void)Key;
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    struct gun_factory
    {
        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Connection] = co_await Gun::Connect(
                std::move(Upstream), "example.com");
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            auto [ErrorCode, Host, Connection] = co_await Gun::Accept(
                std::move(Upstream));
            (void)Host;
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    struct reality_factory
    {
        // 共享密钥对（客户端持 cli 私钥，服务端持 srv 私钥）
        std::array<std::uint8_t, Reality::KeyLen> ServerPrivate{};
        std::array<std::uint8_t, Reality::KeyLen> ServerPublic{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPrivate{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPublic{};
        std::array<std::uint8_t, 40> Random{};
        std::array<std::uint8_t, 128> Hello{};

        reality_factory()
        {
            EXPECT_FALSE(Reality::GenerateKeypair(ServerPrivate, ServerPublic));
            EXPECT_FALSE(Reality::GenerateKeypair(ClientPrivate, ClientPublic));
            for (std::size_t Index = 0; Index < Random.size(); ++Index)
            {
                Random[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
            }
            for (std::size_t Index = 0; Index < Hello.size(); ++Index)
            {
                Hello[Index] = static_cast<std::uint8_t>(Index);
            }
        }

        auto ClientConnect(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ClientConfig Config;
            Config.private_key = ClientPrivate;
            Config.ShortId.fill(0x42);
            auto [ErrorCode, Connection] = co_await Reality::Connect(
                {std::move(Upstream), Config, ServerPublic,
                 Reality::HandshakeParams{Random, Hello, Config.ShortId}});
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
        auto ServerAccept(SharedTransmission Upstream)
            -> Net::awaitable<std::pair<Error, SharedTransmission>>
        {
            Reality::ServerConfig Config;
            Config.private_key = ServerPrivate;
            Config.ShortId.fill(0x42);
            auto [ErrorCode, GotSessionId, Connection] = co_await Reality::Accept(
                {std::move(Upstream), Config, ClientPublic,
                 Reality::HandshakeParams{Random, Hello}});
            (void)GotSessionId;
            co_return std::pair{ErrorCode, ToTransmission(ErrorCode, std::move(Connection))};
        }
    };

    // ---------- 测试用例 ----------

    TEST(StealthNested, ShadowTlsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, shadowtls_factory{}, "shadowtls");
    }

    TEST(StealthNested, RestlsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, restls_factory{}, "restls");
    }

    TEST(StealthNested, AnyTlsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, anytls_factory{}, "anytls");
    }

    TEST(StealthNested, TrustTunnelVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, trusttunnel_factory{}, "trusttunnel");
    }

    TEST(TrustTunnelConn, HandshakeDirect)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto ServerCompletion = std::make_shared<CompletionChannel>(
            IoContext.get_executor(), 1);
        auto ServerException = std::make_shared<std::exception_ptr>();
        auto Target = std::make_shared<std::string>();
        RunCoroutine(IoContext,
                 [ClientMemory = std::move(ClientMemory),
                  ServerMemory = std::move(ServerMemory),
                  ServerCompletion,
                  ServerException,
                  Target,
                  &IoContext]() mutable -> Net::awaitable<void>
                 {
                     auto ServerCoroutine = [ServerMemory = std::move(ServerMemory),
                                             ServerCompletion,
                                             ServerException,
                                             Target]() mutable -> Net::awaitable<void>
                     {
                         auto [ErrorCode, AcceptedTarget, Connection] = co_await Trusttunnel::Accept(
                             std::make_shared<MemoryStream>(std::move(ServerMemory)),
                             Trusttunnel::ServerConfig{"tu_user", "tu_pass"});
                         if (ErrorCode != Error::None)
                         {
                             EXPECT_TRUE(false) << "Accept err=" << static_cast<int>(ErrorCode);
                             co_return;
                         }
                         *Target = std::move(AcceptedTarget);
                     };
                     auto OnServerComplete = [ServerCompletion, ServerException](
                                                 std::exception_ptr Exception) -> void
                     {
                         *ServerException = std::move(Exception);
                         (void)ServerCompletion->try_send(
                             boost::system::error_code{});
                     };
                     Net::co_spawn(
                         IoContext,
                         ServerCoroutine(),
                         std::move(OnServerComplete));
                     auto [ErrorCode, Connection] = co_await Trusttunnel::Connect(
                         {std::make_shared<MemoryStream>(std::move(ClientMemory)),
                          Trusttunnel::ClientConfig{"tu_user", "tu_pass"}, "example.com", 443});
                     if (ErrorCode != Error::None)
                     {
                         EXPECT_TRUE(false) << "Connect err=" << static_cast<int>(ErrorCode);
                         co_await WaitForCompletion(ServerCompletion);
                         co_return;
                     }
                     co_await WaitForCompletion(ServerCompletion);
                     if (*ServerException)
                     {
                         std::rethrow_exception(*ServerException);
                     }
                     EXPECT_EQ(*Target, "example.com");
                     Connection->Close();
                 });
    }

    TEST(StealthNested, WsVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, ws_factory{}, "ws");
    }

    TEST(StealthNested, GunVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, gun_factory{}, "gun");
    }

    TEST(StealthNested, RealityVless)
    {
        Net::io_context IoContext;
        RunNestedVless(IoContext, reality_factory{}, "reality");
    }

} // namespace
