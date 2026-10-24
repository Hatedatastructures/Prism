/** @file CanonicalDatagramTest.cpp @brief 真实协议数据报 owner 的配置与生命周期回归。 */
#include <gtest/gtest.h>
#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/HostText.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <Prism/Protocols/Trojan/DatagramSession.hpp>
#include <Prism/Transport/Transmission.hpp>
#include "TrojanDatagramTestSupport.hpp"
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/thread_pool.hpp>
#include <array>
#include <expected>
#include <system_error>
namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    namespace Fault = Prism::Fault;
    using Udp = Net::ip::udp;
    using Prism::Error;
    using Prism::PrismMockTransport;
    using Prism::Testing::RunCoro;
    using Prism::Testing::TrafficRecorder;
    using DatagramRunResult = std::expected<void, Fault::Failure>;

    /** @brief 把 typed Run 投影为现有协议状态断言。 */
    auto DatagramStatus(const DatagramRunResult& Result) -> Fault::Code
    {
        return Result ? Fault::Code::Success : Result.error().Code;
    }

    struct DatagramCloseRetryState final
    {
        std::size_t CloseCalls{0};
        bool Open{true};
    };

    /** @brief 首次 OnClose 回执保留 native cause，原 executor 重试才关闭。 */
    class DatagramCloseRetryTransmission final : public Prism::Transmission
    {
    public:
        DatagramCloseRetryTransmission(
            Net::any_io_executor Executor,
            std::shared_ptr<DatagramCloseRetryState> State)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              State_(std::move(State)) {}

        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Fault::Code::Eof}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), {0, {Fault::Code::Canceled}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (++State_->CloseCalls == 1)
                return std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::io_error)));
            State_->Open = false;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }
        [[nodiscard]] auto IsOpen() const -> bool override { return State_->Open; }

    private:
        ExecutorType Executor_;
        std::shared_ptr<DatagramCloseRetryState> State_;
    };

    /** @brief 一次拒绝 typed Close，后续显式 retry 交付真实 carrier Close。 */
    struct TypedFailureDatagramWire final
    {
        std::shared_ptr<PrismMockTransport> Carrier;
        std::shared_ptr<std::size_t> CloseRequests;
        Fault::Code Validation{Fault::Code::Success};
        bool FailCloseOnce{true};

        [[nodiscard]] auto Validate() const noexcept -> Fault::Code
        {
            return Validation;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Carrier->Executor();
        }

        [[nodiscard]] auto CarrierActivities() const
            -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>
        {
            return Prism::Protocols::CaptureDatagramCarrierActivities(*Carrier);
        }

        [[nodiscard]] auto Cancel() const -> Prism::Transmission::ControlResult
        {
            return Carrier->Cancel();
        }

        [[nodiscard]] auto Close() const -> Prism::Transmission::ControlResult
        {
            if (FailCloseOnce && ++*CloseRequests == 1)
                return std::unexpected(Fault::FromNative(
                    std::make_error_code(std::errc::io_error)));
            if (!FailCloseOnce) ++*CloseRequests;
            return Carrier->Close();
        }

        auto Receive(Prism::Protocols::DatagramPacket&)
            -> Net::awaitable<std::expected<void, Fault::Failure>>
        {
            co_return std::unexpected(Fault::Failure{Fault::Code::Eof});
        }

        auto Send(const Udp::endpoint&, std::span<const std::uint8_t>)
            -> Net::awaitable<std::expected<void, Fault::Failure>>
        {
            co_return std::expected<void, Fault::Failure>{};
        }
    };

    /**
     * @brief 配置 resolver 的测试观察值。
     * @details 字符串与计数器由测试栈拥有，存活到 Session::Run 完整返回。
     */
    struct ConfiguredResolverCallback final
    {
        std::size_t &ResolveCalls;
        std::string &ResolvedHost;
        std::uint16_t &ResolvedPort;
        std::uint16_t EchoPort;
    };

    /**
     * @brief 记录配置 resolver 请求并返回测试 echo socket 的地址。
     * @param Request Trojan 数据报携带的目标地址。
     * @param Callback 测试观察值和 echo 端口的借用视图。
     */
    auto ResolveConfiguredEndpoint(
        Prism::Network::Target Request,
        ConfiguredResolverCallback Callback)
        -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
    {
        ++Callback.ResolveCalls;
        const auto Text = Prism::Network::ToText(Request.Host);
        Callback.ResolvedHost = Text.View();
        Callback.ResolvedPort = Request.Port;
        co_return Udp::endpoint(Net::ip::address_v4::loopback(), Callback.EchoPort);
    }

    /**
     * @brief 挂起 resolver 的测试 owner 借用状态。
     * @details RunCoro 等待取消和解析协程退出后，引用目标才离开作用域。
     */
    struct PendingResolveCallback final
    {
        Net::io_context &Io;
        std::shared_ptr<Trojan::DatagramSession> &Session;
        std::shared_ptr<Net::steady_timer> &Timer;
        std::size_t &ResolveCalls;
        bool &ResolveExited;
    };

    /**
     * @brief 执行可取消的挂起 resolver，用于验证 session 等待其退出。
     * @param Target Trojan 数据报携带的目标地址。
     * @param Callback 测试中的 session、timer 和生命周期观察值。
     */
    auto ResolveUntilCanceled(
        Prism::Network::Target Target,
        PendingResolveCallback Callback)
        -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
    {
        ++Callback.ResolveCalls;
        EXPECT_EQ(Target.Host, *Prism::Network::ParseHost("x"));
        auto Session = Callback.Session;
        Net::post(Callback.Io, [Session] { Session->Cancel(); });
        Callback.Timer->expires_after(std::chrono::seconds(30));
        boost::system::error_code ErrorCode;
        co_await Callback.Timer->async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
        Callback.ResolveExited = true;
        co_return std::unexpected(Fault::Failure{Fault::Code::Canceled});
    }

    struct ActualDnsResolverCallback final
    {
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        bool& ResolveExited;
    };

    auto ResolveActualDnsEndpoint(
        Prism::Network::Target Target,
        ActualDnsResolverCallback Callback)
        -> Net::awaitable<std::expected<Udp::endpoint, Fault::Failure>>
    {
        struct ExitFlag final
        {
            bool& Value;
            ~ExitFlag() { Value = true; }
        } Exit{Callback.ResolveExited};
        const auto Text = Prism::Network::ToText(Target.Host);
        auto Addresses = co_await Callback.Resolver->AsyncResolve(std::string(Text.View()));
        if (!Addresses) co_return std::unexpected(Addresses.error());
        if (Addresses->Empty())
            co_return std::unexpected(Fault::Failure{Fault::Code::DnsFailed});
        co_return Udp::endpoint((*Addresses)[0], Target.Port);
    }

    auto UdpEchoOnce(const std::shared_ptr<Udp::socket> &Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 65535> Payload{};
        Udp::endpoint Peer;
        boost::system::error_code ErrorCode;
        const auto Size = co_await Socket->async_receive_from(
            Net::buffer(Payload), Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return;
        }
        co_await Socket->async_send_to(
            Net::buffer(Payload.data(), Size), Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return;
    }

    struct ConfiguredResolverRequest final
    {
        std::shared_ptr<Trojan::DatagramSession> Session;
        std::shared_ptr<Udp::socket> Echo;
        DatagramRunResult *Result;
    };

    /**
     * @brief 运行配置 resolver 的真实 Trojan 数据报 association。
     * @param Request session、echo socket 和结果输出。
     */
    auto RunConfiguredResolver(ConfiguredResolverRequest Request) -> Net::awaitable<void>
    {
        *Request.Result = co_await Request.Session->Run();
        const auto Retired = co_await Request.Session->Activity()->Drain();
        EXPECT_TRUE(Retired);
        boost::system::error_code Error;
        Request.Echo->close(Error);
    }

    struct PendingResolveCancelRequest final
    {
        std::shared_ptr<Trojan::DatagramSession> Session;
        bool *ResolveExited;
    };

    /**
     * @brief 取消挂起的 resolver 并等待真实解析协程退出。
     * @param Request session 和 resolver 退出状态。
     */
    auto RunPendingResolveCancel(PendingResolveCancelRequest Request) -> Net::awaitable<void>
    {
        EXPECT_EQ(DatagramStatus(co_await Request.Session->Run()), Fault::Code::Canceled);
        EXPECT_TRUE(*Request.ResolveExited);
        EXPECT_EQ(DatagramStatus(co_await Request.Session->Run()), Fault::Code::InvalidArgument);
        Request.Session->Close();
        Request.Session->Close();
        const auto Retired = co_await Request.Session->Activity()->Drain();
        EXPECT_TRUE(Retired);
    }

    using DatagramDoneChannel =
        Net::experimental::channel<void(boost::system::error_code, Fault::Failure)>;

    struct RealDnsCancelRequest final
    {
        std::shared_ptr<Trojan::DatagramSession> Session;
        std::shared_ptr<Trojan::DatagramSession> *SessionSlot;
        std::shared_ptr<Udp::socket> DnsSocket;
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        std::shared_ptr<Prism::Network::Dns::Resolver> *ResolverSlot;
        std::shared_ptr<DatagramDoneChannel> Done;
        bool *ResolveExited;
    };

    /**
     * @brief 取消真实 DNS 查询并等待 session 与 resolver 完整退出。
     * @param Request session、DNS socket、resolver 和完成通道。
     */
    auto RunRealDnsCancel(RealDnsCancelRequest Request) -> Net::awaitable<void>
    {
        Net::co_spawn(Request.DnsSocket->get_executor(), Request.Session->Run(),
            [Done = Request.Done](std::exception_ptr Exception, DatagramRunResult Result)
            {
                const auto Failure = Exception ? Fault::Failure{Fault::Code::IoError}
                    : Result ? Fault::Failure{} : Result.error();
                (void)Done->try_send(boost::system::error_code{}, Failure);
            });
        std::array<std::byte, 512> Query{};
        Udp::endpoint Peer;
        const auto Size = co_await Request.DnsSocket->async_receive_from(
            Net::buffer(Query), Peer, Net::use_awaitable);
        EXPECT_GT(Size, 12U);
        const auto Started = std::chrono::steady_clock::now();
        Request.Session->Cancel();
        const auto Result = co_await Request.Done->async_receive(Net::use_awaitable);
        EXPECT_EQ(Result.Code, Fault::Code::Canceled);
        EXPECT_TRUE(*Request.ResolveExited);
        EXPECT_LT(std::chrono::steady_clock::now() - Started, std::chrono::seconds(1));
        const auto Retired = co_await Request.Session->Activity()->Drain();
        EXPECT_TRUE(Retired);
        Request.Session.reset();
        Request.Resolver.reset();
        Request.SessionSlot->reset();
        Request.ResolverSlot->reset();
        boost::system::error_code Error;
        Request.DnsSocket->close(Error);
    }

    struct IdleDnsTimeoutRequest final
    {
        std::shared_ptr<Trojan::DatagramSession> Session;
        std::shared_ptr<Trojan::DatagramSession> *SessionSlot;
        std::shared_ptr<Udp::socket> DnsSocket;
        std::shared_ptr<Prism::Network::Dns::Resolver> Resolver;
        std::shared_ptr<Prism::Network::Dns::Resolver> *ResolverSlot;
        std::shared_ptr<DatagramDoneChannel> Done;
        bool *ResolveExited;
    };

    /**
     * @brief 验证 idle timeout 取消真实 DNS 查询并回收 session。
     * @param Request session、DNS socket、resolver 和完成通道。
     */
    auto RunIdleDnsTimeout(IdleDnsTimeoutRequest Request) -> Net::awaitable<void>
    {
        Net::co_spawn(Request.DnsSocket->get_executor(), Request.Session->Run(),
            [Done = Request.Done](std::exception_ptr Exception, DatagramRunResult Value)
            {
                const auto Failure = Exception ? Fault::Failure{Fault::Code::IoError}
                    : Value ? Fault::Failure{} : Value.error();
                (void)Done->try_send(boost::system::error_code{}, Failure);
            });
        std::array<std::byte, 512> Query{};
        Udp::endpoint Peer;
        const auto Size = co_await Request.DnsSocket->async_receive_from(
            Net::buffer(Query), Peer, Net::use_awaitable);
        EXPECT_GT(Size, 12U);
        const auto Started = std::chrono::steady_clock::now();
        Net::steady_timer Watchdog(Request.DnsSocket->get_executor());
        Watchdog.expires_after(std::chrono::milliseconds(200));
        using Net::experimental::awaitable_operators::operator||;
        auto Completion = co_await (Request.Done->async_receive(Net::use_awaitable) ||
                                    Watchdog.async_wait(Net::use_awaitable));
        EXPECT_EQ(Completion.index(), 0U);
        auto Result = Fault::Failure{Fault::Code::IoError};
        if (Completion.index() == 0)
        {
            Result = std::get<0>(Completion);
        }
        else
        {
            Request.Session->Cancel();
            Result = co_await Request.Done->async_receive(Net::use_awaitable);
        }
        EXPECT_EQ(Result.Code, Fault::Code::Timeout);
        EXPECT_TRUE(*Request.ResolveExited);
        EXPECT_LT(std::chrono::steady_clock::now() - Started, std::chrono::seconds(1));
        const auto Retired = co_await Request.Session->Activity()->Drain();
        EXPECT_TRUE(Retired);
        Request.Session.reset();
        Request.Resolver.reset();
        Request.SessionSlot->reset();
        Request.ResolverSlot->reset();
        boost::system::error_code Error;
        Request.DnsSocket->close(Error);
    }

    TEST(CanonicalDatagramRegression, CloseBeforeRunUsesActivityRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Carrier = std::make_shared<PrismMockTransport>(Context->Io.get_executor());
        auto Dgram = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Dgram, Trojan::DatagramSession::Options{{}, {}});
        const auto Activity = Session->Activity();
        const auto Retirement = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        std::expected<void, Fault::Failure> DrainResult;
        RunCoro(Context->Io, [&]() -> Net::awaitable<void>
        {
            Session->Close();
            DrainResult = co_await Activity->Drain();
        });

        EXPECT_TRUE(DrainResult);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(Retirement->IsRetired());
    }

    TEST(CanonicalDatagramRegression, StoppedDomainReportsFailureAndRetainsOwnerUntilRetry)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Carrier = std::make_shared<PrismMockTransport>(Context->Io.get_executor());
        std::weak_ptr<Prism::Transmission> WeakCarrier = Carrier;
        auto Dgram = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Dgram, Trojan::DatagramSession::Options{{}, {}});
        const auto Activity = Session->Activity();
        const auto Retirement = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        Context->Io.stop();
        Net::io_context ControlIo;
        DatagramRunResult RunResult{};
        RunCoro(ControlIo, [&]() -> Net::awaitable<void> { RunResult = co_await Session->Run(); });
        EXPECT_EQ(DatagramStatus(RunResult), Fault::Code::Blocked);
        Session->Close();
        Session.reset(); Dgram.reset(); Carrier.reset();
        std::expected<void, Fault::Failure> FirstDrain;
        ControlIo.restart();
        RunCoro(ControlIo, [&]() -> Net::awaitable<void> { FirstDrain = co_await Activity->Drain(); });
        ASSERT_FALSE(FirstDrain);
        EXPECT_EQ(FirstDrain.error().Code, Fault::Code::Blocked);
        EXPECT_FALSE(FirstDrain.error().Native);
        EXPECT_FALSE(Retirement->IsRetired());
        EXPECT_FALSE(WeakCarrier.expired());
        EXPECT_GT(Storage->Pending(), 0U);
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        EXPECT_TRUE(Retirement->IsRetired());
        std::expected<void, Fault::Failure> RecoveredDrain;
        Context->Io.restart();
        RunCoro(Context->Io, [&]() -> Net::awaitable<void> { RecoveredDrain = co_await Activity->Drain(); });
        ASSERT_TRUE(RecoveredDrain);
        EXPECT_TRUE(Retirement->IsRetired());
        EXPECT_TRUE(WeakCarrier.expired());
        EXPECT_EQ(Storage->Pending(), 0U);
    }

    TEST(CanonicalDatagramRegression, ForeignExecutorCancelUsesSerializedRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Carrier = std::make_shared<PrismMockTransport>(Context->Io.get_executor());
        auto Dgram = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Dgram, Trojan::DatagramSession::Options{{}, {}});
        const auto Activity = Session->Activity();
        const auto Retirement = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        Net::thread_pool Caller(1);
        Net::post(Caller, [Session] { Session->Cancel(); });
        Caller.join();
        std::expected<void, Fault::Failure> DrainResult;

        RunCoro(Context->Io, [&]() -> Net::awaitable<void>
        {
            DrainResult = co_await Activity->Drain();
        });

        EXPECT_TRUE(DrainResult);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(Retirement->IsRetired());
    }

    TEST(CanonicalDatagramRegression, ValidationFailureUsesActivityRetirement)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Carrier = std::make_shared<PrismMockTransport>(Context->Io.get_executor());
        auto CloseRequests = std::make_shared<std::size_t>(0);
        using Session = Prism::Protocols::DatagramRelay<TypedFailureDatagramWire>;
        auto Owner = std::make_shared<Session>(
            TypedFailureDatagramWire{
                Carrier, CloseRequests, Fault::Code::InvalidArgument, false},
            Session::Options{{}, {}});
        const auto Activity = Owner->Activity();
        const auto Retirement = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        DatagramRunResult RunResult{};
        std::expected<void, Fault::Failure> DrainResult;

        RunCoro(Context->Io, [&]() -> Net::awaitable<void>
        {
            RunResult = co_await Owner->Run();
            DrainResult = co_await Activity->Drain();
        });

        EXPECT_EQ(DatagramStatus(RunResult), Fault::Code::InvalidArgument);
        EXPECT_TRUE(DrainResult);
        EXPECT_EQ(*CloseRequests, 1U);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(Retirement->IsRetired());
    }

    TEST(CanonicalDatagramRegression, TypedCloseFailureSurfacesThroughActivityDrain)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto Carrier = std::make_shared<PrismMockTransport>(Context->Io.get_executor());
        auto CloseRequests = std::make_shared<std::size_t>(0);
        using Session = Prism::Protocols::DatagramRelay<TypedFailureDatagramWire>;
        auto Owner = std::make_shared<Session>(
            TypedFailureDatagramWire{Carrier, CloseRequests}, Session::Options{{}, {}});
        const auto Activity = Owner->Activity();
        const auto Retirement = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        std::expected<void, Fault::Failure> DrainResult;

        RunCoro(Context->Io, [&]() -> Net::awaitable<void>
        {
            Owner->Close();
            DrainResult = co_await Activity->Drain();
        });

        ASSERT_FALSE(DrainResult);
        EXPECT_EQ(DrainResult.error().Native,
            std::make_error_code(std::errc::io_error));
        EXPECT_EQ(*CloseRequests, 1U);
        EXPECT_FALSE(Carrier->IsClosed());
        EXPECT_GT(Storage->Pending(), 0U);
        EXPECT_FALSE(Retirement->IsRetired());

        Context->Io.restart();
        Context->Io.run();
        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        if (Storage->Pending() != 0)
        {
            Context->Io.restart();
            Storage->Retry();
            Context->Io.run();
        }

        EXPECT_EQ(*CloseRequests, 2U);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(Retirement->IsRetired());
    }

    TEST(CanonicalDatagramRegression, NativeCloseFailureWaitsForExplicitRetirementRetry)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        auto Context = Prism::Executor::ContextOwner::Create(Storage);
        auto State = std::make_shared<DatagramCloseRetryState>();
        auto Carrier = std::make_shared<DatagramCloseRetryTransmission>(
            Context->Io.get_executor(), State);
        auto Dgram = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Dgram, Trojan::DatagramSession::Options{{}, {}});
        const auto Activity = Session->Activity();
        const auto Retirement = std::dynamic_pointer_cast<Prism::Executor::ClosingResource>(Activity);
        ASSERT_TRUE(Retirement);
        DatagramRunResult RunResult{};
        std::expected<void, Fault::Failure> DrainResult;

        RunCoro(Context->Io, [&]() -> Net::awaitable<void>
        {
            RunResult = co_await Session->Run();
            DrainResult = co_await Activity->Drain();
        });

        EXPECT_TRUE(RunResult.has_value());
        ASSERT_FALSE(DrainResult);
        EXPECT_EQ(DrainResult.error().Native,
            std::make_error_code(std::errc::io_error));
        ASSERT_EQ(State->CloseCalls, 1U);
        EXPECT_TRUE(State->Open);
        ASSERT_GT(Storage->Pending(), 0U);

        Context->Io.restart();
        EXPECT_GT(Storage->Pending(), 0U);
        EXPECT_FALSE(Retirement->IsRetired());

        Context->Io.restart();
        Storage->Retry();
        Context->Io.run();
        if (Storage->Pending() != 0)
        {
            Context->Io.restart();
            Storage->Retry();
            Context->Io.run();
        }

        EXPECT_EQ(State->CloseCalls, 2U);
        EXPECT_FALSE(State->Open);
        EXPECT_EQ(Storage->Pending(), 0U);
        EXPECT_TRUE(Retirement->IsRetired());

        Context->Io.restart();
        std::expected<void, Fault::Failure> RecoveredDrain;
        RunCoro(Context->Io, [&]() -> Net::awaitable<void>
        {
            RecoveredDrain = co_await Activity->Drain();
        });
        EXPECT_TRUE(RecoveredDrain);
    }

    TEST(CanonicalDatagramRegression, ConfiguredResolverReachesTypedAssociation)
    {
        Net::io_context Io;
        auto Echo = std::make_shared<Udp::socket>(
            Io.get_executor(), Udp::endpoint(Udp::v4(), 0));
        const auto EchoPort = Echo->local_endpoint().port();
        Net::co_spawn(Io, UdpEchoOnce(Echo), Net::detached);

        auto Carrier = std::make_shared<PrismMockTransport>(Io.get_executor());
        const std::string Payload = "trojan packet";
        const std::string TargetHost = "udp-echo.test";
        Carrier->ToRead = {
            static_cast<std::uint8_t>(Trojan::AddressType::Domain),
            static_cast<std::uint8_t>(TargetHost.size())};
        Carrier->ToRead.insert(Carrier->ToRead.end(), TargetHost.begin(), TargetHost.end());
        Carrier->ToRead.insert(
            Carrier->ToRead.end(),
            {static_cast<std::uint8_t>(EchoPort >> 8),
             static_cast<std::uint8_t>(EchoPort),
             0, static_cast<std::uint8_t>(Payload.size()), '\r', '\n'});
        Carrier->ToRead.insert(Carrier->ToRead.end(), Payload.begin(), Payload.end());
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Traffic = std::make_shared<TrafficRecorder>();
        Prism::Contract::DatagramServices Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        std::size_t ResolveCalls = 0;
        std::string ResolvedHost;
        std::uint16_t ResolvedPort = 0;
        const ConfiguredResolverCallback ResolverCallback{
            ResolveCalls, ResolvedHost, ResolvedPort, EchoPort};
        Options.Resolve = [ResolverCallback](Prism::Network::Target Request)
        {
            return ResolveConfiguredEndpoint(Request, ResolverCallback);
        };
        Options.Traffic = Traffic;
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Owner, Trojan::DatagramSession::Options{
                std::move(Options), {{}, "trojan-udp-user", {}, Prism::Contract::ProtocolType::Trojan,
                    Prism::AccountId{7}}});
        DatagramRunResult Result{
            std::unexpected(Fault::Failure{Fault::Code::GenericError})};

        RunCoro(Io, RunConfiguredResolver(ConfiguredResolverRequest{
            Session, Echo, &Result}));

        EXPECT_TRUE(Result.has_value());
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(ResolveCalls, 1U);
        EXPECT_EQ(ResolvedHost, TargetHost);
        EXPECT_EQ(ResolvedPort, EchoPort);
        ASSERT_EQ(Carrier->Written.size(), Payload.size() + 11U);
        EXPECT_EQ(Carrier->Written[0], static_cast<std::uint8_t>(Trojan::AddressType::Ipv4));
        EXPECT_EQ(Carrier->Written[1], 127);
        EXPECT_EQ(Carrier->Written[2], 0);
        EXPECT_EQ(Carrier->Written[3], 0);
        EXPECT_EQ(Carrier->Written[4], 1);
        EXPECT_EQ(Carrier->Written[5], static_cast<std::uint8_t>(EchoPort >> 8));
        EXPECT_EQ(Carrier->Written[6], static_cast<std::uint8_t>(EchoPort));
        EXPECT_EQ(std::string(Carrier->Written.begin() + 11, Carrier->Written.end()), Payload);
        EXPECT_EQ(Traffic->Calls, 1);
        EXPECT_EQ(Traffic->LastEvent.Account, Prism::AccountId{7});
        EXPECT_EQ(Traffic->Up, Payload.size());
        EXPECT_EQ(Traffic->Down, Payload.size());
    }

    TEST(CanonicalDatagramRegression, CancelDrainsPendingResolveAndRejectsSecondRun)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PrismMockTransport>(Io.get_executor());
        Carrier->ToRead = {3, 1, 'x', 0, 53, 0, 1, '\r', '\n', 42};
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Timer = std::make_shared<Net::steady_timer>(Io);
        std::shared_ptr<Trojan::DatagramSession> Session;
        std::size_t ResolveCalls = 0;
        bool ResolveExited = false;
        const PendingResolveCallback ResolverCallback{
            Io, Session, Timer, ResolveCalls, ResolveExited};
        Prism::Contract::DatagramServices Services;
        Services.Resolve = [ResolverCallback](Prism::Network::Target Target)
        {
            return ResolveUntilCanceled(Target, ResolverCallback);
        };
        Session = Prism::Testing::TrojanDatagram::MakeSession(
            Owner, Trojan::DatagramSession::Options{std::move(Services), {}});
        const auto Start = std::chrono::steady_clock::now();
        RunCoro(Io, RunPendingResolveCancel(PendingResolveCancelRequest{
            Session, &ResolveExited}));
        EXPECT_EQ(ResolveCalls, 1U);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_LT(std::chrono::steady_clock::now() - Start, std::chrono::seconds(1));
    }

    TEST(CanonicalDatagramRegression, CancelDrainsActualDnsQueryBeforeReturning)
    {
        Net::io_context Io;
        auto DnsSocket = std::make_shared<Udp::socket>(
            Io.get_executor(), Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        Prism::Network::Dns::Config Config;
        Config.DisableIpv6 = true;
        Config.TimeoutMs = 30000;
        Prism::Network::Dns::Server Upstream;
        Upstream.Address = "127.0.0.1";
        Upstream.Port = DnsSocket->local_endpoint().port();
        Config.Servers.push_back(Upstream);
        auto Resolver = std::make_shared<Prism::Network::Dns::Resolver>(Io.get_executor(), Config);
        auto Carrier = std::make_shared<PrismMockTransport>(Io.get_executor());
        Carrier->ToRead = {3, 1, 'x', 0, 53, 0, 1, '\r', '\n', 42};
        bool ResolveExited = false;
        Prism::Contract::DatagramServices Services;
        Services.Resolve = [Resolver, &ResolveExited](Prism::Network::Target Target)
        { return ResolveActualDnsEndpoint(std::move(Target), {Resolver, ResolveExited}); };
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Owner, Trojan::DatagramSession::Options{std::move(Services), {}});
        auto Done = std::make_shared<DatagramDoneChannel>(Io, 1);
        RunCoro(Io, RunRealDnsCancel(RealDnsCancelRequest{
            Session, &Session, DnsSocket, Resolver, &Resolver, Done, &ResolveExited}));
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(CanonicalDatagramRegression, IdleTimeoutDrainsActualDnsQueryBeforeReturning)
    {
        Net::io_context Io;
        auto DnsSocket = std::make_shared<Udp::socket>(
            Io.get_executor(), Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        Prism::Network::Dns::Config Config;
        Config.DisableIpv6 = true;
        Config.TimeoutMs = 30000;
        Prism::Network::Dns::Server Upstream;
        Upstream.Address = "127.0.0.1";
        Upstream.Port = DnsSocket->local_endpoint().port();
        Config.Servers.push_back(Upstream);
        auto Resolver = std::make_shared<Prism::Network::Dns::Resolver>(Io.get_executor(), Config);
        auto Carrier = std::make_shared<PrismMockTransport>(Io.get_executor());
        Carrier->ToRead = {3, 1, 'x', 0, 53, 0, 1, '\r', '\n', 42};
        bool ResolveExited = false;
        Prism::Contract::DatagramServices Services;
        Services.IdleTimeout = std::chrono::milliseconds(20);
        Services.Resolve = [Resolver, &ResolveExited](Prism::Network::Target Target)
        { return ResolveActualDnsEndpoint(std::move(Target), {Resolver, ResolveExited}); };
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto Session = Prism::Testing::TrojanDatagram::MakeSession(
            Owner, Trojan::DatagramSession::Options{std::move(Services), {}});
        auto Done = std::make_shared<DatagramDoneChannel>(Io, 1);
        RunCoro(Io, RunIdleDnsTimeout(IdleDnsTimeoutRequest{
            Session, &Session, DnsSocket, Resolver, &Resolver, Done, &ResolveExited}));
        EXPECT_TRUE(Carrier->IsClosed());
    }

}
