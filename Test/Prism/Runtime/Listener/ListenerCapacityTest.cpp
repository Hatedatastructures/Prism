/**
 * @file ListenerCapacityTest.cpp
 * @brief TcpListener 连接配额（Runtime.MaxConnections）行为契约。
 * @details 覆盖上限内会话持续持有配额、超额连接在进入会话工厂前被拒绝的语义。
 */

#include "ListenerTestSupport.hpp"

#include <TestSupport/Fixtures/StreamFactory.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

namespace
{

    /**
     * @brief 阻塞在长定时器上的 accept 处理，使会话在测试期间持续持有准入配额。
     * @details 配额由 ListenerConnectionDrain 持有的 Reservation 归还，只有会话
     *          真实退出才会释放；因此这里必须让会话保持存活而不是立刻返回。
     */
    auto BlockOnAccept(Prism::Contract::StreamAcceptInput)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        Timer.expires_after(std::chrono::hours(1));
        boost::system::error_code Error;
        co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::Canceled, Error});
        }
        co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Timeout});
    }

    /** @brief 建立真实会话并在其存活期间持有 listener 连接配额。 */
    struct CapacitySessionFactory final
    {
        Prism::Runtime::WorkerGroup *Workers{};
        std::atomic<int> *FactoryCalls{};

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            FactoryCalls->fetch_add(1, std::memory_order_relaxed);
            Prism::Runtime::SessionOptions Options;
            Options.SourceIp = std::move(Admission.SourceIp);
            Options.Services->Generation = Admission.Generation;
            Options.Services->Bytes = RequireWorkerBytePool(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                &BlockOnAccept);
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    /** @brief 推进执行器直到谓词成立或期限结束；返回谓词最终结果。 */
    auto PumpUntil(
        Net::io_context &IoContext,
        const std::function<bool()> &Predicate,
        const std::chrono::milliseconds Limit) -> Net::awaitable<bool>
    {
        const auto Deadline = std::chrono::steady_clock::now() + Limit;
        while (std::chrono::steady_clock::now() < Deadline)
        {
            if (Predicate())
            {
                co_return true;
            }
            Net::steady_timer Tick(IoContext);
            Tick.expires_after(std::chrono::milliseconds(5));
            co_await Tick.async_wait(Net::use_awaitable);
        }
        co_return Predicate();
    }

    struct CapacityRequest final
    {
        Net::io_context &IoContext;
        Prism::Runtime::TcpListener &Listener;
        std::atomic<int> &FactoryCalls;
        int Limit{0};
        int Overflow{0};
    };

    /**
     * @brief 用满配额后继续建连，验证超额连接在进入会话工厂前被拒绝。
     * @details 上限内的会话保持存活以持续持有配额；随后建立的连接只完成 TCP
     *          握手就被 admission 关闭，因此工厂调用次数必须停在上限值。
     */
    auto RunCapacityScenario(CapacityRequest Request) -> Net::awaitable<void>
    {
        const auto Started = co_await Request.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Started, Prism::Fault::Code::Success);
        const auto Port = Request.Listener.LocalEndpoint().port();
        if (Port == 0)
        {
            co_return;
        }

        std::vector<Prism::SharedTransmission> Held;
        Held.reserve(static_cast<std::size_t>(Request.Limit));
        for (int Index = 0; Index < Request.Limit; ++Index)
        {
            Prism::Network::Dialer::Dialer Dialer(Request.IoContext.get_executor());
            auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Port});
            if (Dialed)
            {
                Held.push_back(std::move(*Dialed));
            }
        }
        EXPECT_EQ(Held.size(), static_cast<std::size_t>(Request.Limit));

        const auto Saturated = co_await PumpUntil(Request.IoContext,
            [&Request]
            { return Request.FactoryCalls.load(std::memory_order_acquire) >= Request.Limit; },
            std::chrono::seconds(5));
        EXPECT_TRUE(Saturated) << "上限内的会话未在期限内进入工厂";

        for (int Index = 0; Index < Request.Overflow; ++Index)
        {
            Prism::Network::Dialer::Dialer Dialer(Request.IoContext.get_executor());
            auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Port});
            if (Dialed)
            {
                (void)(*Dialed)->Close();
            }
        }

        // 越过上限的连接必须在进入工厂前被拒绝；这里只推进事件循环，不等待任何成功条件。
        const auto Settled = co_await PumpUntil(Request.IoContext, [] { return false; },
            std::chrono::milliseconds(200));
        EXPECT_FALSE(Settled);
        EXPECT_EQ(Request.FactoryCalls.load(std::memory_order_acquire), Request.Limit)
            << "超额连接穿过了连接配额进入会话工厂";

        for (auto &Connection : Held)
        {
            (void)Connection->Close();
        }
    }

} // namespace

TEST(TcpListener, MaxConnectionsRejectsAdmissionBeforeSessionFactory)
{
    Net::io_context Ioc;
    Prism::Runtime::Process::Options ProcessOptions;
    ProcessOptions.Id = Prism::ProcessId{61};
    ProcessOptions.Generation = Prism::GenerationId{71};
    ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
        ProcessOptions.Generation);
    ProcessOptions.WorkerCount = 1;
    Prism::Runtime::Process ProcessValue(ProcessOptions);
    WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

    std::atomic<int> FactoryCalls{0};
    Prism::Runtime::TcpListener::Options ListenerOptions;
    ListenerOptions.Executor = Ioc.get_executor();
    ListenerOptions.Workers = &ProcessValue.Workers();
    ListenerOptions.Publication = ProcessOptions.Publication;
    ListenerOptions.MaxConnections = 2;
    ListenerOptions.Factory = CapacitySessionFactory{&ProcessValue.Workers(), &FactoryCalls};
    Prism::Runtime::TcpListener Listener(std::move(ListenerOptions));
    EXPECT_EQ(Listener.MaxConnections(), std::size_t{2});

    RunCoro(Ioc, RunCapacityScenario(CapacityRequest{Ioc, Listener, FactoryCalls, 2, 3}));
}
