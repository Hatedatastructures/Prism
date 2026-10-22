/** @file CanonicalWorkspaceTest.cpp @brief 多包字面载荷与串行工作区的取消安全。 */
#include <gtest/gtest.h>
#include <Prism/Protocols/Trojan/DatagramSession.hpp>
#include "TrojanDatagramTestSupport.hpp"
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <new>

namespace AllocationObservation
{
    std::atomic<bool> Enabled{false};
    std::atomic<std::size_t> LargeBuffers{0};
}

/** @brief 仅在真实多包会话运行期计数 65535 字节工作区申请；标准分配签名。 */
auto operator new(std::size_t Size) -> void*
{
    if (AllocationObservation::Enabled.load(std::memory_order_relaxed) && Size == 65535)
        AllocationObservation::LargeBuffers.fetch_add(1, std::memory_order_relaxed);
    if (auto* Value = std::malloc(Size == 0 ? 1 : Size)) return Value;
    throw std::bad_alloc();
}
auto operator delete(void* Value) noexcept -> void { std::free(Value); }
auto operator delete(void* Value, std::size_t) noexcept -> void { std::free(Value); }

namespace
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;
    class WorkspaceScenario final
    {
    public:
        explicit WorkspaceScenario(bool ConcurrentReplies = false)
            : ConcurrentReplies_(ConcurrentReplies)
        {
            Echo = std::make_shared<Udp::socket>(Io, Udp::endpoint(Net::ip::address_v4::loopback(), 0));
            Carrier = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
            const auto Port = Echo->local_endpoint().port();
            const std::array<std::vector<std::uint8_t>, 3> StandardPayloads{{
                {'a', 'b', 'c'}, {42}, {'z', 'y', 'x', 'w', 'v'}}};
            const std::array<std::vector<std::uint8_t>, 3> ConcurrentPayloads{{
                {'a', 'b', 'c'}, {}, {'z', 'y', 'x', 'w', 'v'}}};
            const auto& Payloads = ConcurrentReplies_ ? ConcurrentPayloads : StandardPayloads;
            for (std::size_t Index = 0; Index < Payloads.size(); ++Index)
            {
                const auto& Payload = Payloads[Index];
                const std::array<std::uint8_t, 9> Header{3, 1, 'x', static_cast<std::uint8_t>(Port >> 8),
                    static_cast<std::uint8_t>(Port), 0, static_cast<std::uint8_t>(Payload.size()), '\r', '\n'};
                Carrier->ToRead.insert(Carrier->ToRead.end(), Header.begin(), Header.end());
                Carrier->ToRead.insert(Carrier->ToRead.end(), Payload.begin(), Payload.end());
                if (ConcurrentReplies_ && Index == 0U) continue;
                const std::array<std::uint8_t, 11> Reply{1, 127, 0, 0, 1, static_cast<std::uint8_t>(Port >> 8),
                    static_cast<std::uint8_t>(Port), 0, static_cast<std::uint8_t>(Payload.size()), '\r', '\n'};
                const auto Copies = ConcurrentReplies_ && Index == 1U ? 2U : 1U;
                for (std::size_t Copy = 0; Copy < Copies; ++Copy)
                {
                    Expected.insert(Expected.end(), Reply.begin(), Reply.end());
                    Expected.insert(Expected.end(), Payload.begin(), Payload.end());
                }
            }
            Traffic = std::make_shared<Prism::Testing::TrafficRecorder>();
            Prism::Contract::DatagramServices Services;
            Services.IdleTimeout = std::chrono::milliseconds(20);
            Services.Traffic = Traffic;
            Services.Resolve = [Endpoint = Echo->local_endpoint()](Prism::Network::Target)
                -> Net::awaitable<std::expected<Udp::endpoint, Prism::Fault::Failure>>
            { co_return Endpoint; };
            auto Wire = std::make_shared<Prism::Trojan::Dgram<>>(Carrier);
            Session = Prism::Testing::TrojanDatagram::MakeSession(
                Wire, Prism::Trojan::DatagramSession::Options{Services, {}});
        }
        auto Run() -> Net::awaitable<void>
        {
            Net::co_spawn(Io, EchoPackets(), [](std::exception_ptr Error) { EXPECT_FALSE(Error); });
            AllocationObservation::LargeBuffers.store(0, std::memory_order_relaxed);
            AllocationObservation::Enabled.store(true, std::memory_order_relaxed);
            const auto Status = co_await Session->Run();
            AllocationObservation::Enabled.store(false, std::memory_order_relaxed);
            const auto Allocations = AllocationObservation::LargeBuffers.load(std::memory_order_relaxed);
            const auto PayloadBytes = ConcurrentReplies_ ? 8U : 9U;
            const auto ReplyBytes = ConcurrentReplies_ ? 5U : 9U;
            std::cout << "Packets=3 PayloadBytes=" << PayloadBytes
                      << " Replies=" << (ConcurrentReplies_ ? 3U : 3U)
                      << " LargeWorkspaceAllocations=" << Allocations << '\n';
            EXPECT_TRUE(Status.has_value());
            // 双地址族 receiver 使用固定 std::array 工作区，不再申请 65535 字节堆缓冲。
            EXPECT_EQ(Allocations, 0U);
            EXPECT_EQ(Carrier->Written, Expected);
            EXPECT_TRUE(Carrier->IsClosed());
            EXPECT_EQ(Traffic->Calls, 1);
            EXPECT_EQ(Traffic->Up, PayloadBytes);
            EXPECT_EQ(Traffic->Down, ReplyBytes);
            Session->Close();
            Session->Close();
            EXPECT_EQ(Traffic->Calls, 1);
            Echo->close();
        }
        Net::io_context Io;
    private:
        auto EchoPackets() -> Net::awaitable<void>
        {
            Udp::socket Rogue(Io, Udp::endpoint(Net::ip::address_v4::loopback(), 0));
            std::array<std::byte, 64> Buffer{};
            for (std::size_t Index = 0; Index < 3; ++Index)
            {
                Udp::endpoint Peer;
                const auto Size = co_await Echo->async_receive_from(Net::buffer(Buffer), Peer, Net::use_awaitable);
                if (ConcurrentReplies_ && Index == 0U) continue;
                if (ConcurrentReplies_ && Index == 1U)
                {
                    const std::array<std::uint8_t, 1> Spoofed{0xFF};
                    co_await Rogue.async_send_to(Net::buffer(Spoofed), Peer, Net::use_awaitable);
                }
                co_await Echo->async_send_to(Net::buffer(Buffer.data(), Size), Peer, Net::use_awaitable);
                if (ConcurrentReplies_ && Index == 1U)
                    co_await Echo->async_send_to(Net::buffer(Buffer.data(), Size), Peer, Net::use_awaitable);
            }
        }
        const bool ConcurrentReplies_;
        std::shared_ptr<Udp::socket> Echo;
        std::shared_ptr<Prism::PrismMockTransport> Carrier;
        std::shared_ptr<Prism::Testing::TrafficRecorder> Traffic;
        std::shared_ptr<Prism::Trojan::DatagramSession> Session;
        std::vector<std::uint8_t> Expected;
    };
    TEST(CanonicalDatagramWorkspace, MultipleLiteralPacketsReuseReplyWorkspace)
    {
        WorkspaceScenario Scenario;
        Prism::Testing::RunCoro(Scenario.Io, [&Scenario]() -> Net::awaitable<void>
        { co_await Scenario.Run(); });
    }
    TEST(CanonicalDatagramWorkspace, IndependentPumpsHandleSilentEmptyAndMultiReply)
    {
        WorkspaceScenario Scenario(true);
        Prism::Testing::RunCoro(Scenario.Io, [&Scenario]() -> Net::awaitable<void>
        { co_await Scenario.Run(); });
    }

    TEST(CanonicalDatagramWorkspace, EmptyCarrierReturnsTypedFailureBeforePumpConstruction)
    {
        const std::shared_ptr<Prism::Trojan::Dgram<>> EmptyCarrier;
        const auto Result = Prism::Trojan::DatagramSession::Create(
            EmptyCarrier, Prism::Trojan::DatagramSession::Options{});
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
    }
}
