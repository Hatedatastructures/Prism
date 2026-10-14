/**
 * @file MuxSessionOwnershipAuditTest.cpp
 * @brief Mux session cycle ownership audit。
 */
#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>
#include <memory>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include "MuxSessionTestSupport.hpp"
namespace
{
    namespace Net = boost::asio;
    using MuxSession = Preview::Mux::Smux::Session<>;

    struct OwnershipAuditRequest final
    {
        Net::io_context &IoContext;
        std::weak_ptr<MuxSession> &WeakSession;
        bool &Connected;
        bool &Opened;
    };

    auto RunMuxSessionCycle(OwnershipAuditRequest Request) -> Net::awaitable<void>
    {
        auto [ClientMemoryValue, ServerMemoryValue] = Preview::MakeMemoryPair(
            Request.IoContext.get_executor());
        auto ClientMemory = std::make_shared<Preview::MemoryStream>(std::move(ClientMemoryValue));
        auto ServerMemory = std::make_shared<Preview::MemoryStream>(std::move(ServerMemoryValue));

        Preview::Mux::Smux::Client<> Client;
        Request.Connected = Client.Connect(ClientMemory);
        auto Stream = co_await Client.OpenStream();
        Request.Opened = Stream != nullptr;
        auto Session = Client.Session();
        Request.WeakSession = Session;
        Stream.reset();

        ServerMemory->Close();
        co_await Session->Close();
        const auto ClientActivity = ClientMemory->Activity();
        const auto ClientDrained = co_await ClientActivity->Drain();
        EXPECT_TRUE(ClientDrained);
        EXPECT_TRUE(ClientActivity->IsRetired());
        const auto ServerActivity = ServerMemory->Activity();
        const auto ServerDrained = co_await ServerActivity->Drain();
        EXPECT_TRUE(ServerDrained);
        EXPECT_TRUE(ServerActivity->IsRetired());
        Session.reset();
    }
}
TEST(OwnershipAudit, MuxSessionCycleLeak)
    {
        Net::io_context IoContext;
        std::weak_ptr<Preview::Mux::Smux::Session<>> WeakSession;
        bool Connected = false;
        bool Opened = false;

        Preview::Testing::MuxSession::RunJoinedCoro(
            IoContext,
            RunMuxSessionCycle(OwnershipAuditRequest{
                IoContext, WeakSession, Connected, Opened}));

        EXPECT_TRUE(Connected);
        EXPECT_TRUE(Opened);
        // 修复前：Session ↔ StreamHandle 循环引用 → WeakSession 未过期（泄漏）
        // 修复后：Teardown 清空流表 → Session 析构
        EXPECT_TRUE(WeakSession.expired());
    }



