/** @file MuxRootFinishTest.cpp @brief Mux child Finish 首因与真实 root 退休回归。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <Prism/Account/Account.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootChild.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootSession.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include "MuxRootCloseTestSupport.hpp"
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include "MuxAcceptSupport.hpp"
#include <array>
#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>

namespace
{
    namespace Net = boost::asio;
}

namespace
{
    auto RunPublishedRootCancellation(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto Root = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, Prism::Mux::RootOptions{});
        Root->Started.store(true, std::memory_order_release);
        EXPECT_FALSE(Root->PublishRunOutcome());
        EXPECT_FALSE(Root->ResourcesRetired.load(std::memory_order_acquire));

        Root->RequestCancel();
        EXPECT_EQ(Root->ExitStatus.load(), Prism::Fault::Code::Success);
        EXPECT_FALSE(Root->TerminalFailure.Load().Failed());

        const auto Activity = Inbound->Activity();
        EXPECT_TRUE(Activity);
        (void)Inbound->Close();
        if (Activity)
        {
            const auto Drained = co_await Activity->Drain();
            EXPECT_TRUE(Drained);
        }
        Root->Inbound.reset();
        Root.reset();
        (void)Peer->Close();
    }
}

TEST(MuxRootOwner, RequestCancelAfterRunOutcomePreservesSuccessfulTerminalState)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunPublishedRootCancellation(Io.get_executor()),
        [&Exception](std::exception_ptr Failure) { Exception = std::move(Failure); });
    Io.run();
    EXPECT_FALSE(Exception);
}

namespace
{
    auto RunCancellationBeforeOutcome(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto Root = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, Prism::Mux::RootOptions{});

        Root->RequestCancel();
        EXPECT_EQ(Root->ExitStatus.load(), Prism::Fault::Code::Canceled);
        Root->Started.store(true, std::memory_order_release);
        Root->RequestCancel();
        EXPECT_EQ(Root->TerminalFailure.Load().Code, Prism::Fault::Code::Canceled);
        EXPECT_TRUE(Root->PublishRunOutcome());

        const auto Activity = Inbound->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity) co_return;
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
        Root->Inbound.reset();
        Root.reset();
        (void)Peer->Close();
    }
}

TEST(MuxRootOwner, RequestCancelBeforeRunOutcomeClaimsTerminalState)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunCancellationBeforeOutcome(Io.get_executor()),
        [&Exception](std::exception_ptr Failure) { Exception = std::move(Failure); });
    Io.run();
    EXPECT_FALSE(Exception);
}

namespace
{
    auto RunRootCloseWithoutCancelFailure(Net::any_io_executor Executor)
        -> Net::awaitable<void>
    {
        auto [PeerRaw, InboundRaw] = Prism::MakeMemoryPair(Executor);
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto State = std::make_shared<Prism::Mux::Detail::RootState>(
            Inbound, Prism::Mux::RootOptions{});
        State->Started.store(true, std::memory_order_release);
        auto Root = Prism::Mux::Testing::RootSessionStateFixture::CreateSession(State);

        Root->Close();
        const auto Activity = Root->Activity();
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_EQ(State->ExitStatus.load(), Prism::Fault::Code::Success);
        EXPECT_FALSE(State->TerminalFailure.Load().Failed());
        EXPECT_TRUE(Root->IsRetired());
        (void)Peer->Close();
    }
}

TEST(MuxRootOwner, CloseDrainsWithoutPublishingCancellationFailure)
{
    Net::io_context Io;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunRootCloseWithoutCancelFailure(Io.get_executor()),
        [&Exception](std::exception_ptr Failure) { Exception = std::move(Failure); });
    Io.run();
    EXPECT_FALSE(Exception);
}
