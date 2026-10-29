/**
 * @file BootstrapPriorityTest.cpp
 * @brief 完整 sing-mux bootstrap 的读取终态优先级回归。
 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

#include <Prism/Contract/Ingress/MuxSession.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Protocols/Mux/Root/Session.hpp>
#include <Prism/Protocols/Mux/Root/State.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/Mux/RootOptions.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/MuxRoot.hpp>
#include "RootCloseTestSupport.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace F = Prism::Testing::MuxRoot;

    class CompleteBootstrapTerminal final : public Prism::Transmission
    {
    public:
        CompleteBootstrapTerminal(
            Net::any_io_executor Executor,
            const Prism::Fault::Failure Terminal)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              Terminal_(Terminal)
        {}

        auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            ++ReadCalls_;
            if (ReadCalls_ == 1U)
            {
                constexpr std::array<std::byte, 2> Wire{
                    std::byte{0x00}, std::byte{0x01}};
                const auto Count = std::min(Buffer.size(), Wire.size());
                std::copy_n(Wire.begin(), Count, Buffer.begin());
                Prism::Transmission::PostResult(
                    Executor_, std::move(Handler), Prism::IoResult{Count, Terminal_});
                return;
            }
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{0U, Terminal_});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++WriteCalls_;
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{Buffer.size(), {}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transmission::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{});
        }

        auto OnClose() -> ControlResult override { return {}; }
        auto OnCancel() -> ControlResult override { return {}; }

        std::size_t ReadCalls_{0U};
        std::size_t WriteCalls_{0U};

    private:
        Net::any_io_executor Executor_;
        Prism::Fault::Failure Terminal_;
    };

    struct TerminalPriorityOutcome final
    {
        Prism::Fault::Failure SetupFailure;
        Prism::Fault::Failure RunFailure;
        Prism::Mux::Mode SelectedWire{Prism::Mux::Mode::Auto};
        std::size_t ReadCalls{0U};
        std::size_t WriteCalls{0U};
        std::size_t OutstandingUses{0U};
        std::size_t EngineTasksStarted{0U};
        bool RunSucceeded{false};
        bool EngineOwnerCreated{false};
    };

    auto RunTerminalPriorityScenario(Net::any_io_executor Executor)
        -> Net::awaitable<TerminalPriorityOutcome>
    {
        TerminalPriorityOutcome Outcome;
        const auto Terminal = Prism::Fault::FromNative(
            std::make_error_code(std::errc::connection_reset));
        auto Raw = std::make_shared<CompleteBootstrapTerminal>(Executor, Terminal);
        auto Fixture = std::make_shared<F::State>(Executor);
        const auto UseState = Fixture->UseState;
        auto Binding = std::make_shared<Prism::Mux::RootBinding>(Prism::Mux::RootOptions{
            .Wire = Prism::Mux::Mode::Smux,
            .Services = {.Egress = std::make_shared<F::Egress>(Fixture)},
            .GenerationUseState = UseState});

        auto Created = co_await F::CreateRoot(Binding, Raw);
        if (!Created)
        {
            Outcome.SetupFailure = Created.error();
            co_return Outcome;
        }
        auto Session = std::move(Created->Session);
        auto Plane = std::move(Created->Plane);
        if (auto *Mux = Plane.Mux()) Mux->Session.reset();
        const auto Root = std::static_pointer_cast<Prism::Mux::Detail::RootSession>(Session);
        const auto State = Prism::Mux::Testing::RootSessionStateFixture::State(Root);
        Prism::Contract::MuxRootRequest Request{.GenerationUseState = UseState};
        const auto Run = co_await Session->Run(std::move(Request));

        Outcome.RunSucceeded = Run.has_value();
        if (!Run) Outcome.RunFailure = Run.error();
        Outcome.SelectedWire = State->SelectedWire;
        Outcome.EngineOwnerCreated = static_cast<bool>(State->EngineControl);
        Outcome.ReadCalls = Raw->ReadCalls_;
        Outcome.WriteCalls = Raw->WriteCalls_;
        Outcome.OutstandingUses = UseState->Outstanding();
        Outcome.EngineTasksStarted = State->Loops->Stats().Started;
        co_return Outcome;
    }
}

TEST(MuxService, CompleteBootstrapTerminalPrecedesConfiguredWireMismatch)
{
    Net::io_context Io;
    std::optional<TerminalPriorityOutcome> Outcome;
    std::exception_ptr Exception;
    Net::co_spawn(Io, RunTerminalPriorityScenario(Io.get_executor()),
        [&Outcome, &Exception](std::exception_ptr Failure, TerminalPriorityOutcome Result)
        {
            Exception = std::move(Failure);
            Outcome = std::move(Result);
        });
    Io.run();

    ASSERT_FALSE(Exception);
    ASSERT_TRUE(Outcome);
    const auto Expected = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    EXPECT_FALSE(Outcome->SetupFailure.Failed());
    EXPECT_FALSE(Outcome->RunSucceeded);
    EXPECT_EQ(Outcome->RunFailure.Code, Expected.Code);
    EXPECT_EQ(Outcome->RunFailure.Native, Expected.Native);
    EXPECT_EQ(Outcome->SelectedWire, Prism::Mux::Mode::Auto);
    EXPECT_FALSE(Outcome->EngineOwnerCreated);
    EXPECT_EQ(Outcome->EngineTasksStarted, 0U);
    EXPECT_EQ(Outcome->ReadCalls, 1U);
    EXPECT_EQ(Outcome->WriteCalls, 0U);
    EXPECT_EQ(Outcome->OutstandingUses, 0U);
}
