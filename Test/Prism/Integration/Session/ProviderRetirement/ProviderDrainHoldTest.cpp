/** @file ProviderDrainHoldTest.cpp @brief 验证未退栈接入阻止材料释放。 */
#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/ProviderLifecycle/ProviderBindingLifecycle.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace Prism::Testing
{
    namespace Net = boost::asio;

    class AdmissionDrainGeneration final : public Prism::Foundation::GenerationLifetime
    {
    public:
        [[nodiscard]] auto Id() const noexcept -> Prism::GenerationId override { return {}; }
    };

    struct AdmissionDrainMaterial final
    {
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        Net::any_io_executor Executor;
    };

    using AdmissionDrainBinding =
        Prism::Protocols::ProviderBindingLifecycle<AdmissionDrainMaterial>;
    using AdmissionDrainResult = Prism::Protocols::ProviderRetirementResult;

    [[nodiscard]] auto RunAdmissionDrain(
        Net::io_context& Context,
        Net::awaitable<AdmissionDrainResult> Operation) -> AdmissionDrainResult
    {
        std::optional<AdmissionDrainResult> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Context, std::move(Operation),
            [&Result, &Exception](std::exception_ptr Error, AdmissionDrainResult Value)
            {
                Exception = std::move(Error);
                Result.emplace(std::move(Value));
            });
        Context.run();
        if (Exception) std::rethrow_exception(Exception);
        if (!Result) throw std::runtime_error("provider drain did not complete");
        return std::move(*Result);
    }

    TEST(ProviderSessionRetirement, BlockedAdmissionDrainRetainsMaterialUntilAttemptCompletes)
    {
        auto Storage = std::make_shared<Prism::Executor::ClosingStorage>();
        const auto Context = Prism::Executor::ContextOwner::Create(Storage);
        const auto Executor = Context->Io.get_executor();
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Material = std::make_shared<const AdmissionDrainMaterial>(AdmissionDrainMaterial{
            std::make_shared<AdmissionDrainGeneration>(), UseState, Executor});
        AdmissionDrainBinding Binding(Material);
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Executor);
        auto Attempt = Binding.Begin(Transport);
        ASSERT_TRUE(Attempt);
        const auto Ticket = Attempt->Owner();
        Attempt->FinishProtocol();
        Binding.Close();

        const auto TicketDrain = RunAdmissionDrain(Context->Io, Ticket->Drain());
        ASSERT_TRUE(TicketDrain);
        ASSERT_TRUE(Ticket->IsRetired());
        ASSERT_TRUE(Context->Io.stopped());
        EXPECT_FALSE(Binding.IsRetired());

        Net::io_context DrainContext;
        const auto BlockedDrain = RunAdmissionDrain(DrainContext, Binding.Drain());
        ASSERT_FALSE(BlockedDrain);
        EXPECT_EQ(BlockedDrain.error().Code, Prism::Fault::Code::Blocked);
        EXPECT_EQ(Binding.DrainFailure().Code, Prism::Fault::Code::Blocked);
        EXPECT_EQ(Binding.Material(), Material);
        EXPECT_EQ(Binding.UseState(), UseState);
        EXPECT_FALSE(Binding.IsRetired());

        Context->Io.restart();
        Attempt->Complete();
        const auto RetryDrain = RunAdmissionDrain(Context->Io, Binding.Drain());
        ASSERT_FALSE(RetryDrain);
        EXPECT_EQ(RetryDrain.error().Code, Prism::Fault::Code::Blocked);
        EXPECT_TRUE(Binding.IsRetired());
        EXPECT_FALSE(Binding.Material());
        EXPECT_FALSE(Binding.UseState());
    }
}
