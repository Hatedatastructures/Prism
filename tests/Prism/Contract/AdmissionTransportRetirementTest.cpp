/**
 * @file AdmissionTransportRetirementTest.cpp
 * @brief 入站传输关闭提交错误、首因与 drain 重试状态测试。
 */
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Ingress/AdmissionTransportRetirement.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using RetirementResult = Prism::Contract::AdmissionRetirementResult;
    using DrainResult = std::expected<void, Prism::Fault::Failure>;

    /** @brief 为每次 drain 指定返回失败、抛异常与物理退休事实。 */
    struct DrainStep final
    {
        Prism::Fault::Failure Failure{};
        std::error_code Exception{};
        bool Retired{false};
    };

    /** @brief 一次 admission retirement 调用的可复用输入与提交状态。 */
    struct RetirementRequest final
    {
        Net::io_context& Io;
        const Prism::SharedTransmission& Transport;
        bool CancelAttempted{false};
        bool CloseAttempted{false};
    };

    /** @brief 退休结果及本次调用观察到的控制提交状态。 */
    struct RetirementObservation final
    {
        RetirementResult Result;
        bool CancelAttempted{false};
        bool CloseAttempted{false};
    };

    /** @brief 只模拟 Activity 的等待和真实退休回执，不替代 Transmission 控制前门。 */
    class ScriptedActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        ScriptedActivity(Net::any_io_executor Executor, std::vector<DrainStep> Steps)
            : Executor_(std::move(Executor)), Steps_(std::move(Steps))
        {
        }

        auto Seal() noexcept -> void override { ++SealCalls; }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_;
        }

        [[nodiscard]] auto Drain() -> Net::awaitable<DrainResult> override
        {
            if (SealCalls != DrainCalls + 1U) SealPrecedesEachDrain = false;
            ++DrainCalls;
            if (NextStep_ >= Steps_.size())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            const auto Step = Steps_[NextStep_++];
            if (Step.Exception)
            {
                throw std::system_error(Step.Exception);
            }
            Retired_ = Step.Retired;
            if (Step.Failure.Failed()) co_return std::unexpected(Step.Failure);
            co_return DrainResult{};
        }

        std::size_t SealCalls{0};
        std::size_t DrainCalls{0};
        bool SealPrecedesEachDrain{true};

    private:
        Net::any_io_executor Executor_;
        std::vector<DrainStep> Steps_;
        std::size_t NextStep_{0};
        bool Retired_{false};
    };

    /** @brief 将控制命令提交到真实 Transmission 前门，并注入可脚本化 Activity。 */
    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(
            Net::any_io_executor Executor,
            std::shared_ptr<ScriptedActivity> Activity)
            : Transmission(std::move(Executor)), Activity_(std::move(Activity))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        std::size_t CancelCalls{0};
        std::size_t CloseCalls{0};

    private:
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            PostResult(Executor(), std::move(Handler),
                {0, {Prism::Fault::Code::NotSupported}});
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            PostResult(Executor(), std::move(Handler),
                {0, {Prism::Fault::Code::NotSupported}});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            PostResult(Executor(), std::move(Handler),
                {0, {Prism::Fault::Code::NotSupported}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCalls;
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++CancelCalls;
            return {};
        }

        std::shared_ptr<ScriptedActivity> Activity_;
    };

    /** @brief 驱动一次退休协程并返回完整关闭/drain 回执。 */
    auto RunRetirement(RetirementRequest& Request) -> RetirementObservation
    {
        std::optional<RetirementResult> Outcome;
        std::exception_ptr Exception;
        Request.Io.restart();
        Net::co_spawn(Request.Io,
            Prism::Contract::RetireAdmissionTransport(
                Request.Transport, Request.CancelAttempted, Request.CloseAttempted),
            [&](std::exception_ptr Error, RetirementResult Value)
            {
                Exception = std::move(Error);
                Outcome.emplace(std::move(Value));
            });
        Request.Io.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Outcome.has_value());
        if (!Outcome)
        {
            return {
                {false, Prism::Fault::Failure{Prism::Fault::Code::Blocked}},
                Request.CancelAttempted,
                Request.CloseAttempted};
        }
        return {
            std::move(*Outcome),
            Request.CancelAttempted,
            Request.CloseAttempted};
    }
}

/**
 * @brief 不拥有基对象的 alias 触发同步提交拒绝；不模拟真实 socket 关闭失败。
 * @details 验证 Cancel/Close 的 InvalidArgument 首因、attempt 标志和重试时不重复提交。
 */
TEST(AdmissionTransportRetirement, UnownedAliasKeepsFirstFailureAndSkipsSubmissionOnRetry)
{
    Net::io_context Io;
    const auto DrainFailure = Prism::Fault::FromNative(
        std::make_error_code(std::errc::connection_reset));
    auto Activity = std::make_shared<ScriptedActivity>(Io.get_executor(),
        std::vector<DrainStep>{{DrainFailure, {}, false}, {{}, {}, true}});
    ScriptedTransmission Owner(Io.get_executor(), Activity);
    auto Lifetime = std::make_shared<int>(0);
    Prism::SharedTransmission Transport(Lifetime, &Owner);
    ASSERT_TRUE(Owner.weak_from_this().expired());
    RetirementRequest Request{Io, Transport};

    const auto First = RunRetirement(Request);
    EXPECT_FALSE(First.Result.Complete);
    EXPECT_EQ(First.Result.Error.Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_FALSE(First.Result.Error.Native);
    EXPECT_TRUE(First.CancelAttempted);
    EXPECT_TRUE(First.CloseAttempted);
    EXPECT_EQ(Activity->DrainCalls, 1U);
    EXPECT_EQ(Activity->SealCalls, 1U);
    EXPECT_TRUE(Activity->SealPrecedesEachDrain);

    const auto Retry = RunRetirement(Request);
    EXPECT_TRUE(Retry.Result.Complete);
    EXPECT_FALSE(Retry.Result.Error.Failed());
    EXPECT_TRUE(Retry.CancelAttempted);
    EXPECT_TRUE(Retry.CloseAttempted);
    EXPECT_EQ(Activity->DrainCalls, 2U);
    EXPECT_EQ(Activity->SealCalls, 2U);
    EXPECT_TRUE(Activity->SealPrecedesEachDrain);
}

/** @brief drain 抛出原生异常时保留 Native，并允许后续 drain 真实退休。 */
TEST(AdmissionTransportRetirement, MapsDrainExceptionAndAllowsRetirementRetry)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_aborted);
    auto Activity = std::make_shared<ScriptedActivity>(Io.get_executor(),
        std::vector<DrainStep>{{{}, Native, false}, {{}, {}, true}});
    ScriptedTransmission Owner(Io.get_executor(), Activity);
    auto Lifetime = std::make_shared<int>(0);
    Prism::SharedTransmission Transport(Lifetime, &Owner);
    RetirementRequest Request{Io, Transport, true, true};

    const auto First = RunRetirement(Request);
    EXPECT_FALSE(First.Result.Complete);
    EXPECT_EQ(First.Result.Error.Code, Prism::Fault::Code::ConnectionAborted);
    EXPECT_EQ(First.Result.Error.Native, Native);
    EXPECT_TRUE(First.CancelAttempted);
    EXPECT_TRUE(First.CloseAttempted);
    EXPECT_EQ(Activity->DrainCalls, 1U);
    EXPECT_EQ(Activity->SealCalls, 1U);
    EXPECT_TRUE(Activity->SealPrecedesEachDrain);

    const auto Retry = RunRetirement(Request);
    EXPECT_TRUE(Retry.Result.Complete);
    EXPECT_FALSE(Retry.Result.Error.Failed());
    EXPECT_TRUE(Retry.CancelAttempted);
    EXPECT_TRUE(Retry.CloseAttempted);
    EXPECT_EQ(Activity->DrainCalls, 2U);
    EXPECT_EQ(Activity->SealCalls, 2U);
    EXPECT_TRUE(Activity->SealPrecedesEachDrain);
}

/** @brief 控制命令成功受理后，Drain 返回的 typed/native 首因可在显式重试前交付。 */
TEST(AdmissionTransportRetirement, PreservesReturnedDrainFailureAfterAcceptedClose)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const Prism::Fault::Failure DrainFailure{Prism::Fault::Code::IoError, Native};
    auto Activity = std::make_shared<ScriptedActivity>(Io.get_executor(),
        std::vector<DrainStep>{{DrainFailure, {}, false}, {{}, {}, true}});
    auto Owner = std::make_shared<ScriptedTransmission>(Io.get_executor(), Activity);
    Prism::SharedTransmission Transport = Owner;
    RetirementRequest Request{Io, Transport};

    const auto First = RunRetirement(Request);
    EXPECT_FALSE(First.Result.Complete);
    EXPECT_EQ(First.Result.Error.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(First.Result.Error.Native, Native);
    EXPECT_TRUE(First.CancelAttempted);
    EXPECT_TRUE(First.CloseAttempted);
    EXPECT_EQ(Owner->CancelCalls, 1U);
    EXPECT_EQ(Owner->CloseCalls, 1U);
    EXPECT_EQ(Activity->DrainCalls, 1U);
    EXPECT_EQ(Activity->SealCalls, 1U);
    EXPECT_TRUE(Activity->SealPrecedesEachDrain);

    const auto Retry = RunRetirement(Request);
    EXPECT_TRUE(Retry.Result.Complete);
    EXPECT_FALSE(Retry.Result.Error.Failed());
    EXPECT_TRUE(Retry.CancelAttempted);
    EXPECT_TRUE(Retry.CloseAttempted);
    EXPECT_EQ(Owner->CancelCalls, 1U);
    EXPECT_EQ(Owner->CloseCalls, 1U);
    EXPECT_EQ(Activity->DrainCalls, 2U);
    EXPECT_EQ(Activity->SealCalls, 2U);
    EXPECT_TRUE(Activity->SealPrecedesEachDrain);
}
