/**
 * @file MuxScenarioAsserts.hpp
 * @brief 配置化 Mux 单根场景的结果断言.
 */
#pragma once

#include "MuxScenarioSetup.hpp"

namespace
{
template <typename State>
auto ExpectScenarioSetup(const std::shared_ptr<State> &StateValue) -> void
{
    ASSERT_TRUE(StateValue);
    EXPECT_FALSE(StateValue->Failure);
    EXPECT_FALSE(StateValue->TimedOut) << StateValue->FailureMessage;
    EXPECT_TRUE(StateValue->FailureMessage.empty()) << StateValue->FailureMessage;
}

auto VerifyConfiguredMuxScenario(const std::shared_ptr<ScenarioState> &State) -> void
{
    ASSERT_TRUE(State);
    EXPECT_FALSE(State->Failure);
    EXPECT_FALSE(State->TimedOut) << State->FailureMessage;
    EXPECT_TRUE(State->FailureMessage.empty()) << State->FailureMessage;
    EXPECT_TRUE(State->Authenticated);
    EXPECT_TRUE(State->LeaseValid);
    EXPECT_TRUE(State->PlaneMux);
    EXPECT_TRUE(State->SameRecord);
    if (State->Kind == ScenarioKind::Replacement)
        EXPECT_EQ(State->Dials, 2U);
    else
        EXPECT_EQ(State->Dials, 1U);
    EXPECT_TRUE(State->BackendAccepted);
    EXPECT_TRUE(State->BackendReceivedPayload);
    EXPECT_TRUE(State->LoopbackBound);
    EXPECT_EQ(State->BackendBytes, Payload.size());
    EXPECT_TRUE(State->BackendClosed);
    EXPECT_TRUE(State->BackendPeerClosed);
    EXPECT_EQ(State->BackendTailBytes, 0U);
    EXPECT_TRUE(State->BackendReturned);
    EXPECT_TRUE(State->ClientClosed);
    EXPECT_TRUE(State->ClientReturned);
    EXPECT_TRUE(State->ServerReturned);
    EXPECT_TRUE(State->RunReturned);
    EXPECT_TRUE(State->CountersDrained);
    EXPECT_TRUE(State->CatalogDrained);
    EXPECT_TRUE(State->WeakRootExpired);
    if (State->Kind == ScenarioKind::Echo)
    {
        EXPECT_TRUE(State->BackendEchoed);
        EXPECT_TRUE(State->RunStatus);
        EXPECT_TRUE(State->CountersAtEcho);
    }
    else if (State->Kind == ScenarioKind::CancelPending)
    {
        EXPECT_FALSE(State->BackendEchoed);
        EXPECT_TRUE(State->ClientReadPendingSignaled);
        EXPECT_TRUE(State->ClientReadReturned);
        EXPECT_EQ(State->ClientReadCount, 0U);
        EXPECT_FALSE(State->ClientReadError.empty());
        EXPECT_TRUE(State->PreCancelCounters);
        EXPECT_TRUE(State->RunStatus);
    }
    else if (State->Kind == ScenarioKind::Replacement)
    {
        EXPECT_TRUE(State->BackendEchoed);
        EXPECT_TRUE(State->FirstBackendClosed);
        EXPECT_TRUE(State->FirstBackendPeerClosed);
        EXPECT_TRUE(State->FirstClientFinReturned);
        EXPECT_EQ(State->FirstClientFinCount, 0U);
        EXPECT_FALSE(State->FirstClientFinError.empty());
        EXPECT_TRUE(State->FirstLeaseReleased);
        EXPECT_TRUE(State->ReplacementOpened);
        EXPECT_TRUE(State->ReplacementBackendReceived);
        EXPECT_TRUE(State->ReplacementEchoed);
        EXPECT_TRUE(State->ReplacementBackendPeerClosed);
        EXPECT_EQ(State->ReplacementBackendBytes, ReplacementPayload.size());
        EXPECT_EQ(State->ReplacementTailBytes, 0U);
        EXPECT_TRUE(State->CountersAtReplacementEcho);
        EXPECT_EQ(State->Dials, 2U);
        EXPECT_TRUE(State->RunStatus);
        EXPECT_TRUE(State->CountersAtEcho);
    }
    else
    {
        EXPECT_TRUE(State->BackendEchoed);
        EXPECT_TRUE(State->BackendContinuationReceived);
        EXPECT_TRUE(State->BackendContinuationEchoed);
        EXPECT_EQ(State->BackendContinuationBytes, Continuation.size());
        EXPECT_TRUE(State->SecondOpened);
        EXPECT_TRUE(State->SecondRejected);
        EXPECT_TRUE(State->SecondReadReturned);
        EXPECT_EQ(State->SecondStatus, 1U);
        EXPECT_TRUE(State->FirstStillActiveAtReject);
        EXPECT_TRUE(State->ContinuationEchoed);
        EXPECT_TRUE(State->BackendOpenAtContinuation);
        EXPECT_EQ(State->Dials, 1U);
        EXPECT_TRUE(State->RunStatus);
        EXPECT_TRUE(State->CountersAtEcho);
    }
    if (State->Failure)
    {
        try
        {
            std::rethrow_exception(State->Failure);
        }
        catch (const std::exception &Error)
        {
            ADD_FAILURE() << Error.what();
        }
    }
}
}












