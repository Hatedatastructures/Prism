/**
 * @file Ss2022RootTest.cpp
 * @brief 配置化 Mux 双 root drain 行为契约。
 */

#include "ScenarioAsserts.hpp"
#include "ScenarioFlow.hpp"
#include "MultiRootFlow.hpp"
TEST(ConfiguredMuxSession, Ss2022TwoFactoriesUseIndependentRootsAndTwoDrainWaiters)
{
    const auto State = MultiRootScenario(ProtocolFamily::Ss2022);
    ExpectScenarioSetup(State);
    VerifyMultiRootScenario(State);
}

