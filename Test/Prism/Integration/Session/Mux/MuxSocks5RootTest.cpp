/**
 * @file MuxSocks5RootTest.cpp
 * @brief 配置化 Mux 双 root drain 行为契约。
 */

#include "MuxScenarioAsserts.hpp"
#include "MuxScenarioFlow.hpp"
#include "ConfiguredMuxMultiRootFlow.hpp"
TEST(ConfiguredMuxSession, Socks5TwoFactoriesUseIndependentRootsAndTwoDrainWaiters)
{
    const auto State = MultiRootScenario(ProtocolFamily::Socks5);
    ExpectScenarioSetup(State);
    VerifyMultiRootScenario(State);
}

