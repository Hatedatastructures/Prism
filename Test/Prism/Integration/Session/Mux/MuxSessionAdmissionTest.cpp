/**
 * @file MuxSessionAdmissionTest.cpp
 * @brief 配置化 Mux 真实 owner 与 drain 行为契约。
 */

#include "MuxScenarioAsserts.hpp"

TEST(ConfiguredMuxSession, Socks5ConfiguredSmuxRunsRealChildEchoAndDrainsLease)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Socks5, ScenarioKind::Echo));
}

TEST(ConfiguredMuxSession, Ss2022ConfiguredSmuxRunsRealChildEchoAndDrainsLease)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Ss2022, ScenarioKind::Echo));
}

TEST(ConfiguredMuxSession, Socks5MaxOneStreamRejectsSecondWithoutDial)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Socks5, ScenarioKind::QuotaSecond));
}

TEST(ConfiguredMuxSession, Ss2022MaxOneStreamRejectsSecondWithoutDial)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Ss2022, ScenarioKind::QuotaSecond));
}

TEST(ConfiguredMuxSession, Socks5CatalogCancelWaitsForPendingChildAndBackend)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Socks5, ScenarioKind::CancelPending));
}

TEST(ConfiguredMuxSession, Ss2022CatalogCancelWaitsForPendingChildAndBackend)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Ss2022, ScenarioKind::CancelPending));
}

TEST(ConfiguredMuxSession, Socks5FinReleasesStreamForReplacementChild)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Socks5, ScenarioKind::Replacement));
}

TEST(ConfiguredMuxSession, Ss2022FinReleasesStreamForReplacementChild)
{
    VerifyConfiguredMuxScenario(Scenario(ProtocolFamily::Ss2022, ScenarioKind::Replacement));
}

