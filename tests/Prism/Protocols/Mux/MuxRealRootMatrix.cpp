/**
 * @file MuxRealRootMatrix.cpp
 * @brief 真实 Mux Root 三模式与并发 64MiB 矩阵测试。
 */

#include "MuxRealRootFixture.hpp"
#include "MuxRealRootMatrixControl.hpp"
#include "MuxRealRootMeasurement.hpp"

namespace Prism::Testing::MuxRealRoot
{
inline auto AssertRealScenario(const std::string_view Name,
                               const RealScenarioResult &Result,
                               const bool Diagnostic) -> void
{
    ASSERT_FALSE(Result.Failure);
    ASSERT_TRUE(Result.FailureMessage.empty()) << Result.FailureMessage;
    EXPECT_TRUE(Result.Authenticated);
    EXPECT_TRUE(Result.LiteralValid);
    EXPECT_EQ(Result.Report.Bytes, RealTotalBytes);
    EXPECT_EQ(Result.Report.Samples, RealTotalBytes / RealBlockBytes);
    EXPECT_EQ(Result.BackendBytes, RealTotalBytes + RealLiteral.size());
    EXPECT_EQ(Result.BackendHash, Result.ExpectedHash);
    EXPECT_TRUE(Result.BackendPeerClosed);
    EXPECT_TRUE(Result.ClientPeerClosed);
    EXPECT_TRUE(Result.RootFinished);
    EXPECT_TRUE(Result.Drained);
    EXPECT_TRUE(Result.ScenarioCompleted);
    EXPECT_TRUE(Result.Exited);
    EXPECT_TRUE(Result.QuotaZero);
    EXPECT_TRUE(Result.WeakExpired);
    EXPECT_EQ(Result.Dials, 1U);
    EXPECT_EQ(Result.FirstConnections, 1U);
    EXPECT_EQ(Result.FirstStreams, 1U);
    EXPECT_EQ(Result.MeasureFailed, 0U);
    if (!Diagnostic)
    {
        EXPECT_GT(Result.Report.Mbps, 0.0);
        PrintRealReport(Name, Result);
    }
}

TEST(MuxPerf, RealRootSmux64MiB)
{
    const auto Result = RealScenario(RealRootMode::Smux, "smux");
    AssertRealScenario("smux", Result, false);
}

TEST(MuxPerf, RealRootYamux64MiB)
{
    const auto Result = RealScenario(RealRootMode::Yamux, "yamux");
    AssertRealScenario("yamux", Result, false);
}

TEST(MuxPerf, RealRootH2Mux64MiB)
{
    const auto Result = RealScenario(RealRootMode::H2Mux, "h2mux");
    AssertRealScenario("h2mux", Result, false);
}

TEST(MuxPerf, RealRoot64MiBConcurrentExecutorMatrix)
{
    if (IsRealMatrixDiagnosticEnabled())
    {
        std::printf(
            "real-root-matrix diagnostic-only=1 performance=disabled mode=smux round=1 lanes=1 bytes=%zu block_bytes=%zu\n",
            RealTotalBytes, RealBlockBytes);
        std::fflush(stdout);
        const auto Result = RunRealMatrix(RealMatrixRequest{
            .Mode = RealRootMode::Smux, .Lanes = 1U, .Round = 1U, .Diagnostic = true});
        ASSERT_TRUE(Result.Prepared);
        ASSERT_FALSE(Result.DeadlineExceeded);
        ASSERT_FALSE(Result.SamplerFailed);
        ASSERT_FALSE(Result.CloseTimedOut);
        ASSERT_EQ(Result.Lanes.size(), 1U);
        AssertRealScenario("smux-matrix-r1-lane1", Result.Lanes.front(), true);
        return;
    }
    constexpr std::array<RealRootMode, 3> Modes{
        RealRootMode::Smux, RealRootMode::Yamux, RealRootMode::H2Mux};
    constexpr std::array<std::size_t, 3> LaneCounts{1U, 2U, 4U};
    const auto Budget = MakeRealMatrixBudget();
    for (std::size_t Round = 1; Round <= 5U; ++Round)
    {
        for (std::size_t Offset = 0; Offset < Modes.size(); ++Offset)
        {
            const auto Mode = Modes[(Round + Offset - 1U) % Modes.size()];
            for (const auto Lanes : LaneCounts)
            {
                const auto Result = RunRealMatrix(RealMatrixRequest{
                    .Mode = Mode, .Lanes = Lanes, .Round = Round, .Budget = Budget});
                ASSERT_TRUE(Result.Prepared);
                ASSERT_FALSE(Result.DeadlineExceeded);
                ASSERT_FALSE(Result.SamplerFailed);
                ASSERT_FALSE(Result.CloseTimedOut);
                ASSERT_EQ(Result.Lanes.size(), Lanes);
                for (std::size_t Lane = 0; Lane < Result.Lanes.size(); ++Lane)
                {
                    const auto Name = std::string(RealRootModeName(Mode)) + "-matrix-r" +
                        std::to_string(Round) + "-lane" + std::to_string(Lane + 1U);
                    AssertRealScenario(Name, Result.Lanes[Lane], false);
                }
            }
        }
    }
}
} // namespace Prism::Testing::MuxRealRoot
