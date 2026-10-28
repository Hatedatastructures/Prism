/**
 * @file TlsPipelineTest.cpp
 * @brief 生产 Probe 的错误进度保留契约。
 */

#include "ReassemblySupport.hpp"

struct RawIngressProbeScenarioState final
{
    explicit RawIngressProbeScenarioState(std::shared_ptr<ScriptedTransport> Value)
        : Transport(std::move(Value))
    {
    }

    std::shared_ptr<ScriptedTransport> Transport;
    rec::RawIngressProbeResult Result;
    Prism::IoResult PrefixResult;
    Prism::IoResult FollowingResult;
    std::array<std::byte, 1> Prefix{};
    std::array<std::byte, 1> Following{};
    std::size_t ReadCallsAfterProbe{0};
};

auto RunRawIngressProbeScenario(
    const std::shared_ptr<RawIngressProbeScenarioState> &State) -> Net::awaitable<void>
{
    State->Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
        std::static_pointer_cast<Prism::Transmission>(State->Transport),
        std::chrono::milliseconds::zero(), MakeTlsReassemblyBytePool()});
    State->ReadCallsAfterProbe = State->Transport->ReadRequests().size();
    if (State->Result.Transport)
    {
        State->PrefixResult = co_await State->Result.Transport->ReadSome(State->Prefix);
        State->FollowingResult = co_await State->Result.Transport->ReadSome(State->Following);
        (void)State->Result.Transport->Close();
    }
}

TEST(TlsReassemblyTest, RawIngressProbePreservesTlsMarkerReturnedWithReadError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Wire{0x16U};
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(AsBytes(Wire), Reset);
        const auto State = std::make_shared<RawIngressProbeScenarioState>(Transport);

        RunCoro(Io, [State] { return RunRawIngressProbeScenario(State); });

        EXPECT_EQ(State->Result.Kind, rec::RawIngressKind::Rejected);
        EXPECT_EQ(State->Result.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(State->Result.NativeError, Reset);
        ASSERT_NE(State->Result.Transport, nullptr);
        EXPECT_EQ(State->PrefixResult.Bytes, 1U);
        EXPECT_EQ(State->Prefix[0], static_cast<std::byte>(0x16U));
        EXPECT_EQ(State->PrefixResult.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(State->PrefixResult.Failure.Native, Reset);
        EXPECT_EQ(State->FollowingResult.Bytes, 0U);
        EXPECT_EQ(State->FollowingResult.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(State->FollowingResult.Failure.Native, Reset);
        EXPECT_EQ(State->Transport->ReadRequests().size(), State->ReadCallsAfterProbe);
    }
