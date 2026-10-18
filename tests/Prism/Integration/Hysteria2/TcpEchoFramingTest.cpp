/**
 * @file TcpEchoFramingTest.cpp
 * @brief 互操作端点必须支持请求头与 TCP payload 分批交付。
 */
#include "TcpEcho.hpp"
#include <gtest/gtest.h>

namespace
{
    namespace Echo = Prism::Testing::Integration::Hysteria2;

    auto MakeRequestHeader() -> std::vector<std::byte>
    {
        constexpr std::string_view Target{"127.0.0.1:443"};
        std::vector<std::byte> Header;
        Echo::AppendVarint(Header, 0x401);
        Echo::AppendVarint(Header, Target.size());
        for (const auto Value : Target) Header.push_back(static_cast<std::byte>(Value));
        Echo::AppendVarint(Header, 0);
        return Header;
    }

    TEST(Hysteria2TcpEcho, RequestHeaderWithoutPayloadKeepsWriteSideOpen)
    {
        Echo::StreamState State;
        Echo::TcpEchoEvidence Evidence;
        const auto Header = MakeRequestHeader();
        const auto Action = Echo::HandleTcpData(Echo::TcpDataInput{State, Header, false, Evidence});
        ASSERT_TRUE(State.RequestDone);
        EXPECT_TRUE(Evidence.RequestParsed);
        EXPECT_EQ(Action.Data, (std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0}}));
        EXPECT_FALSE(Action.Stop);
        EXPECT_FALSE(Action.Fin);
        EXPECT_FALSE(Evidence.ResponseWriteCompleted);
        EXPECT_EQ(Evidence.PayloadBytes, 0U);
    }

    TEST(Hysteria2TcpEcho, FragmentedRequestHeaderProducesOneResponseHeader)
    {
        Echo::StreamState State;
        Echo::TcpEchoEvidence Evidence;
        const auto Header = MakeRequestHeader();
        const auto Prefix = Echo::HandleTcpData(Echo::TcpDataInput{
            State, std::span<const std::byte>(Header).first(1), false, Evidence});
        EXPECT_FALSE(State.RequestDone);
        EXPECT_TRUE(Prefix.Data.empty());
        EXPECT_FALSE(Prefix.Stop);
        const auto Completed = Echo::HandleTcpData(Echo::TcpDataInput{
            State, std::span<const std::byte>(Header).subspan(1), false, Evidence});
        ASSERT_TRUE(State.RequestDone);
        EXPECT_EQ(Completed.Data.size(), 3U);
        EXPECT_FALSE(Completed.Stop);
        const std::array<std::byte, 3> Payload{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
        const auto Data = Echo::HandleTcpData(Echo::TcpDataInput{State, Payload, false, Evidence});
        EXPECT_EQ(Data.Data, std::vector<std::byte>(Payload.begin(), Payload.end()));
        EXPECT_FALSE(Data.Stop);
        EXPECT_FALSE(Data.Fin);
    }

    TEST(Hysteria2TcpEcho, CompletionRequiresAllPayloadWrites)
    {
        Echo::TcpEchoEvidence Evidence;
        Echo::RawAction Header;
        Header.Data = Echo::MakeTcpResponse({});
        Header.ResponseHeaderBytes = 3;
        ASSERT_TRUE(Echo::RecordWritten(Evidence, Header));
        EXPECT_FALSE(Evidence.ResponseWriteCompleted);
        EXPECT_EQ(Evidence.PayloadBytes, 0U);
        const auto Payload = std::as_bytes(std::span(Echo::ExpectedTcpPayload));
        Echo::RawAction Prefix;
        Prefix.Data.assign(Payload.begin(), Payload.begin() + 7);
        ASSERT_TRUE(Echo::RecordWritten(Evidence, Prefix));
        EXPECT_EQ(Evidence.PayloadBytes, 7U);
        EXPECT_FALSE(Evidence.ResponseWriteCompleted);
        Echo::RawAction Remainder;
        Remainder.Data.assign(Payload.begin() + 7, Payload.end());
        ASSERT_TRUE(Echo::RecordWritten(Evidence, Remainder));
        EXPECT_TRUE(Evidence.ResponseWriteCompleted);
        EXPECT_EQ(Evidence.PayloadBytes, Echo::ExpectedTcpPayload.size());
        EXPECT_EQ(Evidence.PayloadHash, Echo::HashPayload(Payload));
        Echo::RawAction Extra;
        Extra.Data = {std::byte{1}};
        EXPECT_FALSE(Echo::RecordWritten(Evidence, Extra));
        EXPECT_EQ(Evidence.PayloadBytes, Echo::ExpectedTcpPayload.size());
    }
}
