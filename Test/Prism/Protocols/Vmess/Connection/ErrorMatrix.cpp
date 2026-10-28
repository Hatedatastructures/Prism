/**
 * @file ErrorMatrix.cpp
 * @brief VMess Conn 握手截断与随机源错误矩阵测试。
 */
#include "SessionSupport.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>
#include <tuple>
#include <vector>

#include <TestSupport/Prism/MockTransport.hpp>

namespace
{
    /** @brief 生成错误矩阵使用的固定 UUID。 */
    [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, 16>
    {
        return {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    }

    /** @brief 在第五次请求时模拟 VMess 随机源失败。 */
    struct FailFifthRandomCall final
    {
        int& Calls;

        auto operator()(std::uint8_t* Bytes, int Size) const -> int
        {
            ++Calls;
            if (Calls == 5)
            {
                return 0;
            }
            for (int Index = 0; Index < Size; ++Index)
            {
                Bytes[Index] = 0x42;
            }
            return 1;
        }
    };

    /** @brief 发送四字节截断头并验证服务端保留原协议错误。 */
    auto RunTruncatedHeader(Net::io_context& Context) -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        Vmess::ServerConfig Config;
        Config.uuid = MakeUuid();
        using ServerResultType = std::expected<Vmess::AcceptedConnection, Prism::Fault::Failure>;
        VmessTestTask<ServerResultType> ServerTask(
            Context.get_executor());
        ServerTask.Start(AcceptVmessStream(Pair.SecondOwner, Config));

        const std::vector<std::uint8_t> Wire{0x01, 0x02, 0x03, 0x04};
        const auto Write = co_await Pair.FirstOwner->WriteSome(AsBytes(
            std::span<const std::uint8_t>(Wire)));
        EXPECT_EQ(Write.Bytes, Wire.size());
        EXPECT_TRUE(Write.Failure.Succeeded());
        const auto ClientClose = co_await Prism::Testing::CloseFixture(Pair.FirstOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientClose);

        auto AcceptResult = co_await ServerTask.Wait();
        EXPECT_FALSE(AcceptResult);
        if (!AcceptResult)
        {
            EXPECT_EQ(AcceptResult.error().Code, Prism::Fault::Code::Eof);
            EXPECT_FALSE(AcceptResult.error().Native);
        }
        const auto ServerClose = co_await Prism::Testing::CloseFixture(Pair.SecondOwner);
        Prism::Testing::ExpectFixtureCloseReceipt(ServerClose);
    }

    /** @brief 随机源第五次调用失败时验证 ConnOptions 与握手错误。 */
    auto RunClientHandshakeRejectsRandomFailure(Net::io_context& Context)
        -> Net::awaitable<void>
    {
        auto Pair = MakeVmessTransportPair(Context);
        const auto Uuid = MakeUuid();
        int Calls = 0;
        const Vmess::RandomSource Source = FailFifthRandomCall{Calls};
        auto Client = std::make_shared<Vmess::Conn<>>(Vmess::ConnOptions{
            .Executor = Pair.FirstOwner->Executor(), .Uuid = Uuid, .Source = Source});
        const auto Handshake = co_await Client->WriteHandshake(
            Pair.FirstOwner, MakeAddress(Vmess::AddressType::Domain, "example.com", 443));
        EXPECT_FALSE(Handshake);
        if (!Handshake)
        {
            EXPECT_EQ(Handshake.error().Code, Prism::Fault::Code::GenericError);
            EXPECT_FALSE(Handshake.error().Native);
        }
        EXPECT_EQ(Calls, 5);

        const auto ClientClose = co_await Prism::Testing::CloseFixture(Client);
        Prism::Testing::ExpectFixtureCloseReceipt(ClientClose);
        const auto EndpointCloses = co_await CloseVmessEndpoints(Pair);
        Prism::Testing::ExpectFixtureCloseReceipt(EndpointCloses.First);
        Prism::Testing::ExpectFixtureCloseReceipt(EndpointCloses.Second);
    }

    auto RunPartialNativeWriteFailure(Net::io_context &Context) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Context.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->WriteErrorBytes = 1;
        Raw->SetWriteError(Native);
        Vmess::ClientConfig Config;
        Config.uuid = MakeUuid();
        const auto Target = MakeAddress(Vmess::AddressType::Domain, "example.com", 443);
        auto Result = co_await Vmess::Connect(Vmess::ConnectParameters{Raw, Config, Target});
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.error().Native, Native);
        EXPECT_EQ(Raw->Written.size(), 1u);
        EXPECT_TRUE(Raw->IsClosed());
        const auto RawDrained = co_await Raw->Activity()->Drain();
        EXPECT_TRUE(RawDrained);
    }

    auto RunPartialNativeReadFailure(Net::io_context &Context) -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Context.get_executor());
        const auto Native = std::make_error_code(std::errc::connection_reset);
        Raw->InjectRead({0x01});
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(Native);
        Vmess::ServerConfig Config;
        Config.uuid = MakeUuid();
        auto Result = co_await AcceptVmessStream(Raw, Config);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.error().Native, Native);
        EXPECT_EQ(Raw->ReadsDone, 1u);
        const auto Closed = co_await Prism::Testing::CloseFixture(Raw);
        Prism::Testing::ExpectFixtureCloseReceipt(Closed);
    }
} // namespace

TEST(VmessConnErrorMatrix, TruncatedHeader)
{
    Net::io_context Context;
    RunCoroutine(Context, RunTruncatedHeader(Context));
}

TEST(VmessConnErrorMatrix, ClientHandshakeRejectsAuthNonceRandomFailure)
{
    Net::io_context Context;
    RunCoroutine(Context, RunClientHandshakeRejectsRandomFailure(Context));
}

TEST(VmessConnErrorMatrix, PartialHandshakeWritePreservesNativeFailure)
{
    Net::io_context Context;
    RunCoroutine(Context, RunPartialNativeWriteFailure(Context));
}

TEST(VmessConnErrorMatrix, PartialHandshakeReadPreservesNativeFailure)
{
    Net::io_context Context;
    RunCoroutine(Context, RunPartialNativeReadFailure(Context));
}
