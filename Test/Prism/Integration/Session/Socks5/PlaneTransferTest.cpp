/**
 * @file PlaneTransferTest.cpp
 * @brief 验证 SOCKS5 typed 数据面 move 后的传输、账户租约和回复回调所有权。
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <memory>
#include <utility>

#include <Prism/Account/Account.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Test/Prism/Transport/Core/Resources.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;

    auto FinalizeTransport(Net::io_context& Io, Prism::SharedTransmission Transport) -> void
    {
        if (Transport->IsOpen())
        {
            Prism::Testing::ExpectFixtureCloseReceipt(
                Prism::Testing::DriveClose(Io, std::move(Transport)));
            return;
        }
        EXPECT_TRUE(Prism::Testing::DriveDrain(Io, std::move(Transport)));
    }
}

TEST(Socks5TypedHandoff, MovingPlaneTransfersTransportLeaseAndPostDial)
{
    Net::io_context Io;
    auto [RawTransport, RawPeer] = Prism::MakeMemoryPair(Io.get_executor());
    auto Transport = std::make_shared<Prism::MemoryStream>(std::move(RawTransport));
    auto Peer = std::make_shared<Prism::MemoryStream>(std::move(RawPeer));
    const auto AccountId = Prism::AccountId{7301};
    auto Directory = Prism::Testing::ProviderAccount(
        Prism::Account::Credential::Password("typed-password"), AccountId,
        {.MaxConnections = 1});
    const auto Record = Directory->Store->FindById(AccountId);
    ASSERT_TRUE(Record);
    auto AuthResult = Directory->Authenticator->Authenticate(Prism::AuthenticationRequest{
        .AccountId = {},
        .Identity = {},
        .Credential = Prism::Account::CredentialView::Password("typed-password"),
        .Rate = {}});
    ASSERT_TRUE(AuthResult);
    ASSERT_TRUE(*AuthResult);

    Prism::Contract::ProtocolDataPlane Result;
    Result.ProtocolAuthenticated = true;
    Result.AccountId = AuthResult->AccountId();
    Result.AccountLease = std::move(*AuthResult);
    Result.Root = Prism::Contract::StreamDataPlane{Transport};
    const auto CallbackCalled = std::make_shared<bool>(false);
    Result.PostDial = [CallbackCalled](Fault::Failure) -> Net::awaitable<Fault::Failure>
    {
        *CallbackCalled = true;
        co_return Fault::Failure{};
    };

    auto Accepted = std::move(Result);
    ASSERT_TRUE(Accepted.HasTransport());
    EXPECT_EQ(Accepted.Transport().get(), Transport.get());
    EXPECT_FALSE(Result.Transport());
    EXPECT_FALSE(Result.PostDial);
    ASSERT_TRUE(Accepted.AccountLease);
    EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
    ASSERT_TRUE(Accepted.PostDial);

    Prism::Testing::RunCoro(Io, [&]() -> Net::awaitable<void>
    {
        const auto PostDialFailure = co_await Accepted.PostDial(Fault::Failure{});
        EXPECT_TRUE(PostDialFailure.Succeeded());
    }());
    EXPECT_TRUE(*CallbackCalled);

    Accepted.AccountLease.Release();
    EXPECT_FALSE(static_cast<bool>(Accepted.AccountLease));
    EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    FinalizeTransport(Io, Transport);
    FinalizeTransport(Io, Peer);
}
