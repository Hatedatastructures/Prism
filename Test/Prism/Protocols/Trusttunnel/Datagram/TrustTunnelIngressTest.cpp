/**
 * @file TrustTunnelIngressTest.cpp
 * @brief TrustTunnel wire-proof and ingress binding tests.
 */
#include "TrustTunnelSupport.hpp"

TEST(TrusttunnelIngressFactory, RejectsRawTransportWithoutWireProof)
    {
        Net::io_context IoContext;
        auto OnData = [](std::int32_t, std::span<const std::byte>)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        };
        auto Raw = std::make_shared<Trusttunnel::Detail::Http2Transport>(
            Trusttunnel::Detail::Http2Transport::Options{
                IoContext.get_executor(), std::move(OnData), Trusttunnel::Detail::Http2Transport::FinishCb{},
                Trusttunnel::Detail::Http2Transport::CloseCb{}});
        Trusttunnel::IngressFactory Factory(
            Trusttunnel::IngressOptions{
                Trusttunnel::MakeWireAuthBinding(Trusttunnel::ServerConfig{"user", "password"}, {})});
        std::optional<std::expected<Prism::Contract::ProtocolDataPlane,
                                    Prism::Fault::Failure>> Result;

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                Result.emplace(co_await Factory.Accept(Prism::Contract::StreamAcceptInput{
                    .Inbound = Raw,
                    .Metadata = {},
                    .Bytes = std::make_shared<Prism::Memory::BytePool>()}));
                co_return;
            });

        ASSERT_TRUE(Result.has_value());
        ASSERT_FALSE(*Result);
        EXPECT_EQ(Result->error().Code, Prism::Fault::Code::NotSupported);
    }

    TEST(TrusttunnelIngressFactory, AcceptsWireProofAndRejectsMismatchedBinding)
    {
        WireAdmissionFixture Fixture;
        ASSERT_TRUE(Fixture.TlsReady);
        ASSERT_TRUE(Fixture.AuthA.Directory);
        ASSERT_TRUE(Fixture.AuthB.Directory);
        ASSERT_TRUE(Fixture.AuthA.Record);
        ASSERT_TRUE(Fixture.AuthB.Record);

        Net::co_spawn(Fixture.IoContext, Fixture.RunServer(), WireCompletion{&Fixture});
        Net::co_spawn(Fixture.IoContext, Fixture.RunClient(), WireCompletion{&Fixture});
        Net::co_spawn(Fixture.IoContext, Fixture.Watchdog(), Net::detached);
        Fixture.IoContext.run();
        Fixture.Acceptor.close();

        if (Fixture.Failure)
        {
            std::rethrow_exception(Fixture.Failure);
        }

        const auto &Observation = Fixture.Observation;
        EXPECT_FALSE(Observation.TimedOut);
        EXPECT_EQ(Observation.ServerAcceptErrors, 0);
        EXPECT_EQ(Observation.ClientConnectErrors, 0);
        EXPECT_TRUE(Observation.SameHandshake.Succeeded());
        EXPECT_EQ(Observation.SameAdmission.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Observation.SameTarget, "example.com:443");
        EXPECT_TRUE(Observation.SameAccepted);
        EXPECT_TRUE(Observation.SameStream);
        EXPECT_TRUE(Observation.SameAuthenticated);
        EXPECT_EQ(Observation.SameAccountId, Prism::AccountId{4101});
        EXPECT_TRUE(Observation.ServerPayloadRead);
        EXPECT_TRUE(Observation.ServerPayloadEqual);
        EXPECT_TRUE(Observation.ClientPayloadWritten);
        EXPECT_TRUE(Observation.ServerResponseWritten);
        EXPECT_FALSE(Observation.ServerDataFailure.Failed())
            << "Code=" << static_cast<unsigned>(Observation.ServerDataFailure.Code)
            << " Native=" << Observation.ServerDataFailure.Native.category().name()
            << "/" << Observation.ServerDataFailure.Native.value();
        EXPECT_TRUE(Observation.ClientResponseRead);
        EXPECT_TRUE(Observation.ClientResponseEqual);
        EXPECT_TRUE(Observation.ClientResponseEndStream);
        EXPECT_FALSE(Observation.ClientDataFailure.Failed());
        EXPECT_TRUE(Observation.ClientHalfClose);
        EXPECT_TRUE(Observation.ClientTlsCloseNotify);
        EXPECT_TRUE(Observation.ServerHalfClose)
            << "Code=" << static_cast<unsigned>(Observation.ServerDataFailure.Code)
            << " Native=" << Observation.ServerDataFailure.Native.category().name()
            << "/" << Observation.ServerDataFailure.Native.value();
        EXPECT_EQ(Observation.SameActiveDuring, 1U);
        EXPECT_EQ(Observation.SameActiveAfter, 0U);
        EXPECT_TRUE(Observation.DriverClosed);
        EXPECT_TRUE(Observation.DriverStateExpired);
        EXPECT_TRUE(Observation.SameDrainSucceeded);
        EXPECT_TRUE(Observation.SameRetired);
        EXPECT_EQ(Fixture.AuthA.Authenticator->Calls(), 1);

        EXPECT_TRUE(Observation.CrossHandshake.Succeeded());
        EXPECT_EQ(Observation.CrossAdmission.Code, Prism::Fault::Code::NotSupported);
        EXPECT_TRUE(Observation.ClientCross.Succeeded())
            << "Code=" << static_cast<unsigned>(Observation.ClientCross.Code)
            << " Native=" << Observation.ClientCross.Native.category().name()
            << "/" << Observation.ClientCross.Native.value();
        EXPECT_EQ(Observation.CrossActiveAfter, 0U);
        EXPECT_TRUE(Observation.CrossDriverClosed);
        EXPECT_TRUE(Observation.CrossDrainSucceeded);
        EXPECT_TRUE(Observation.CrossRetired);
        EXPECT_EQ(Fixture.AuthB.Authenticator->Calls(), 0);

        EXPECT_TRUE(Observation.WrongHandshake.Failed());
        EXPECT_EQ(Observation.ClientWrong.Code, Prism::Fault::Code::AuthFailed)
            << "Native=" << Observation.ClientWrong.Native.category().name()
            << "/" << Observation.ClientWrong.Native.value();
        EXPECT_FALSE(Observation.WrongTransport);
        EXPECT_EQ(Fixture.AuthA.Authenticator->Calls(), 1);
    }

