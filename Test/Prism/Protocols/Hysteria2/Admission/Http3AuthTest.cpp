/**
 * @file Http3AuthTest.cpp
 * @brief Hysteria2 HTTP/3 auth seam contract tests.
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

#include <Prism/Account/Account.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Hysteria2/Codec.hpp>
#include <Prism/Protocols/Hysteria2/Http3Auth.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace
{

    auto MakeRequest(
        std::string_view Secret,
        const bool Fin = true) -> Prism::Http3::RequestEvent
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({":method", "POST"});
        Headers.Fields.push_back({":scheme", "https"});
        Headers.Fields.push_back({":authority", "hysteria"});
        Headers.Fields.push_back({":path", "/auth"});
        Headers.Fields.push_back({"hysteria-auth", std::string(Secret)});
        Headers.Fields.push_back({"hysteria-cc-rx", "0"});
        return Prism::Http3::RequestEvent{
            0,
            Prism::Http3::RequestHead{std::move(Headers), Fin}};
    }

    /** @brief 执行一个完整 invalid request 变体并验证 typed error。 */
    template <typename Mutator>
    auto ExpectInvalidRequest(
        boost::asio::io_context &Io,
        const std::shared_ptr<Prism::Authenticator> &Authenticator,
        Mutator Mutate) -> void
    {
        Prism::Hysteria2::Http3AuthSession Session(
            Prism::Hysteria2::Http3AuthSessionOptions{Io.get_executor(), Authenticator});
        auto Request = MakeRequest("secret");
        Mutate(Request);
        auto Result = Session.HandleRequest(std::move(Request));
        ASSERT_FALSE(Result.has_value());
        EXPECT_EQ(Result.error(), Prism::Hysteria2::AuthError::InvalidRequest);
        Session.Close();
    }

    TEST(Hysteria2Http3Auth, ClientHelperOwnsHysteriaWireFields)
    {
        const auto Request = Prism::Hysteria2::BuildAuthRequest(
            Prism::Hysteria2::ClientAuthOptions{
                .Authority = "hysteria.example",
                .Password = "secret",
                .ReceiveRate = 123,
                .Padding = "request-padding-a1"});

        ASSERT_TRUE(Request.Headers.Owner);
        EXPECT_EQ(Request.Headers.Fields[0].Name, ":method");
        EXPECT_EQ(Request.Headers.Fields[0].value, "POST");
        EXPECT_EQ(Request.Headers.Fields[2].Name, ":authority");
        EXPECT_EQ(Request.Headers.Fields[2].value, "hysteria.example");
        EXPECT_EQ(Request.Headers.Fields[3].Name, ":path");
        EXPECT_EQ(Request.Headers.Fields[3].value, "/auth");
        std::string Padding;
        for (const auto &Field : Request.Headers.Fields)
        {
            if (Field.Name == "hysteria-padding")
            {
                Padding = Field.value;
            }
        }
        EXPECT_EQ(Padding, "request-padding-a1");
    }

    TEST(Hysteria2Http3Auth, WireHelpersRemainHysteria2Owned)
    {
        const auto Wire = Prism::Hysteria2::MakeAuthRequest("secret");
        ASSERT_GT(Wire.size(), 2U);
        EXPECT_EQ(static_cast<std::uint8_t>(Wire[0]),
                  Prism::Hysteria2::AuthFrameHeaders);
        const auto HeaderLength = static_cast<std::uint8_t>(Wire[1]);
        ASSERT_LE(static_cast<std::size_t>(HeaderLength) + 2U, Wire.size());
        Prism::Hysteria2::WireAuthRequest Parsed;
        EXPECT_TRUE(Prism::Hysteria2::ParseAuthRequestWire(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Wire.data() + 2), HeaderLength),
            Parsed,
            Prism::Memory::CurrentResource()));
        EXPECT_EQ(Parsed.Method, "POST");
        EXPECT_EQ(Parsed.Authority, "hysteria2");
        EXPECT_EQ(Parsed.Path, "/auth");
        EXPECT_EQ(Parsed.Credential, "secret");
    }

    TEST(Hysteria2Http3Auth, ResponseParserOwnsStatusAndUdpNegotiation)
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({"hysteria-udp", "true"});
        Headers.Fields.push_back({"hysteria-cc-rx", "42"});
        Headers.Fields.push_back({"hysteria-padding", "256"});

        auto Parsed = Prism::Hysteria2::ParseAuthResponse(
            Prism::Http3::ResponseHead{9, 233, std::move(Headers), false});
        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->UdpEnabled);
        ASSERT_TRUE(std::holds_alternative<std::uint64_t>(Parsed->ReceiveRate));
        EXPECT_EQ(std::get<std::uint64_t>(Parsed->ReceiveRate), 42U);

        auto ReorderedOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock ReorderedHeaders(ReorderedOwner);
        ReorderedHeaders.Fields.push_back({"hysteria-padding", "7"});
        ReorderedHeaders.Fields.push_back({"hysteria-udp", "false"});
        ReorderedHeaders.Fields.push_back({"hysteria-cc-rx", "3"});
        auto Reordered = Prism::Hysteria2::ParseAuthResponse(
            Prism::Http3::ResponseHead{9, 233, std::move(ReorderedHeaders), false});
        ASSERT_TRUE(Reordered.has_value());
        EXPECT_FALSE(Reordered->UdpEnabled);
        ASSERT_TRUE(std::holds_alternative<std::uint64_t>(Reordered->ReceiveRate));
        EXPECT_EQ(std::get<std::uint64_t>(Reordered->ReceiveRate), 3U);

        auto DuplicateOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock DuplicateHeaders(DuplicateOwner);
        DuplicateHeaders.Fields.push_back({"hysteria-udp", "true"});
        DuplicateHeaders.Fields.push_back({"hysteria-udp", "false"});
        EXPECT_FALSE(Prism::Hysteria2::ParseAuthResponse(
                         Prism::Http3::ResponseHead{9, 233, std::move(DuplicateHeaders), false})
                         .has_value());

        auto DuplicateRateOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock DuplicateRateHeaders(DuplicateRateOwner);
        DuplicateRateHeaders.Fields.push_back({"hysteria-udp", "true"});
        DuplicateRateHeaders.Fields.push_back({"hysteria-cc-rx", "1"});
        DuplicateRateHeaders.Fields.push_back({"hysteria-cc-rx", "2"});
        EXPECT_FALSE(Prism::Hysteria2::ParseAuthResponse(
                         Prism::Http3::ResponseHead{9, 233, std::move(DuplicateRateHeaders), false})
                         .has_value());

        auto DuplicatePaddingOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock DuplicatePaddingHeaders(DuplicatePaddingOwner);
        DuplicatePaddingHeaders.Fields.push_back({"hysteria-udp", "true"});
        DuplicatePaddingHeaders.Fields.push_back({"hysteria-padding", "a"});
        DuplicatePaddingHeaders.Fields.push_back({"hysteria-padding", "b"});
        EXPECT_FALSE(Prism::Hysteria2::ParseAuthResponse(
                         Prism::Http3::ResponseHead{9, 233, std::move(DuplicatePaddingHeaders), false})
                         .has_value());

        auto InvalidRateOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock InvalidRateHeaders(InvalidRateOwner);
        InvalidRateHeaders.Fields.push_back({"hysteria-udp", "true"});
        InvalidRateHeaders.Fields.push_back({"hysteria-cc-rx", "not-auto"});
        EXPECT_FALSE(Prism::Hysteria2::ParseAuthResponse(
                         Prism::Http3::ResponseHead{9, 233, std::move(InvalidRateHeaders), false})
                         .has_value());

        auto ErrorOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        auto Error = Prism::Hysteria2::ParseAuthResponse(
            Prism::Http3::ResponseHead{
                9, 401, Prism::Http3::HeaderBlock(ErrorOwner), true});
        EXPECT_FALSE(Error.has_value());
    }

    TEST(Hysteria2Http3Auth, ResponseParserAcceptsStandardRandomOptionalPadding)
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({"hysteria-udp", "true"});
        Headers.Fields.push_back({"hysteria-cc-rx", "0"});
        Headers.Fields.push_back({"hysteria-padding", std::string(256, 'a')});

        auto Parsed = Prism::Hysteria2::ParseAuthResponse(
            Prism::Http3::ResponseHead{9, 233, std::move(Headers), false});
        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->UdpEnabled);
        ASSERT_TRUE(std::holds_alternative<std::uint64_t>(Parsed->ReceiveRate));
        EXPECT_EQ(std::get<std::uint64_t>(Parsed->ReceiveRate), 0U);
    }

    TEST(Hysteria2Http3Auth, ResponseParserAcceptsOmittedOptionalPadding)
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({"hysteria-udp", "true"});
        Headers.Fields.push_back({"hysteria-cc-rx", "0"});

        auto Parsed = Prism::Hysteria2::ParseAuthResponse(
            Prism::Http3::ResponseHead{9, 233, std::move(Headers), false});
        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->UdpEnabled);
        ASSERT_TRUE(std::holds_alternative<std::uint64_t>(Parsed->ReceiveRate));
        EXPECT_EQ(std::get<std::uint64_t>(Parsed->ReceiveRate), 0U);
    }

    TEST(Hysteria2Http3Auth, ResponseParserAcceptsTypedAutoReceiveRate)
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({"hysteria-udp", "true"});
        Headers.Fields.push_back({"hysteria-cc-rx", "auto"});
        Headers.Fields.push_back({"hysteria-padding", std::string(256, 'a')});

        auto Parsed = Prism::Hysteria2::ParseAuthResponse(
            Prism::Http3::ResponseHead{9, 233, std::move(Headers), false});
        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->UdpEnabled);
        EXPECT_TRUE(std::holds_alternative<Prism::Hysteria2::AutomaticReceiveRate>(
            Parsed->ReceiveRate));
        ASSERT_NE(std::get_if<Prism::Hysteria2::AutomaticReceiveRate>(
                      &Parsed->ReceiveRate), nullptr);
    }

    TEST(Hysteria2Http3Auth, AuthFailureResponseMapsTypedStatus)
    {
        const auto Unauthorized = Prism::Hysteria2::BuildAuthFailureResponse(
            3, Prism::Hysteria2::AuthError::Unauthorized);
        EXPECT_EQ(Unauthorized.StreamId, 3);
        EXPECT_EQ(Unauthorized.Status, 401);
        EXPECT_TRUE(Unauthorized.Fin);
        ASSERT_TRUE(Unauthorized.Headers.Owner);

        const auto Invalid = Prism::Hysteria2::BuildAuthFailureResponse(
            3, Prism::Hysteria2::AuthError::InvalidRequest);
        EXPECT_EQ(Invalid.Status, 400);
        EXPECT_TRUE(Invalid.Fin);

        const auto Unavailable = Prism::Hysteria2::BuildAuthFailureResponse(
            3, Prism::Hysteria2::AuthError::AuthenticatorUnavailable);
        EXPECT_EQ(Unavailable.Status, 503);
        EXPECT_TRUE(Unavailable.Fin);

        const auto Duplicate = Prism::Hysteria2::BuildAuthFailureResponse(
            3, Prism::Hysteria2::AuthError::AlreadyAuthenticated);
        EXPECT_EQ(Duplicate.Status, 409);
        EXPECT_TRUE(Duplicate.Fin);
    }

    TEST(Hysteria2Http3Auth, AuthenticationResultLeaseLivesUntilClose)
    {
        boost::asio::io_context Io;
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token("secret"), Prism::AccountId{77},
            {.MaxConnections = 1, .MaxStreams = 1});
        ASSERT_TRUE(Directory->Store->FindById(Prism::AccountId{77}));
            auto Authenticator = Directory->Authenticator;

        Prism::Hysteria2::Http3AuthSession First(
            Prism::Hysteria2::Http3AuthSessionOptions{Io.get_executor(), Authenticator});
        auto Accepted = First.HandleRequest(MakeRequest("secret"));
        ASSERT_TRUE(Accepted.has_value());
        // Authentication succeeds from response headers while the auth stream remains open.
        EXPECT_FALSE(Accepted->Fin);
        auto Duplicate = First.HandleRequest(MakeRequest("secret"));
        ASSERT_FALSE(Duplicate.has_value());
        EXPECT_EQ(Duplicate.error(), Prism::Hysteria2::AuthError::AlreadyAuthenticated);
        EXPECT_EQ(First.AccountId(), Prism::AccountId{77});
        EXPECT_EQ(First.Identity(), "provider-fixture");
        EXPECT_NE(First.Identity(), "Provider Fixture");

        Prism::Hysteria2::Http3AuthSession Second(
            Prism::Hysteria2::Http3AuthSessionOptions{Io.get_executor(), Authenticator});
        EXPECT_FALSE(Second.HandleRequest(MakeRequest("secret")).has_value());

        First.Close();
        auto Released = Second.HandleRequest(MakeRequest("secret"));
        EXPECT_TRUE(Released.has_value());
        Second.Close();
    }

    TEST(Hysteria2Http3Auth, RejectsTransportIdentityAndDuplicateCredential)
    {
        boost::asio::io_context Io;
        auto Authenticator = std::make_shared<Prism::RejectAuthenticator>();
        Prism::Hysteria2::Http3AuthSession Session(
            Prism::Hysteria2::Http3AuthSessionOptions{Io.get_executor(), Authenticator});

        auto Request = MakeRequest("secret");
        Request.StreamId = -1;
        EXPECT_FALSE(Session.HandleRequest(std::move(Request)).has_value());

        auto Duplicate = MakeRequest("secret");
        Duplicate.Head.Headers.Fields.push_back({"hysteria-auth", "second"});
        EXPECT_FALSE(Session.HandleRequest(std::move(Duplicate)).has_value());
        Session.Close();
    }

    TEST(Hysteria2Http3Auth, RejectsCompleteInvalidRequestMatrix)
    {
        boost::asio::io_context Io;
        auto Authenticator = std::make_shared<Prism::RejectAuthenticator>();

        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields[0].value = "GET";
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields[3].value = "/other";
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields.erase(Request.Head.Headers.Fields.begin() + 2);
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields.erase(Request.Head.Headers.Fields.begin() + 4);
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields.push_back({":method", "POST"});
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields.insert(
                Request.Head.Headers.Fields.begin(),
                Prism::Http3::Qpack::HeaderField{":protocol", "webtransport"});
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields[0].Name = ":Method";
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields.insert(
                Request.Head.Headers.Fields.begin() + 2,
                Prism::Http3::Qpack::HeaderField{":scheme", "https"});
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields[1].value = "http";
        });
        ExpectInvalidRequest(Io, Authenticator, [](auto &Request)
        {
            Request.Head.Headers.Fields.erase(Request.Head.Headers.Fields.begin() + 1);
        });
        Prism::Hysteria2::Http3AuthSession Unavailable(
            Prism::Hysteria2::Http3AuthSessionOptions{Io.get_executor(), {}});
        auto UnavailableResult = Unavailable.HandleRequest(MakeRequest("secret"));
        ASSERT_FALSE(UnavailableResult.has_value());
        EXPECT_EQ(UnavailableResult.error(), Prism::Hysteria2::AuthError::AuthenticatorUnavailable);
        Unavailable.Close();

        Prism::Hysteria2::Http3AuthSession Closed(
            Prism::Hysteria2::Http3AuthSessionOptions{Io.get_executor(), Authenticator});
        Closed.Close();
        auto ClosedResult = Closed.HandleRequest(MakeRequest("secret"));
        ASSERT_FALSE(ClosedResult.has_value());
        EXPECT_EQ(ClosedResult.error(), Prism::Hysteria2::AuthError::Closed);
    }

} // namespace
