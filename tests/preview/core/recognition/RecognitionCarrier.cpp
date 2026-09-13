/**
 * @file RecognitionCarrier.cpp
 * @brief TLS carrier 候选与 scheme 提交行为 RED 测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <exception>
#include <memory>
#include <string>
#include <stdexcept>
#include <span>
#include <vector>

#include <preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <preview/Protocols/Shadowtls/Server.hpp>
#include <preview/Protocols/Anytls/Anytls.hpp>
#include <preview/Protocols/Ws/Ws.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <preview/Transport/MemoryStream.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

    auto MakeFeatures(std::string ServerName, std::vector<std::string> Alpn)
        -> Core::ClientHelloFeatures
    {
        Core::ClientHelloFeatures Features;
        Features.ServerName = std::move(ServerName);
        Features.AlpnProtocols = std::move(Alpn);
        Features.HasAlpn = !Features.AlpnProtocols.empty();
        return Features;
    }

    auto AppendU16(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    auto AppendU24(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFFU));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFFU));
    }

    auto MakeClientHello(std::string_view ServerName, std::string_view Alpn) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> SniName{0};
        AppendU16(SniName, ServerName.size());
        SniName.insert(SniName.end(), ServerName.begin(), ServerName.end());
        std::vector<std::uint8_t> Sni;
        AppendU16(Sni, SniName.size());
        Sni.insert(Sni.end(), SniName.begin(), SniName.end());
        std::vector<std::uint8_t> SniExtension{0x00, 0x00};
        AppendU16(SniExtension, Sni.size());
        SniExtension.insert(SniExtension.end(), Sni.begin(), Sni.end());

        std::vector<std::uint8_t> AlpnList{static_cast<std::uint8_t>(Alpn.size())};
        AlpnList.insert(AlpnList.end(), Alpn.begin(), Alpn.end());
        std::vector<std::uint8_t> AlpnPayload;
        AppendU16(AlpnPayload, AlpnList.size());
        AlpnPayload.insert(AlpnPayload.end(), AlpnList.begin(), AlpnList.end());
        std::vector<std::uint8_t> AlpnExtension{0x00, 0x10};
        AppendU16(AlpnExtension, AlpnPayload.size());
        AlpnExtension.insert(AlpnExtension.end(), AlpnPayload.begin(), AlpnPayload.end());

        std::vector<std::uint8_t> Versions{0x02, 0x03, 0x04};
        std::vector<std::uint8_t> VersionsExtension{0x00, 0x2B};
        AppendU16(VersionsExtension, Versions.size());
        VersionsExtension.insert(VersionsExtension.end(), Versions.begin(), Versions.end());
        std::vector<std::uint8_t> Extensions;
        Extensions.insert(Extensions.end(), SniExtension.begin(), SniExtension.end());
        Extensions.insert(Extensions.end(), AlpnExtension.begin(), AlpnExtension.end());
        Extensions.insert(Extensions.end(), VersionsExtension.begin(), VersionsExtension.end());

        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), 32, 0x42);
        Body.push_back(0);
        AppendU16(Body, 2);
        Body.push_back(0x13);
        Body.push_back(0x01);
        Body.push_back(1);
        Body.push_back(0);
        AppendU16(Body, Extensions.size());
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());
        std::vector<std::uint8_t> Message{0x01};
        AppendU24(Message, Body.size());
        Message.insert(Message.end(), Body.begin(), Body.end());
        return Message;
    }

    auto MakeTlsRecord(const std::vector<std::uint8_t> &Message) -> std::vector<std::byte>
    {
        std::vector<std::byte> Record;
        Record.reserve(Message.size() + 5);
        Record.push_back(std::byte{0x16});
        Record.push_back(std::byte{0x03});
        Record.push_back(std::byte{0x03});
        Record.push_back(static_cast<std::byte>((Message.size() >> 8) & 0xFFU));
        Record.push_back(static_cast<std::byte>(Message.size() & 0xFFU));
        for (const auto Byte : Message)
        {
            Record.push_back(static_cast<std::byte>(Byte));
        }
        return Record;
    }

    struct HandshakeRun
    {
        Preview::Error ClientError{Preview::Error::None};
        Core::CommitResult Commit;
        std::exception_ptr Exception;
    };

    struct HandshakeState
    {
        explicit HandshakeState(Net::io_context &Context) : Io(Context) {}

        void Complete(std::exception_ptr Error)
        {
            if (Error && !Result.Exception)
            {
                Result.Exception = Error;
            }
            ++Completed;
            if (Completed == 2)
            {
                Io.stop();
            }
        }

        Net::io_context &Io;
        HandshakeRun Result;
        std::size_t Completed{0};
    };

    using ClientHandshakeFn = std::function<Net::awaitable<Preview::Error>(Preview::SharedTransmission)>;

    auto RunConcreteHandshake(Composition::TlsCandidateBinding Binding, ClientHandshakeFn Client)
        -> HandshakeRun
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto ClientRaw = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto ServerRaw = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto State = std::make_shared<HandshakeState>(Io);
        Net::co_spawn(
            Io,
            [ServerRaw, Binding = std::move(Binding), State]() mutable -> Net::awaitable<void>
            {
                Core::CommitContext Context;
                Context.Candidate = Binding.Spec.Id;
                Context.Inbound = ServerRaw;
                State->Result.Commit = co_await Binding.Spec.Commit(std::move(Context));
                if (State->Result.Commit.Transport)
                {
                    State->Result.Commit.Transport->Close();
                }
            },
            [State](std::exception_ptr Error) { State->Complete(Error); });
        Net::co_spawn(
            Io,
            [ClientRaw, Client = std::move(Client), State]() mutable -> Net::awaitable<void>
            {
                State->Result.ClientError = co_await Client(ClientRaw);
            },
            [State](std::exception_ptr Error) { State->Complete(Error); });
        Io.run();
        if (State->Result.Exception)
        {
            try
            {
                std::rethrow_exception(State->Result.Exception);
            }
            catch (const std::exception &Error)
            {
                ADD_FAILURE() << Error.what();
            }
            catch (...)
            {
                ADD_FAILURE() << "unknown coroutine exception";
            }
        }
        auto Result = std::move(State->Result);
        Result.Commit.Transport.reset();
        State.reset();
        return Result;
    }

    struct WsAcceptState
    {
        Preview::Error Error{Preview::Error::None};

        auto Run(Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::SharedTransmission>
        {
            auto [ErrorCode, Key, Conn] = co_await Preview::Ws::Accept(std::move(Inbound), {});
            Error = ErrorCode;
            (void)Key;
            if (ErrorCode == Preview::Error::None)
            {
                co_return Preview::SharedTransmission(std::move(Conn));
            }
            co_return Preview::SharedTransmission{};
        }
    };

    auto MakeWsAccept(const std::shared_ptr<WsAcceptState> &State) -> Composition::CarrierAcceptFn
    {
        return [State](Preview::SharedTransmission Inbound)
        {
            return State->Run(std::move(Inbound));
        };
    }

    struct AnytlsAcceptState
    {
        Preview::Error Error{Preview::Error::None};
        std::string Password;

        auto Run(Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::SharedTransmission>
        {
            auto [ErrorCode, Conn] = co_await Preview::Anytls::Accept(
                std::move(Inbound), Preview::Anytls::ServerConfig{Password});
            Error = ErrorCode;
        if (ErrorCode == Preview::Error::None)
        {
            co_return Preview::SharedTransmission(std::move(Conn));
        }
        co_return Preview::SharedTransmission{};
        }
    };

    auto MakeAnytlsAccept(const std::shared_ptr<AnytlsAcceptState> &State)
        -> Composition::CarrierAcceptFn
    {
        return [State](Preview::SharedTransmission Inbound)
        {
            return State->Run(std::move(Inbound));
        };
    }

    auto RunWsClient(Preview::SharedTransmission Inbound, std::string Host)
        -> Net::awaitable<Preview::Error>
    {
        auto [ErrorCode, Conn] = co_await Preview::Ws::Connect(
            std::move(Inbound), Preview::Ws::ClientConfig{std::move(Host)});
        if (Conn)
        {
            Conn->Close();
        }
        co_return ErrorCode;
    }

    auto RunAnytlsClient(Preview::SharedTransmission Inbound, std::string Password)
        -> Net::awaitable<Preview::Error>
    {
        auto [ErrorCode, Conn] = co_await Preview::Anytls::Connect(
            std::move(Inbound), Preview::Anytls::ClientConfig{std::move(Password)});
        if (Conn)
        {
            Conn->Close();
        }
        co_return ErrorCode;
    }

    auto RunBadWsClient(Preview::SharedTransmission Inbound, std::string Host)
        -> Net::awaitable<Preview::Error>
    {
        (void)Host;
        const std::string Request = "GET / HTTP/1.1\r\nHost: edge.example\r\n\r\n";
        std::error_code Error;
        co_await Inbound->async_write_some(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.data()), Request.size()),
            Error);
        if (Error)
        {
            co_return Preview::Error::IoError;
        }
        co_return Preview::Error::None;
    }

    TEST(RecognitionCarrier, FiltersBySniAndAlpnWithoutExecutingScheme)
    {
        Preview::Recognition::SchemeExecutor Executor;
        std::size_t Executes = 0;
        ASSERT_TRUE(Executor.RegisterScheme(
            "native", [&Executes](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::SharedTransmission>
            {
                ++Executes;
                co_return Inbound;
            }));

        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{7, "native", "native", {"edge.example"}, {"h2"}},
            &Executor);
        const auto Features = MakeFeatures("edge.example", {"h2", "http/1.1"});

        EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Structural);
        EXPECT_EQ(Executes, 0U);
    }

    TEST(RecognitionCarrier, CommitsSchemeOnlyAfterWinnerSelection)
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        Writer.Close();
        Preview::Recognition::SchemeExecutor Executor;
        std::size_t Executes = 0;
        ASSERT_TRUE(Executor.RegisterScheme(
            "ws", [&Executes](Preview::SharedTransmission Transport)
            -> Net::awaitable<Preview::SharedTransmission>
            {
                ++Executes;
                co_return Transport;
            }));

        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{8, "ws", "ws", {"edge.example"}, {"http/1.1"}},
            &Executor);
        Core::CommitContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Inbound = Inbound;
        Core::CommitResult Result;
        Net::co_spawn(Io, Binding.Spec.Commit(std::move(Context)),
                      [&Result, &Io](std::exception_ptr Error, Core::CommitResult Value)
                      {
                          if (!Error)
                          {
                              Result = std::move(Value);
                          }
                          Io.stop();
                      });
        Io.run();

        EXPECT_EQ(Executes, 1U);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
    }

    TEST(RecognitionCarrier, RejectsMissingSniUnlessExplicitFallback)
    {
        Preview::Recognition::SchemeExecutor Executor;
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{9, "native", "native", {"edge.example"}, {"h2"}},
            &Executor);
        EXPECT_EQ(Binding.Inspect(MakeFeatures("", {"h2"})), Core::MatchState::Rejected);

        auto Fallback = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{10, "native-fallback", "native", {}, {}, true},
            &Executor);
        EXPECT_EQ(Fallback.Inspect(MakeFeatures("", {})), Core::MatchState::Structural);
    }

    TEST(RecognitionCarrier, RejectsEchWithoutInnerHelloSupport)
    {
        auto Features = MakeFeatures("outer.example", {"h2"});
        Features.HasEch = true;

        Preview::Recognition::SchemeExecutor Executor;
        auto Routed = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{30, "native", "native", {"outer.example"}, {"h2"}},
            &Executor);
        auto Fallback = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{31, "native-fallback", "native", {}, {}, true},
            &Executor);

        EXPECT_EQ(Routed.Inspect(Features), Core::MatchState::Rejected);
        EXPECT_EQ(Fallback.Inspect(Features), Core::MatchState::Rejected);
    }

    TEST(RecognitionCarrier, ParsesClientHelloBeforeProfileCommit)
    {
        const auto Record = MakeTlsRecord(MakeClientHello("edge.example", "h2"));
        const auto Parsed = Core::ParseClientHello(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Record.data()), Record.size()));
        ASSERT_EQ(Parsed.first, Preview::Error::None);
        ASSERT_EQ(Parsed.second.ServerName, "edge.example");
        ASSERT_EQ(Parsed.second.AlpnProtocols.front(), "h2");

        Net::io_context Io;
        std::size_t Executes = 0;
        Preview::Recognition::SchemeExecutor Executor;
        ASSERT_TRUE(Executor.RegisterScheme(
            "native", [&Executes](Preview::SharedTransmission Transport)
            -> Net::awaitable<Preview::SharedTransmission>
            {
                ++Executes;
                co_return Transport;
            }));
        auto Binding = Composition::TlsCandidateFactory::MakeNative(
            Composition::TlsCandidateOptions{11, "native", "", {"edge.example"}, {"h2"}}, &Executor);
        Core::ProfileSpec Spec;
        Spec.ConfiguredCandidate = Binding.Spec.Id;
        Spec.Candidates.push_back(Binding.Spec);
        auto Profile = Core::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Profile.has_value());

        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Source = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        Core::RecognizeResult Result;
        Net::co_spawn(
            Io,
            [Source, Inbound, Profile = *Profile, Record = std::move(Record), &Result]() mutable
                -> Net::awaitable<void>
            {
                std::error_code WriteError;
                co_await Source->async_write_some(Record, WriteError);
                Source->Shutdown();
                Core::Pipeline Pipeline(Profile);
                Result = co_await Pipeline.Recognize(Inbound);
                if (Result.transport)
                {
                    Result.transport->Close();
                }
                Source->Close();
            },
            Net::detached);
        Io.run();

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, 11U);
        EXPECT_EQ(Result.CandidateName, "native");
        EXPECT_EQ(Executes, 1U);
    }

    TEST(RecognitionCarrier, ExposesAllCarrierSchemeNames)
    {
        const std::vector<std::pair<Composition::TlsCarrier, std::string>> Cases = {
            {Composition::TlsCarrier::Native, "native"},
            {Composition::TlsCarrier::Reality, "reality"},
            {Composition::TlsCarrier::Shadowtls, "shadowtls"},
            {Composition::TlsCarrier::Restls, "restls"},
            {Composition::TlsCarrier::Anytls, "anytls"},
            {Composition::TlsCarrier::Ws, "ws"},
            {Composition::TlsCarrier::Xhttp, "xhttp"},
            {Composition::TlsCarrier::Gun, "gun"},
            {Composition::TlsCarrier::Trusttunnel, "trusttunnel"},
        };
        for (const auto &[Carrier, Scheme] : Cases)
        {
            auto Options = Composition::TlsCandidateOptions{21, {}, {}, {"edge.example"}, {"h2"}};
            Options.Carrier = Carrier;
            const auto Binding = Composition::TlsCandidateFactory::Make(
                Options, static_cast<Preview::Recognition::SchemeExecutor *>(nullptr));
            EXPECT_EQ(Binding.Scheme, Scheme);
            EXPECT_EQ(Binding.Spec.Name, Scheme);
            EXPECT_EQ(Binding.Spec.Scheme, Scheme);
        }
    }

    TEST(RecognitionCarrier, NormalizesDirectFactorySchemeAndFallback)
    {
        const auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{26, "native", "NATIVE", {}, {}, true},
            static_cast<Preview::Recognition::SchemeExecutor *>(nullptr));

        EXPECT_EQ(Binding.Spec.Scheme, "native");
        EXPECT_TRUE(Binding.Spec.Fallback);
    }

    TEST(RecognitionCarrier, MarksDirectFactoryAsTlsCarrier)
    {
        const auto Binding = Composition::TlsCandidateFactory::MakeNative(
            Composition::TlsCandidateOptions{27, "native", {}, {"edge.example"}, {"h2"}},
            static_cast<Preview::Recognition::SchemeExecutor *>(nullptr));

        EXPECT_EQ(Binding.Spec.Kind, Core::CandidateKind::TlsCarrier);
    }

    TEST(RecognitionCarrier, SchemeExceptionBecomesNoMatch)
    {
        Preview::Recognition::SchemeExecutor Executor;
        ASSERT_TRUE(Executor.RegisterScheme(
            "throwing", [](Preview::SharedTransmission) -> Net::awaitable<Preview::SharedTransmission>
            {
                throw std::runtime_error("carrier failure");
                co_return nullptr;
            }));
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{28, "throwing", "throwing", {}, {}}, &Executor);
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission) -> Net::awaitable<Preview::Error>
            {
                co_return Preview::Error::None;
            });

        EXPECT_EQ(Result.Exception, nullptr);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
    }

    TEST(RecognitionCarrier, ShadowtlsServerAdapterRejectsMalformedInbound)
    {
        const auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{29, "shadowtls", "shadowtls", {}, {}},
            Composition::MakeShadowtlsServerAccept(Preview::Shadowtls::ServerOptions{},
                                                    Preview::Shadowtls::ServerConfig{"carrier-password"}));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound) -> Net::awaitable<Preview::Error>
            {
                const std::array<std::uint8_t, 2> Malformed{0x16, 0x03};
                std::error_code Ec;
                co_await Inbound->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Malformed.data()), Malformed.size()),
                    Ec);
                Inbound->Shutdown();
                co_return Preview::Error::None;
            });
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Error, Preview::make_error_code(Preview::Error::BadAuth));
    }

    TEST(RecognitionCarrier, WebsocketConcreteAcceptRunsOnlyAtCommit)
    {
        auto State = std::make_shared<WsAcceptState>();
        std::size_t NativeCalls = 0;
        Preview::Recognition::SchemeExecutor Executor;
        ASSERT_TRUE(Executor.RegisterScheme(
            "native", [&NativeCalls](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::SharedTransmission>
            {
                ++NativeCalls;
                co_return Inbound;
            }));
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{22, "ws", "ws", {"edge.example"}, {"http/1.1"}},
            &Executor, MakeWsAccept(State));
        EXPECT_EQ(Binding.Inspect(MakeFeatures("edge.example", {"http/1.1"})),
                  Core::MatchState::Structural);
        EXPECT_EQ(NativeCalls, 0U);
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            {
                return RunWsClient(std::move(Inbound), "edge.example");
            });
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(State->Error, Preview::Error::None);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(NativeCalls, 0U);
    }

    TEST(RecognitionCarrier, WebsocketConcreteFailureDoesNotFallbackNative)
    {
        auto State = std::make_shared<WsAcceptState>();
        std::size_t NativeCalls = 0;
        Preview::Recognition::SchemeExecutor Executor;
        ASSERT_TRUE(Executor.RegisterScheme(
            "native", [&NativeCalls](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::SharedTransmission>
            {
                ++NativeCalls;
                co_return Inbound;
            }));
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{23, "ws", "ws", {"edge.example"}, {"http/1.1"}},
            &Executor, MakeWsAccept(State));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            {
                return RunBadWsClient(std::move(Inbound), "edge.example");
            });
        EXPECT_EQ(State->Error, Preview::Error::BadMagic);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(NativeCalls, 0U);
    }

    TEST(RecognitionCarrier, AnytlsConcreteAcceptAuthenticatesAtCommit)
    {
        auto State = std::make_shared<AnytlsAcceptState>();
        State->Password = "carrier-secret";
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{24, "anytls", "anytls", {"edge.example"}, {}},
            MakeAnytlsAccept(State));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            {
                return RunAnytlsClient(std::move(Inbound), "carrier-secret");
            });
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(State->Error, Preview::Error::None);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::Accepted);
    }

    TEST(RecognitionCarrier, AnytlsWrongPasswordDoesNotFallbackNative)
    {
        auto State = std::make_shared<AnytlsAcceptState>();
        State->Password = "carrier-secret";
        std::size_t NativeCalls = 0;
        Preview::Recognition::SchemeExecutor Executor;
        ASSERT_TRUE(Executor.RegisterScheme(
            "native", [&NativeCalls](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::SharedTransmission>
            {
                ++NativeCalls;
                co_return Inbound;
            }));
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{25, "anytls", "anytls", {"edge.example"}, {}},
            &Executor, MakeAnytlsAccept(State));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            {
                return RunAnytlsClient(std::move(Inbound), "wrong-secret");
            });
        EXPECT_EQ(State->Error, Preview::Error::BadAuth);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(NativeCalls, 0U);
    }

} // namespace
