/**
 * @file RecognitionCarrier.cpp
 * @brief TLS carrier 候选与 scheme 提交行为 RED 测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <stdexcept>
#include <span>
#include <system_error>
#include <vector>

#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Composition/Recognition/ShadowtlsCarrier.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/CandidateRegistry.hpp>
#include <Preview/Protocols/Shadowtls/Server.hpp>
#include <Preview/Protocols/Anytls/Anytls.hpp>
#include <Preview/Protocols/Gun/Gun.hpp>
#include <Preview/Protocols/Xhttp/Xhttp.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Transport/MemoryStream.hpp>

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

        auto Run(Preview::SharedTransmission Inbound) -> Net::awaitable<Core::CarrierAcceptResult>
        {
            auto [ErrorCode, Key, Conn] = co_await Preview::Ws::Accept(std::move(Inbound), {});
            Error = ErrorCode;
            (void)Key;
            Core::CarrierAcceptResult Result;
            if (ErrorCode == Preview::Error::None)
            {
                Result.Transport = Preview::SharedTransmission(std::move(Conn));
            }
            else
            {
                Result.Code = Preview::Fault::ToCode(Preview::make_error_code(ErrorCode));
            }
            co_return Result;
        }
    };

    auto MakeWsAccept(const std::shared_ptr<WsAcceptState> &State) -> Composition::CarrierAcceptFn
    {
        return [State](Preview::SharedTransmission Inbound)
        {
            return State->Run(std::move(Inbound));
        };
    }

    inline constexpr std::array<std::byte, 6> AnytlsPayload{
        std::byte{0x50}, std::byte{0x72}, std::byte{0x69},
        std::byte{0x73}, std::byte{0x6D}, std::byte{0x21}};

    struct AnytlsProtocolOptions
    {
        std::string ClientPassword;
        std::string ServerPassword;
        bool TransferPayload{false};
    };

    struct AnytlsProtocolOutcome
    {
        Preview::Error ClientError{Preview::Error::None};
        Preview::Error ServerError{Preview::Error::None};
        bool ClientConnected{false};
        bool ServerConnected{false};
        bool TimedOut{false};
        std::error_code ReadError;
        std::error_code WriteError;
        std::size_t ReadBytes{0};
        std::size_t WrittenBytes{0};
        std::array<std::byte, AnytlsPayload.size()> Received{};
        std::exception_ptr Exception;
    };

    struct AnytlsProtocolState
    {
        AnytlsProtocolState(Net::io_context &Context, AnytlsProtocolOptions Options)
            : Deadline(Context), Options(std::move(Options))
        {
        }

        auto Complete(std::exception_ptr Error) -> void
        {
            if (Error && !Outcome.Exception)
            {
                Outcome.Exception = Error;
            }
            ++Completed;
            if (Completed == 2)
            {
                (void)Deadline.cancel();
            }
        }

        Net::steady_timer Deadline;
        AnytlsProtocolOptions Options;
        AnytlsProtocolOutcome Outcome;
        std::size_t Completed{0};
    };

    auto RunAnytlsAccept(std::shared_ptr<AnytlsProtocolState> State,
                         Preview::SharedTransmission Inbound) -> Net::awaitable<void>
    {
        const Preview::Anytls::ServerConfig Config{State->Options.ServerPassword};
        auto [ErrorCode, Conn] = co_await Preview::Anytls::Accept(std::move(Inbound), Config);
        State->Outcome.ServerError = ErrorCode;
        State->Outcome.ServerConnected = static_cast<bool>(Conn);
        if (!Conn)
        {
            co_return;
        }
        State->Outcome.ReadBytes = co_await Conn->async_read_some(
            State->Outcome.Received, State->Outcome.ReadError);
        Conn->Close();
    }

    auto RunAnytlsConnect(std::shared_ptr<AnytlsProtocolState> State,
                          Preview::SharedTransmission Inbound) -> Net::awaitable<void>
    {
        const Preview::Anytls::ClientConfig Config{State->Options.ClientPassword};
        auto [ErrorCode, Conn] = co_await Preview::Anytls::Connect(std::move(Inbound), Config);
        State->Outcome.ClientError = ErrorCode;
        State->Outcome.ClientConnected = static_cast<bool>(Conn);
        if (!Conn)
        {
            co_return;
        }
        if (State->Options.TransferPayload)
        {
            State->Outcome.WrittenBytes = co_await Conn->async_write_some(
                AnytlsPayload, State->Outcome.WriteError);
        }
        Conn->Close();
    }

    auto RunAnytlsProtocolPair(AnytlsProtocolOptions Options) -> AnytlsProtocolOutcome
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        Preview::SharedTransmission ClientRaw =
            std::make_shared<Preview::MemoryStream>(std::move(Writer));
        Preview::SharedTransmission ServerRaw =
            std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto State = std::make_shared<AnytlsProtocolState>(Io, std::move(Options));
        State->Deadline.expires_after(std::chrono::seconds(3));
        State->Deadline.async_wait(
            [State, ClientRaw, ServerRaw](boost::system::error_code Error)
            {
                if (Error)
                {
                    return;
                }
                State->Outcome.TimedOut = true;
                ClientRaw->Close();
                ServerRaw->Close();
            });

        const auto Complete = [State](std::exception_ptr Error) { State->Complete(Error); };
        Net::co_spawn(Io, RunAnytlsAccept(State, ServerRaw), Complete);
        Net::co_spawn(Io, RunAnytlsConnect(State, ClientRaw), Complete);
        Io.run();
        ClientRaw->Close();
        ServerRaw->Close();
        return std::move(State->Outcome);
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

    auto SnapshotOf(std::string_view Data) -> Core::ProbeSnapshot
    {
        auto Storage = std::make_shared<std::vector<std::byte>>();
        Storage->reserve(Data.size());
        for (const auto Character : Data)
        {
            Storage->push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
        }
        Core::ProbeSnapshot Snapshot;
        Snapshot.Storage = std::move(Storage);
        return Snapshot;
    }

    auto RunPrepare(Core::PrepareFn Prepare, Core::PrepareContext Context) -> Core::PrepareResult
    {
        Net::io_context Io;
        Core::PrepareResult Result;
        std::exception_ptr Failure;
        Net::co_spawn(Io, Prepare(std::move(Context)),
                      [&Result, &Failure, &Io](std::exception_ptr Error, Core::PrepareResult Value)
                      {
                          Failure = std::move(Error);
                          if (!Failure)
                          {
                              Result = std::move(Value);
                          }
                          Io.stop();
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        return Result;
    }

    struct AnytlsCandidateAcceptOutcome
    {
        Preview::Fault::Code Code{Preview::Fault::Code::ProtocolError};
        bool IsMux{false};
        bool ProtocolAuthenticated{false};
        bool HasTransport{false};
        std::string Mode;
        std::exception_ptr Exception;
    };

    struct AnytlsCandidateAcceptState
    {
        Composition::CandidateBinding Binding;
        Preview::SharedTransmission Client;
        Preview::SharedTransmission Server;
        std::string Frame;
        AnytlsCandidateAcceptOutcome Outcome;
    };

    auto WriteFrame(Preview::SharedTransmission Transport, std::string Frame)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Frame.size())
        {
            std::error_code Error;
            const auto Bytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Frame.data() + Offset), Frame.size() - Offset);
            const auto Written = co_await Transport->async_write_some(Bytes, Error);
            if (Error || Written == 0 || Written > Frame.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    auto RunAnytlsCandidateAccept(std::shared_ptr<AnytlsCandidateAcceptState> State)
        -> Net::awaitable<void>
    {
        if (!co_await WriteFrame(State->Client, std::move(State->Frame)))
        {
            State->Outcome.Code = Preview::Fault::Code::IoError;
            co_return;
        }
        Preview::Middleware::Context Context;
        auto Inbound = State->Server;
        State->Outcome.Code = co_await State->Binding.Accept(Inbound, Context);
        State->Outcome.IsMux = Context.DataPlane.IsMux();
        State->Outcome.ProtocolAuthenticated = Context.ProtocolAuthenticated;
        const auto Transport = Context.DataPlane.Transport();
        State->Outcome.HasTransport = static_cast<bool>(Transport);
        if (const auto *Mux = Context.DataPlane.Mux())
        {
            State->Outcome.Mode = Mux->Mode;
        }
        if (Transport)
        {
            Transport->Close();
        }
        State->Client->Close();
        State->Server->Close();
    }

    auto RunAnytlsCandidateAccept(Composition::CandidateBinding Binding, std::string Frame)
        -> AnytlsCandidateAcceptOutcome
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto State = std::make_shared<AnytlsCandidateAcceptState>(
            AnytlsCandidateAcceptState{
                std::move(Binding),
                std::make_shared<Preview::MemoryStream>(std::move(Writer)),
                std::make_shared<Preview::MemoryStream>(std::move(Reader)),
                std::move(Frame),
                {}});
        Net::co_spawn(Io, RunAnytlsCandidateAccept(State),
                      [State](std::exception_ptr Error) { State->Outcome.Exception = Error; });
        Io.run();
        State->Client->Close();
        State->Server->Close();
        return std::move(State->Outcome);
    }

    auto MakeAnytlsAuthFrame(std::string_view Password, const std::uint16_t PadLen = 0)
        -> std::string
    {
        std::string Frame;
        EXPECT_EQ(Preview::Anytls::BuildAuthFrame(Password, PadLen, Frame), Preview::Error::None);
        return Frame;
    }

    TEST(RecognitionCarrier, AnytlsCandidateFactoryAndRegistryConstructTypedBinding)
    {
        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.RegisterAnytls(Preview::Anytls::ServerConfig{"candidate-secret"}));
        EXPECT_TRUE(Registry.Has("anytls"));

        Composition::CandidateOptions Options;
        Options.Id = 101;
        Options.Name = "anytls";
        auto FactoryBinding = Composition::CandidateFactory::MakeAnytls(
            Options, Preview::Anytls::ServerConfig{"candidate-secret"});
        EXPECT_EQ(FactoryBinding.Spec.Protocol, Core::ProtocolType::AnyTls);
        EXPECT_EQ(FactoryBinding.Spec.Kind, Core::CandidateKind::Opaque);
        EXPECT_TRUE(FactoryBinding.Spec.RequiresAuthentication);

        Preview::Settings::RecognitionCandidate Candidate;
        Candidate.Id = 102;
        Candidate.Name = "anytls";
        Candidate.Protocol = "anytls";
        const auto Binding = Registry.Build(Candidate);
        ASSERT_TRUE(Binding.has_value());
        EXPECT_EQ(Binding->Spec.Protocol, Core::ProtocolType::AnyTls);
    }

    TEST(RecognitionCarrier, AnytlsCandidateAuthenticatesIntoMuxDataPlane)
    {
        auto Binding = Composition::CandidateFactory::MakeAnytls(
            Composition::CandidateOptions{103, "anytls", 0, 0, false},
            Preview::Anytls::ServerConfig{"candidate-secret"});
        const auto Result = RunAnytlsCandidateAccept(
            std::move(Binding), MakeAnytlsAuthFrame("candidate-secret", 3));

        EXPECT_EQ(Result.Exception, nullptr);
        EXPECT_EQ(Result.Code, Preview::Fault::Code::Success);
        EXPECT_TRUE(Result.IsMux);
        EXPECT_TRUE(Result.ProtocolAuthenticated);
        EXPECT_TRUE(Result.HasTransport);
        EXPECT_EQ(Result.Mode, "auto");
    }

    TEST(RecognitionCarrier, AnytlsCandidateRejectsWrongPasswordBeforeCommit)
    {
        auto Binding = Composition::CandidateFactory::MakeAnytls(
            Composition::CandidateOptions{104, "anytls", 0, 0, false},
            Preview::Anytls::ServerConfig{"candidate-secret"});
        const auto Frame = MakeAnytlsAuthFrame("wrong-secret");
        const auto Snapshot = SnapshotOf(Frame);
        EXPECT_EQ(Binding.Spec.Inspect(Snapshot), Core::MatchState::Rejected);

        Core::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Snapshot;
        const auto Prepared = RunPrepare(Binding.Spec.Prepare, std::move(Context));
        EXPECT_EQ(Prepared.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_FALSE(Prepared.NeedMore);
    }

    TEST(RecognitionCarrier, AnytlsCandidateRejectsPaddedIncompleteAuthFrame)
    {
        auto Binding = Composition::CandidateFactory::MakeAnytls(
            Composition::CandidateOptions{105, "anytls", 0, 0, false},
            Preview::Anytls::ServerConfig{"candidate-secret"});
        auto Frame = MakeAnytlsAuthFrame("candidate-secret", 5);
        Frame.resize(Preview::Anytls::AuthFrameHdrlen + 4);
        const auto Snapshot = SnapshotOf(Frame);
        EXPECT_EQ(Binding.Spec.Inspect(Snapshot), Core::MatchState::NeedMore);

        Core::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Snapshot;
        const auto Prepared = RunPrepare(Binding.Spec.Prepare, std::move(Context));
        EXPECT_EQ(Prepared.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_TRUE(Prepared.NeedMore);
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
            {Composition::TlsCarrier::Ws, "ws"},
            {Composition::TlsCarrier::Xhttp, "xhttp"},
            {Composition::TlsCarrier::Gun, "gun"},
        };
        EXPECT_EQ(Cases.size(), 7U);
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

    TEST(RecognitionCarrier, ShadowtlsServerAdapterPreservesMissingTargetFault)
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
        EXPECT_EQ(Result.Commit.FaultCode, Preview::Fault::Code::NotSupported);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "shadowtls");
    }

    TEST(RecognitionCarrier, ShadowtlsConfiguredCarrierRequiresDialContextAndDestination)
    {
        Composition::ShadowtlsCarrierOptions Options;
        Options.HandshakeDest = "target.example:443";
        Options.Password = "shadowtls-test-password";

        EXPECT_FALSE(Composition::MakeConfiguredShadowtlsServerAccept(Options).has_value());

        Options.Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::NotSupported,
                                Preview::SharedTransmission{}};
        };
        const auto Accept = Composition::MakeConfiguredShadowtlsServerAccept(std::move(Options));
        ASSERT_TRUE(Accept.has_value());

        Composition::TlsCandidateOptions Candidate;
        Candidate.Id = 32;
        Candidate.Name = "shadowtls-configured";
        Candidate.Scheme = "shadowtls";
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Candidate), std::move(*Accept));
        EXPECT_EQ(Binding.Spec.Scheme, "shadowtls");
        EXPECT_TRUE(static_cast<bool>(Binding.Spec.Commit));
    }

    TEST(RecognitionCarrier, WebsocketServerAcceptFactoryRunsRealHandshake)
    {
        Composition::TlsCandidateOptions Options;
        Options.Id = 31;
        Options.Name = "ws-real";
        Options.Scheme = "ws";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"http/1.1"};
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            Composition::MakeWebsocketServerAccept(
                Preview::Ws::ServerConfig{"/", "edge.example"}));

        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            {
                return RunWsClient(std::move(Inbound), "edge.example");
            });

        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "ws");
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

    TEST(RecognitionCarrier, XhttpServerAcceptFactoryRunsRealHandshake)
    {
        auto TlsContext = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Preview::Xhttp::Config Config;
        Config.Path = "/xhttp";
        Config.Host = "edge.example";
        Config.Mode = "StreamOne";
        Composition::TlsCandidateOptions Options;
        Options.Id = 33;
        Options.Name = "xhttp-real";
        Options.Scheme = "xhttp";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            Composition::MakeXhttpServerAccept(TlsContext, std::move(Config)));

        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::Error>
            {
                const std::array<std::byte, 2> Invalid{std::byte{0x16}, std::byte{0x03}};
                std::error_code ErrorCode;
                (void)co_await Inbound->async_write_some(Invalid, ErrorCode);
                Inbound->Close();
                co_return Preview::Error::None;
            });

        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "xhttp");
        EXPECT_TRUE(Preview::Fault::Failed(Result.Commit.FaultCode));
    }

    TEST(RecognitionCarrier, GunServerAcceptFactoryRunsRealHandshake)
    {
        auto TlsContext = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Composition::TlsCandidateOptions Options;
        Options.Id = 34;
        Options.Name = "gun-real";
        Options.Scheme = "gun";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            Composition::MakeGunServerAccept(
                TlsContext, "/GunService/Tun", "GunService"));

        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::Error>
            {
                const std::array<std::byte, 2> Invalid{std::byte{0x16}, std::byte{0x03}};
                std::error_code ErrorCode;
                (void)co_await Inbound->async_write_some(Invalid, ErrorCode);
                Inbound->Close();
                co_return Preview::Error::None;
            });

        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "gun");
        EXPECT_TRUE(Preview::Fault::Failed(Result.Commit.FaultCode));
    }

    TEST(RecognitionCarrier, RealityPreparedFactoryRejectsMissingPreparedHello)
    {
        std::array<std::uint8_t, Preview::Reality::KeyLen> PrivateKey{};
        std::vector<std::array<std::uint8_t, Preview::Reality::MaxShortIdLen>> ShortIds(1);
        Composition::TlsCandidateOptions Options;
        Options.Id = 35;
        Options.Name = "reality-prepared";
        Options.Scheme = "reality";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        const auto Binding = Composition::TlsCandidateFactory::MakePrepared(
            std::move(Options),
            Composition::MakeRealityServerAccept(PrivateKey, std::move(ShortIds)));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::Error>
            {
                Inbound->Close();
                co_return Preview::Error::None;
            });

        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "reality");
        EXPECT_TRUE(Preview::Fault::Failed(Result.Commit.FaultCode));
    }

    TEST(RecognitionCarrier, AnytlsProtocolAuthenticatesAndPreservesWirePayload)
    {
        const auto Result = RunAnytlsProtocolPair(
            AnytlsProtocolOptions{"carrier-secret", "carrier-secret", true});

        EXPECT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ServerError, Preview::Error::None);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_TRUE(Result.ServerConnected);
        EXPECT_FALSE(Result.ReadError);
        EXPECT_FALSE(Result.WriteError);
        EXPECT_EQ(Result.ReadBytes, AnytlsPayload.size());
        EXPECT_EQ(Result.WrittenBytes, AnytlsPayload.size());
        EXPECT_EQ(Result.Received, AnytlsPayload);
        EXPECT_EQ(Result.Exception, nullptr);
    }

    TEST(RecognitionCarrier, AnytlsProtocolRejectsWrongPassword)
    {
        const auto Result = RunAnytlsProtocolPair(
            AnytlsProtocolOptions{"wrong-secret", "carrier-secret", false});

        EXPECT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ServerError, Preview::Error::BadAuth);
        EXPECT_FALSE(Result.ServerConnected);
        EXPECT_EQ(Result.Exception, nullptr);
    }

} // namespace
