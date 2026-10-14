/**
 * @file RecognitionCarrierTestSupport.hpp
 * @brief RecognitionCarrier.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file RecognitionCarrier.cpp
 * @brief TLS carrier 候选与 scheme 提交行为 RED 测试
 */

#include "../../protocols/Ws/WsFactorySupport.hpp"
#include <gtest/gtest.h>
#include <TestSupport/Fixtures/StreamFactory.hpp>

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
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
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

    /** @brief 关闭测试传输并等待本层活动预约全部退栈。 */
    auto CloseAndDrain(Preview::SharedTransmission Transport) -> Net::awaitable<void>
    {
        if (!Transport)
        {
            co_return;
        }
        const auto CloseResult = Transport->Close();
        EXPECT_TRUE(CloseResult);
        const auto DrainResult = co_await Transport->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
    }

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
                Context.Bytes = Preview::Tests::WsFactorySupport::WebSocketTestBytes();
                State->Result.Commit = co_await Binding.Spec.Commit(std::move(Context));
                co_await CloseAndDrain(State->Result.Commit.Transport);
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
        Preview::Fault::Failure Failure{};
        std::size_t Calls{0};

        auto Run(Core::CarrierAcceptInput Input) -> Net::awaitable<Core::CarrierAcceptResult>
        {
            ++Calls;
            Failure = {};
            auto Accepted = co_await Preview::Ws::Accept(
                Preview::Ws::AcceptOptions{
                    std::move(Input.Inbound), std::move(Input.Bytes), {}});
            Core::CarrierAcceptResult Result;
            if (!Accepted)
            {
                Failure = Accepted.error();
                Result.Code = Failure.Code;
                Result.NativeError = Failure.Native;
                co_return Result;
            }
            if (!Accepted->Connection)
            {
                Failure = {Preview::Fault::Code::ProtocolError};
                Result.Code = Failure.Code;
                co_return Result;
            }
            Result.Transport = Preview::SharedTransmission(
                std::move(Accepted->Connection));
            co_return Result;
        }
    };

    auto MakeWsAccept(const std::shared_ptr<WsAcceptState> &State) -> Composition::CarrierAcceptFn
    {
        return [State](Core::CarrierAcceptInput Input)
        {
            return State->Run(std::move(Input));
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
        Preview::Fault::Failure ClientError;
        Preview::Fault::Failure ServerError;
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

    /**
     * @brief 持有 AnyTLS 协议对的超时回调及其原始传输 owner。
     * @details timer 取消只结束等待；仅真实到期时标记超时并关闭双方载体。
     */
    struct AnytlsProtocolTimeout final
    {
        std::shared_ptr<AnytlsProtocolState> State;
        Preview::SharedTransmission ClientRaw;
        Preview::SharedTransmission ServerRaw;

        auto operator()(boost::system::error_code Error) const -> void
        {
            if (Error)
            {
                return;
            }
            State->Outcome.TimedOut = true;
            const auto ClientCloseResult = ClientRaw->Close();
            const auto ServerCloseResult = ServerRaw->Close();
            EXPECT_TRUE(ClientCloseResult);
            EXPECT_TRUE(ServerCloseResult);
        }
    };

    auto RunAnytlsAccept(std::shared_ptr<AnytlsProtocolState> State,
                         Preview::SharedTransmission Inbound) -> Net::awaitable<void>
    {
        const Preview::Anytls::ServerConfig Config{State->Options.ServerPassword};
        auto Accepted = co_await Preview::Anytls::Accept(std::move(Inbound), Config);
        if (!Accepted)
        {
            State->Outcome.ServerError = Accepted.error();
            State->Outcome.ServerConnected = false;
            co_return;
        }
        State->Outcome.ServerError = {};
        State->Outcome.ServerConnected = true;
        auto Conn = std::move(*Accepted);
        const auto Read = co_await Conn->ReadSome(State->Outcome.Received);
        State->Outcome.ReadError = Preview::Fault::ToNative(Read.Failure);
        State->Outcome.ReadBytes = Read.Bytes;
        co_await CloseAndDrain(Conn);
    }

    auto RunAnytlsConnect(std::shared_ptr<AnytlsProtocolState> State,
                          Preview::SharedTransmission Inbound) -> Net::awaitable<void>
    {
        const Preview::Anytls::ClientConfig Config{State->Options.ClientPassword};
        auto Connected = co_await Preview::Anytls::Connect(std::move(Inbound), Config);
        if (!Connected)
        {
            State->Outcome.ClientError = Connected.error();
            State->Outcome.ClientConnected = false;
            co_return;
        }
        State->Outcome.ClientError = {};
        State->Outcome.ClientConnected = true;
        auto Conn = std::move(*Connected);
        if (State->Options.TransferPayload)
        {
            const auto Write = co_await Conn->WriteSome(AnytlsPayload);
            State->Outcome.WriteError = Preview::Fault::ToNative(Write.Failure);
            State->Outcome.WrittenBytes = Write.Bytes;
        }
        co_await CloseAndDrain(Conn);
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
            AnytlsProtocolTimeout{State, ClientRaw, ServerRaw});

        const auto Complete = [State](std::exception_ptr Error) { State->Complete(Error); };
        Net::co_spawn(Io, RunAnytlsAccept(State, ServerRaw), Complete);
        Net::co_spawn(Io, RunAnytlsConnect(State, ClientRaw), Complete);
        Io.run();
        const auto ClientCloseResult = ClientRaw->Close();
        const auto ServerCloseResult = ServerRaw->Close();
        EXPECT_TRUE(ClientCloseResult);
        EXPECT_TRUE(ServerCloseResult);
        return std::move(State->Outcome);
    }

    auto RunWsClient(Preview::SharedTransmission Inbound, std::string Host)
        -> Net::awaitable<Preview::Error>
    {
        auto Connected = co_await Preview::Ws::Connect(
            Preview::Tests::WsFactorySupport::MakeConnectOptionsForTest(
                std::move(Inbound), Preview::Ws::ClientOptions{std::move(Host)}));
        if (!Connected)
        {
            co_return Preview::Error::IoError;
        }
        auto Connection = std::move(Connected->Connection);
        co_await CloseAndDrain(Connection);
        co_return Preview::Error::None;
    }

    auto RunBadWsClient(Preview::SharedTransmission Inbound, std::string Host)
        -> Net::awaitable<Preview::Error>
    {
        (void)Host;
        const std::string Request = "GET / HTTP/1.1\r\nHost: edge.example\r\n\r\n";
        std::error_code Error;
        const auto Write = co_await Inbound->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Request.data()), Request.size()));
        Error = Preview::Fault::ToNative(Write.Failure);
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
        bool HasOwner{false};
        std::exception_ptr Exception;
    };

    struct AnytlsCandidateAcceptState
    {
        Composition::CandidateBinding Binding;
        Preview::SharedTransmission Client;
        Preview::SharedTransmission Server;
        std::shared_ptr<Preview::Memory::BytePool> Bytes;
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
            const auto Write = co_await Transport->WriteSome(Bytes);
            Error = Preview::Fault::ToNative(Write.Failure);
            const auto Written = Write.Bytes;
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
        auto GenerationUseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Accepted = co_await State->Binding.Accept->Accept(
            Preview::Contract::StreamAcceptInput{
                std::move(Inbound), {}, std::move(State->Bytes), std::move(GenerationUseState)});
        if (Accepted)
        {
            State->Outcome.Code = Preview::Fault::Code::Success;
            Context.SetDataPlane(std::move(*Accepted));
            Inbound = Context.Inbound();
        }
        else
        {
            State->Outcome.Code = Accepted.error().Code;
        }
        State->Outcome.IsMux = Context.DataPlane.IsMux();
        State->Outcome.ProtocolAuthenticated = Context.ProtocolAuthenticated();
        const auto Transport = Context.DataPlane.Transport();
        State->Outcome.HasTransport = static_cast<bool>(Transport);
        if (const auto *Mux = Context.DataPlane.Mux())
        {
            State->Outcome.HasOwner = bool(Mux->Session);
        }
        if (Transport)
        {
            co_await CloseAndDrain(Transport);
        }
        co_await CloseAndDrain(State->Client);
        co_await CloseAndDrain(State->Server);
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
                Preview::Tests::WsFactorySupport::WebSocketTestBytes(),
                std::move(Frame),
                {}});
        Net::co_spawn(Io, RunAnytlsCandidateAccept(State),
                      [State](std::exception_ptr Error) { State->Outcome.Exception = Error; });
        Io.run();
        const auto ClientCloseResult = State->Client->Close();
        const auto ServerCloseResult = State->Server->Close();
        EXPECT_TRUE(ClientCloseResult);
        EXPECT_TRUE(ServerCloseResult);
        return std::move(State->Outcome);
    }

    auto MakeAnytlsAuthFrame(std::string_view Password, const std::uint16_t PadLen = 0)
        -> std::string
    {
        std::string Frame;
        EXPECT_EQ(Preview::Anytls::BuildAuthFrame(Password, PadLen, Frame), Preview::Error::None);
        return Frame;
    }


























} // namespace


