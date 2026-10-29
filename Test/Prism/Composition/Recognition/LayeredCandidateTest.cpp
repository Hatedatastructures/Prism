/**
 * @file LayeredCandidateTest.cpp
 * @brief TLS carrier 到内层协议 handler 的分层候选回归
 */

#include <gtest/gtest.h>
#include <TestSupport/Fixtures/StreamFactory.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Composition/Recognition/Detail/InnerProtocolDispatch.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/MockTransport.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

#include <TestSupport/Fixtures/RecognitionWire.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    namespace Composition = Prism::Composition::Recognition;

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

    auto MakeClientHello(std::string_view ServerName, std::string_view Alpn)
        -> std::vector<std::uint8_t>
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

    auto ConsumeTlsRecord(Prism::SharedTransmission Inbound)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        std::array<std::byte, 5> Header{};
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "native";
        const auto HeaderRead = co_await Inbound->ReadExact(Header);
        if (HeaderRead.Bytes != Header.size() || HeaderRead.Failure.Failed())
        {
            Result.Code = HeaderRead.Failure.Failed()
                ? HeaderRead.Failure.Code : Prism::Fault::Code::TlsHsfail;
            if (HeaderRead.Failure.Native)
                Result.NativeError = HeaderRead.Failure.Native;
            co_return Result;
        }
        const auto Length = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[3])) << 8) |
                            static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[4]));
        std::vector<std::byte> Body(Length);
        const auto BodyRead = co_await Inbound->ReadExact(Body);
        if (BodyRead.Bytes != Body.size() || BodyRead.Failure.Failed())
        {
            Result.Code = BodyRead.Failure.Failed()
                ? BodyRead.Failure.Code : Prism::Fault::Code::TlsHsfail;
            if (BodyRead.Failure.Native)
                Result.NativeError = BodyRead.Failure.Native;
            co_return Result;
        }
        Result.Transport = std::move(Inbound);
        co_return Result;
    }

    auto RunLayeredCarrier(const bool CarrierSucceeds,
                           const std::shared_ptr<std::size_t> &CarrierCalls,
                           Prism::SharedTransmission Inbound)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        ++*CarrierCalls;
        if (!CarrierSucceeds)
        {
            Core::CarrierAcceptResult Result;
            Result.Code = Prism::Fault::Code::TlsHsfail;
            Result.Metadata.Carrier = "native";
            co_return Result;
        }
        co_return co_await ConsumeTlsRecord(std::move(Inbound));
    }

    struct LayeredRun
    {
        Core::RecognizeResult Result;
        Prism::Fault::Code AcceptError{Prism::Fault::Code::ProtocolError};
        std::size_t CarrierCalls{0};
        std::size_t InnerCalls{0};
    };

    struct LayeredReadObservation final
    {
        bool InspectedPrefix{false};
        std::size_t ReadBytes{0};
        std::byte ReadByte{};
        Prism::Fault::Failure ReadFailure{};
        std::size_t StickyReadBytes{0};
        Prism::Fault::Failure StickyReadFailure{};
        bool AdmissionSucceeded{false};
        bool CloseSucceeded{false};
        bool DrainSucceeded{false};
        bool RejectedTransportCancelled{false};
        bool RejectedTransportClosed{false};
        bool RejectedActivityRetired{false};
        bool RejectedDrainSucceeded{false};
        Prism::Fault::Failure AcceptFailure{};
    };

    auto MakeCombinedReadTransport(Net::any_io_executor Executor)
        -> std::shared_ptr<Prism::PrismMockTransport>
    {
        auto Transport = std::make_shared<Prism::PrismMockTransport>(std::move(Executor));
        Transport->InjectRead({0xA5U});
        Transport->ReadErrorBytes = 1U;
        Transport->SetReadError(std::make_error_code(std::errc::connection_reset));
        Transport->EofOnDrain = true;
        return Transport;
    }

    auto MakeInnerBinding(
        const std::shared_ptr<LayeredReadObservation> &Observation,
        const bool AcceptPrefix)
        -> std::shared_ptr<Composition::CandidateInnerBinding>
    {
        auto Binding = std::make_shared<Composition::CandidateInnerBinding>();
        Binding->Spec.Id = 1U;
        Binding->Spec.Name = "terminal-read";
        Binding->Spec.Protocol = Prism::Contract::ProtocolType::Http;
        Binding->Spec.Priority = 1U;
        Binding->Spec.Inspect = [Observation, AcceptPrefix](const Core::ProbeSnapshot &Snapshot)
        {
            if (Snapshot.Empty())
            {
                return Core::MatchState::NeedMore;
            }
            Observation->InspectedPrefix = Snapshot.Data().front() == std::byte{0xA5};
            return AcceptPrefix ? Core::MatchState::Structural : Core::MatchState::NeedMore;
        };
        return Binding;
    }

    auto ObserveReplayedTerminal(
        const std::shared_ptr<LayeredReadObservation> &Observation,
        Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        std::array<std::byte, 2> Buffer{};
        const auto Read = co_await Input.Inbound->ReadSome(Buffer);
        Observation->ReadBytes = Read.Bytes;
        Observation->ReadByte = Buffer.front();
        Observation->ReadFailure = Read.Failure;
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
    }

    auto AcceptTerminalDataPlane(Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Prism::Contract::ProtocolType::Http;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
        co_return Plane;
    }

    struct LayeredAdmissionScenario final
    {
        std::shared_ptr<Prism::Contract::StreamFactory> Factory;
        std::shared_ptr<Prism::PrismMockTransport> Transport;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        std::shared_ptr<LayeredReadObservation> Observation;
    };

    auto RunRejectedAdmissionTerminalScenario(LayeredAdmissionScenario Request)
        -> Net::awaitable<void>
    {
        const auto Result = co_await Request.Factory->Accept(Prism::Contract::StreamAcceptInput{
            Request.Transport, {}, Request.Bytes});
        Request.Observation->AdmissionSucceeded = Result.has_value();
        if (!Result)
        {
            Request.Observation->AcceptFailure = Result.error();
        }
        Request.Observation->RejectedTransportCancelled = Request.Transport->IsCancelled();
        Request.Observation->RejectedTransportClosed = Request.Transport->IsClosed();
        const auto Activity = Request.Transport->Activity();
        if (Activity)
        {
            const auto Drain = co_await Activity->Drain();
            Request.Observation->RejectedDrainSucceeded = Drain.has_value();
            Request.Observation->RejectedActivityRetired = Activity->IsRetired();
        }
    }

    auto RunSuccessfulAdmissionTerminalScenario(LayeredAdmissionScenario Request)
        -> Net::awaitable<void>
    {
        auto Result = co_await Request.Factory->Accept(Prism::Contract::StreamAcceptInput{
            Request.Transport, {}, Request.Bytes});
        Request.Observation->AdmissionSucceeded = Result.has_value();
        if (!Result)
        {
            Request.Observation->AcceptFailure = Result.error();
            co_return;
        }
        const auto *Stream = Result->Stream();
        if (!Stream)
        {
            co_return;
        }
        std::array<std::byte, 2> Buffer{};
        const auto First = co_await Stream->Transport->ReadSome(Buffer);
        Request.Observation->ReadBytes = First.Bytes;
        Request.Observation->ReadByte = Buffer.front();
        Request.Observation->ReadFailure = First.Failure;
        const auto Second = co_await Stream->Transport->ReadSome(Buffer);
        Request.Observation->StickyReadBytes = Second.Bytes;
        Request.Observation->StickyReadFailure = Second.Failure;
        const auto Close = Stream->Transport->Close();
        Request.Observation->CloseSucceeded = Close.has_value();
        const auto Drain = co_await Stream->Transport->Activity()->Drain();
        Request.Observation->DrainSucceeded = Drain.has_value();
    }

    using LayeredResolver = std::function<std::shared_ptr<Prism::Contract::StreamFactory>(Core::CandidateId)>;

    struct LayeredScenarioRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Writer;
        std::shared_ptr<Prism::MemoryStream> Reader;
        Core::SharedProfile Profile;
        LayeredResolver Resolver;
        std::vector<std::byte> Record;
        LayeredRun &Output;
    };

    auto RunLayeredScenario(LayeredScenarioRequest Request) -> Net::awaitable<void>
    {
        std::size_t Offset = 0;
        while (Offset < Request.Record.size())
        {
            const auto Remaining = Request.Record.size() - Offset;
            const auto Written = co_await Request.Writer->WriteSome(
                std::span<const std::byte>(Request.Record.data() + Offset, Remaining));
            if (Written.Failure.Failed() || Written.Bytes == 0 ||
                Written.Bytes > Remaining)
            {
                co_return;
            }
            Offset += Written.Bytes;
        }
        const auto Shutdown = co_await Request.Writer->WriteShutdown();
        if (!Shutdown)
        {
            co_return;
        }
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Core::Pipeline Pipeline(Request.Profile, std::move(Bytes));
        Request.Output.Result = co_await Pipeline.Recognize(Request.Reader);
        if (Request.Output.Result.success)
        {
            auto Accept = Request.Resolver(Request.Output.Result.Candidate);
            if (Accept)
            {
                auto Inbound = std::move(Request.Output.Result.transport);
                auto Accepted = co_await Accept->Accept(Prism::Contract::StreamAcceptInput{
                    std::move(Inbound), {}, Bytes});
                Request.Output.AcceptError = Accepted ? Prism::Fault::Code::Success
                    : Accepted.error().Code;
                if (Accepted)
                {
                    const auto *Stream = Accepted->Stream();
                    if (Stream)
                    {
                        Request.Output.Result.transport = Stream->Transport;
                    }
                    else
                    {
                        Request.Output.AcceptError = Prism::Fault::Code::ProtocolError;
                    }
                }
            }
        }
        if (Request.Output.Result.transport)
        {
            (void)Request.Output.Result.transport->Close();
            Request.Output.Result.transport.reset();
        }
        (void)Request.Writer->Close();
    }

    auto RunNaturalCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto MakeHttpCandidate(Composition::CandidateOptions Options)
        -> Composition::CandidateBinding
    {
        auto Factory = std::make_shared<Prism::Http11::Binding>(
            Prism::Http11::PreparedBinding{
                .Instance = "layered-candidate-test",
                .Executor = Net::system_executor(),
                .RequireAuth = false});
        return Composition::CandidateFactory::MakeHttp(std::move(Options), std::move(Factory));
    }

    auto RunLayered(bool CarrierSucceeds) -> LayeredRun
    {
        Net::io_context Io;
        auto CarrierCalls = std::make_shared<std::size_t>(0);
        auto InnerCalls = std::make_shared<std::size_t>(0);
        auto Inner = MakeHttpCandidate(
            Prism::Composition::Recognition::CandidateOptions{8});
        Inner.Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [InnerCalls](Prism::Contract::StreamAcceptInput Input)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                ++*InnerCalls;
                Prism::Contract::ProtocolDataPlane Plane;
                Plane.Protocol = Prism::Contract::ProtocolType::Http;
                Plane.Root = Prism::Contract::StreamDataPlane{
                    std::move(Input.Inbound), {}};
                co_return Plane;
            });

        Composition::TlsCandidateOptions Options;
        Options.Id = 7;
        Options.Name = "native-http";
        Options.Scheme = "native";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        Options.Carrier = Composition::TlsCarrier::Native;
        auto Carrier = [CarrierSucceeds, CarrierCalls](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        { return RunLayeredCarrier(CarrierSucceeds, CarrierCalls, std::move(Input.Inbound)); };
        auto Layered = Composition::LayeredCandidateFactory::Make(
            std::move(Options), std::move(Carrier), std::move(Inner));
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Configured;
        BuilderOptions.ConfiguredCandidate = Layered.Spec.Id;
        auto Built = Composition::ProfileBuilder::Build(std::move(Layered), std::move(BuilderOptions));
        if (!Built)
        {
            return {};
        }

        auto [WriterValue, ReaderValue] = Prism::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Prism::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Prism::MemoryStream>(std::move(ReaderValue));
        auto Record = MakeTlsRecord(MakeClientHello("edge.example", "h2"));
        auto Http = Prism::Testing::RecognitionWire::MakeHttp("layered");
        Record.insert(Record.end(), Http.begin(), Http.end());
        LayeredRun Output;
        const auto Scenario = LayeredScenarioRequest{
            Writer, Reader, Built->Profile, Built->Resolver, std::move(Record), Output};
        RunNaturalCoro(Io, RunLayeredScenario(Scenario));
        Output.CarrierCalls = *CarrierCalls;
        Output.InnerCalls = *InnerCalls;
        return Output;
    }

    TEST(LayeredCandidate, CarrierThenInnerHandler)
    {
        const auto Run = RunLayered(true);
        EXPECT_TRUE(Run.Result.success);
        EXPECT_EQ(Run.Result.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(Run.Result.Candidate, 7U);
        EXPECT_EQ(Run.Result.detected, Prism::Contract::ProtocolType::Http);
        EXPECT_EQ(Run.CarrierCalls, 1U);
        EXPECT_EQ(Run.InnerCalls, 1U);
        EXPECT_EQ(Run.AcceptError, Prism::Fault::Code::Success);
    }

    TEST(LayeredCandidate, CarrierFailureDoesNotReachInnerHandler)
    {
        const auto Run = RunLayered(false);
        EXPECT_FALSE(Run.Result.success);
        EXPECT_EQ(Run.Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Run.CarrierCalls, 1U);
        EXPECT_EQ(Run.InnerCalls, 0U);
        EXPECT_EQ(Run.AcceptError, Prism::Fault::Code::ProtocolError);
    }

    TEST(LayeredCandidate, ReadFailureAfterPrefixStopsWithoutAnotherRead)
    {
        Net::io_context Io;
        auto Transport = MakeCombinedReadTransport(Io.get_executor());
        auto Observation = std::make_shared<LayeredReadObservation>();
        auto Binding = MakeInnerBinding(Observation, false);
        auto Factory = Composition::MakeInnerProtocolDispatch(
            std::vector<std::shared_ptr<const Composition::CandidateInnerBinding>>{Binding});
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U, 2U});

        Prism::Testing::RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            const auto Result = co_await Factory->Accept(Prism::Contract::StreamAcceptInput{
                Transport, {}, Bytes});
            if (!Result)
            {
                Observation->AcceptFailure = Result.error();
            }
        }());

        const auto Native = std::make_error_code(std::errc::connection_reset);
        EXPECT_TRUE(Observation->InspectedPrefix);
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_EQ(Observation->AcceptFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Observation->AcceptFailure.Native, Native);
    }

    TEST(LayeredCandidate, AcceptedPrefixReplaysItsTerminalWithTheLastBytes)
    {
        Net::io_context Io;
        auto Transport = MakeCombinedReadTransport(Io.get_executor());
        auto Observation = std::make_shared<LayeredReadObservation>();
        auto Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [Observation](Prism::Contract::StreamAcceptInput Input)
            { return ObserveReplayedTerminal(Observation, std::move(Input)); });
        auto Binding = MakeInnerBinding(Observation, true);
        Binding->Accept = std::move(Accept);
        auto Factory = Composition::MakeInnerProtocolDispatch(
            std::vector<std::shared_ptr<const Composition::CandidateInnerBinding>>{Binding});
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U, 2U});

        Prism::Testing::RunCoro(Io, RunRejectedAdmissionTerminalScenario(
            LayeredAdmissionScenario{Factory, Transport, Bytes, Observation}));

        const auto Native = std::make_error_code(std::errc::connection_reset);
        EXPECT_FALSE(Observation->AdmissionSucceeded);
        EXPECT_EQ(Observation->AcceptFailure.Code, Prism::Fault::Code::ProtocolError);
        EXPECT_TRUE(Observation->RejectedTransportCancelled);
        EXPECT_TRUE(Observation->RejectedTransportClosed);
        EXPECT_TRUE(Observation->RejectedDrainSucceeded);
        EXPECT_TRUE(Observation->RejectedActivityRetired);
        EXPECT_TRUE(Observation->InspectedPrefix);
        EXPECT_EQ(Observation->ReadBytes, 1U);
        EXPECT_EQ(Observation->ReadByte, std::byte{0xA5});
        EXPECT_EQ(Observation->ReadFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Observation->ReadFailure.Native, Native);
    }

    TEST(LayeredCandidate, SuccessfulAdmissionKeepsTerminalStickyAfterPrefix)
    {
        Net::io_context Io;
        auto Transport = MakeCombinedReadTransport(Io.get_executor());
        auto Observation = std::make_shared<LayeredReadObservation>();
        auto Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [](Prism::Contract::StreamAcceptInput Input)
            { return AcceptTerminalDataPlane(std::move(Input)); });
        auto Binding = MakeInnerBinding(Observation, true);
        Binding->Accept = std::move(Accept);
        auto Factory = Composition::MakeInnerProtocolDispatch(
            std::vector<std::shared_ptr<const Composition::CandidateInnerBinding>>{Binding});
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U, 2U});

        Prism::Testing::RunCoro(Io, RunSuccessfulAdmissionTerminalScenario(
            LayeredAdmissionScenario{Factory, Transport, Bytes, Observation}));

        const auto Native = std::make_error_code(std::errc::connection_reset);
        EXPECT_TRUE(Observation->InspectedPrefix);
        EXPECT_TRUE(Observation->AdmissionSucceeded);
        EXPECT_EQ(Observation->ReadBytes, 1U);
        EXPECT_EQ(Observation->ReadByte, std::byte{0xA5});
        EXPECT_EQ(Observation->ReadFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Observation->ReadFailure.Native, Native);
        EXPECT_EQ(Observation->StickyReadBytes, 0U);
        EXPECT_EQ(Observation->StickyReadFailure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Observation->StickyReadFailure.Native, Native);
        EXPECT_EQ(Transport->ReadsDone, 1U);
        EXPECT_TRUE(Observation->CloseSucceeded);
        EXPECT_TRUE(Observation->DrainSucceeded);
    }

} // namespace


