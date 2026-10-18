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
#include <functional>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Composition/Recognition/ProfileBuilder.hpp>
#include <Prism/Runtime/Recognition/Recognition.hpp>
#include <Prism/Transport/MemoryStream.hpp>
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
        std::error_code Error;
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "native";
        if (co_await Inbound->AsyncRead(Header, Error) != Header.size() || Error)
        {
            Result.Code = Prism::Fault::Code::TlsHsfail;
            co_return Result;
        }
        const auto Length = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[3])) << 8) |
                            static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[4]));
        std::vector<std::byte> Body(Length);
        if (co_await Inbound->AsyncRead(Body, Error) != Body.size() || Error)
        {
            Result.Code = Prism::Fault::Code::TlsHsfail;
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
        Request.Writer->Shutdown();
        Core::Pipeline Pipeline(Request.Profile);
        Request.Output.Result = co_await Pipeline.Recognize(Request.Reader);
        if (Request.Output.Result.success)
        {
            auto Accept = Request.Resolver(Request.Output.Result.Candidate);
            if (Accept)
            {
                auto Inbound = std::move(Request.Output.Result.transport);
                Prism::Middleware::Context Context;
                auto Accepted = co_await Accept->Accept(Inbound, {});
                Request.Output.AcceptError = Accepted ? Prism::Fault::Code::Success
                    : Accepted.error().Code;
                if (Accepted)
                {
                    Context.SetDataPlane(std::move(*Accepted));
                    Inbound = Context.Inbound();
                }
                Request.Output.Result.transport = std::move(Inbound);
            }
        }
        if (Request.Output.Result.transport)
        {
            Request.Output.Result.transport->Close();
            Request.Output.Result.transport.reset();
        }
        Request.Writer->Close();
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

    auto RunLayered(bool CarrierSucceeds) -> LayeredRun
    {
        Net::io_context Io;
        auto CarrierCalls = std::make_shared<std::size_t>(0);
        auto InnerCalls = std::make_shared<std::size_t>(0);
        auto Inner = Composition::CandidateFactory::MakeHttp(Prism::Composition::Recognition::CandidateOptions{8});
        auto InnerAccept = std::move(Inner.Accept);
        Inner.Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [InnerAccept = std::move(InnerAccept), InnerCalls](
                Prism::SharedTransmission Inbound, Prism::Contract::RequestMetadata Metadata)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                ++*InnerCalls;
                co_return co_await InnerAccept->Accept(std::move(Inbound), std::move(Metadata));
            });

        Composition::TlsCandidateOptions Options;
        Options.Id = 7;
        Options.Name = "native-http";
        Options.Scheme = "native";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        Options.Carrier = Composition::TlsCarrier::Native;
        auto Carrier = [CarrierSucceeds, CarrierCalls](Prism::SharedTransmission Inbound)
            -> Net::awaitable<Core::CarrierAcceptResult>
        { return RunLayeredCarrier(CarrierSucceeds, CarrierCalls, std::move(Inbound)); };
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

} // namespace


