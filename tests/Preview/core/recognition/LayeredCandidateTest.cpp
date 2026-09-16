/**
 * @file LayeredCandidateTest.cpp
 * @brief TLS carrier 到内层协议 handler 的分层候选回归
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Runtime/Recognition/Recognition.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

#include "RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

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

    auto ConsumeTlsRecord(Preview::SharedTransmission Inbound)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        std::array<std::byte, 5> Header{};
        std::error_code Error;
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "native";
        if (co_await Inbound->AsyncRead(Header, Error) != Header.size() || Error)
        {
            Result.Code = Preview::Fault::Code::TlsHsfail;
            co_return Result;
        }
        const auto Length = (static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[3])) << 8) |
                            static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[4]));
        std::vector<std::byte> Body(Length);
        if (co_await Inbound->AsyncRead(Body, Error) != Body.size() || Error)
        {
            Result.Code = Preview::Fault::Code::TlsHsfail;
            co_return Result;
        }
        Result.Transport = std::move(Inbound);
        co_return Result;
    }

    struct LayeredRun
    {
        Core::RecognizeResult Result;
        Preview::Fault::Code AcceptError{Preview::Fault::Code::ProtocolError};
        std::size_t CarrierCalls{0};
        std::size_t InnerCalls{0};
    };

    auto RunLayered(bool CarrierSucceeds) -> LayeredRun
    {
        Net::io_context Io;
        auto CarrierCalls = std::make_shared<std::size_t>(0);
        auto InnerCalls = std::make_shared<std::size_t>(0);
        auto Inner = Composition::CandidateFactory::MakeHttp(8);
        auto InnerAccept = std::move(Inner.Accept);
        Inner.Accept = [InnerAccept = std::move(InnerAccept), InnerCalls](
                            Preview::SharedTransmission &Inbound,
                            Preview::Middleware::Context &Context)
            -> Net::awaitable<Preview::Fault::Code>
        {
            ++*InnerCalls;
            co_return co_await InnerAccept(Inbound, Context);
        };

        Composition::TlsCandidateOptions Options;
        Options.Id = 7;
        Options.Name = "native-http";
        Options.Scheme = "native";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        Options.Carrier = Composition::TlsCarrier::Native;
        auto Carrier = [CarrierSucceeds, CarrierCalls](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            ++*CarrierCalls;
            if (!CarrierSucceeds)
            {
                Core::CarrierAcceptResult Result;
                Result.Code = Preview::Fault::Code::TlsHsfail;
                Result.Metadata.Carrier = "native";
                co_return Result;
            }
            co_return co_await ConsumeTlsRecord(std::move(Inbound));
        };
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

        auto [WriterValue, ReaderValue] = Preview::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Preview::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Preview::MemoryStream>(std::move(ReaderValue));
        auto Record = MakeTlsRecord(MakeClientHello("edge.example", "h2"));
        auto Http = Preview::Testing::RecognitionWire::MakeHttp("layered");
        Record.insert(Record.end(), Http.begin(), Http.end());
        LayeredRun Output;
        Preview::Testing::RunCoro(
            Io,
            [Writer, Reader, Profile = Built->Profile, Resolver = Built->Resolver,
             Record = std::move(Record), &Output, CarrierCalls, InnerCalls]() mutable
                -> Net::awaitable<void>
            {
                std::error_code Error;
                const auto Written = co_await Writer->async_write_some(
                    std::span<const std::byte>(Record), Error);
                if (Error || Written != Record.size())
                {
                    co_return;
                }
                Writer->Shutdown();
                Core::Pipeline Pipeline(Profile);
                Output.Result = co_await Pipeline.Recognize(Reader);
                if (Output.Result.success)
                {
                    auto Accept = Resolver(Output.Result.Candidate);
                    if (Accept)
                    {
                        auto Inbound = std::move(Output.Result.transport);
                        Preview::Middleware::Context Context;
                        Output.AcceptError = co_await Accept(Inbound, Context);
                        Output.Result.transport = std::move(Inbound);
                    }
                }
                if (Output.Result.transport)
                {
                    Output.Result.transport->Close();
                    Output.Result.transport.reset();
                }
                Writer->Close();
                co_return;
            });
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
        EXPECT_EQ(Run.Result.detected, Core::ProtocolType::Http);
        EXPECT_EQ(Run.CarrierCalls, 1U);
        EXPECT_EQ(Run.InnerCalls, 1U);
        EXPECT_EQ(Run.AcceptError, Preview::Fault::Code::Success);
    }

    TEST(LayeredCandidate, CarrierFailureDoesNotReachInnerHandler)
    {
        const auto Run = RunLayered(false);
        EXPECT_FALSE(Run.Result.success);
        EXPECT_EQ(Run.Result.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Run.CarrierCalls, 1U);
        EXPECT_EQ(Run.InnerCalls, 0U);
        EXPECT_EQ(Run.AcceptError, Preview::Fault::Code::ProtocolError);
    }

} // namespace
