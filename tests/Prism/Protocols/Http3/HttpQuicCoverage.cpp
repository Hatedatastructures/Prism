/**
 * @file HttpQuicCoverage.cpp
 * @brief Generic HTTP/3/QPACK and QUIC adapter coverage.
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Http3/Auth.hpp>
#include <Prism/Protocols/Http3/Qpack.hpp>
#include <Prism/Protocols/Http3/Server.hpp>

namespace
{

    namespace Qpack = Prism::Http3::Qpack;

    TEST(Http3Qpack, EncodeDecodeRoundtrip)
    {
        std::array<std::uint8_t, 512> Block{};
        auto Offset = Qpack::EncodePrefix(Block);
        Offset += Qpack::EncodeLiteral(
            ":method", "GET", std::span(Block).subspan(Offset));
        Offset += Qpack::EncodeLiteral(
            ":path", "/generic", std::span(Block).subspan(Offset));
        Offset += Qpack::EncodeLiteral(
            "x-h3-test", "value", std::span(Block).subspan(Offset));

        const auto Fields = Qpack::DecodeHeaderBlock(
            std::span<const std::uint8_t>(Block.data(), Offset),
            Prism::Memory::CurrentResource());
        ASSERT_EQ(Fields.size(), 3U);
        EXPECT_EQ(Fields[0].Name, ":method");
        EXPECT_EQ(Fields[0].value, "GET");
        EXPECT_EQ(Fields[1].Name, ":path");
        EXPECT_EQ(Fields[1].value, "/generic");
        EXPECT_EQ(Fields[2].Name, "x-h3-test");
        EXPECT_EQ(Fields[2].value, "value");
    }

    TEST(Http3Qpack, RejectsMalformedAndDynamicBlocks)
    {
        const auto Resource = Prism::Memory::CurrentResource();
        EXPECT_TRUE(Qpack::DecodeHeaderBlock({}, Resource).empty());
        const std::array<std::uint8_t, 2> RequiredCount{0x01, 0x00};
        EXPECT_TRUE(Qpack::DecodeHeaderBlock(RequiredCount, Resource).empty());
        const std::array<std::uint8_t, 2> DeltaBase{0x00, 0x02};
        EXPECT_TRUE(Qpack::DecodeHeaderBlock(DeltaBase, Resource).empty());
        const std::array<std::uint8_t, 4> DynamicName{0x00, 0x00, 0x40, 0x00};
        EXPECT_TRUE(Qpack::DecodeHeaderBlock(DynamicName, Resource).empty());
    }

    TEST(Http3Contracts, HeaderBlocksAndEventsOwnTheirPayloads)
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({":method", "GET"});
        Headers.Fields.push_back({":path", "/generic"});

        Prism::Http3::RequestEvent Request{
            0, Prism::Http3::RequestHead{std::move(Headers), true}};
        Prism::Http3::ServerEvent Event{std::move(Request)};
        ASSERT_TRUE(std::holds_alternative<Prism::Http3::RequestEvent>(Event));
        const auto &RequestValue = std::get<Prism::Http3::RequestEvent>(Event);
        EXPECT_EQ(RequestValue.Head.Headers.Owner, Owner);
        ASSERT_EQ(RequestValue.Head.Headers.Fields.size(), 2U);
        EXPECT_EQ(RequestValue.Head.Headers.Fields[0].value, "GET");

        Prism::Http3::DataEvent Data{
            0, std::vector<std::byte>{std::byte{0x41}, std::byte{0x42}}, true};
        Prism::Http3::ServerEvent DataEvent{std::move(Data)};
        const auto &Payload = std::get<Prism::Http3::DataEvent>(DataEvent);
        EXPECT_EQ(Payload.Data.size(), 2U);
        EXPECT_TRUE(Payload.Fin);

        auto ResponseOwner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock ResponseHeaders(ResponseOwner);
        ResponseHeaders.Fields.push_back({"content-type", "application/octet-stream"});
        Prism::Http3::ResponseHead Response{7, 418, std::move(ResponseHeaders), false};
        EXPECT_EQ(Response.Status, 418);
        EXPECT_FALSE(Response.Fin);
    }

    TEST(Http3Server, InitFailureAndGenericResponseContract)
    {
        auto Server = Prism::Http3::MakeServer(
            Prism::Http3::ServerOptions{Prism::Memory::CurrentResource()});
        EXPECT_EQ(
            Server->Feed(0, std::span<const std::byte>{}, false),
            Prism::Fault::Code::ProtocolError);
        EXPECT_FALSE(Server->Init([] { return std::int64_t{-1}; }));

        std::int64_t NextStream = 3;
        ASSERT_TRUE(Server->Init([&NextStream]
        {
            const auto Result = NextStream;
            NextStream += 4;
            return Result;
        }));
        EXPECT_TRUE(Server->IsOpen());
        EXPECT_TRUE(Server->Init([] { return std::int64_t{-1}; }));
        Server->Close();
        EXPECT_FALSE(Server->IsOpen());
    }

    TEST(Http3Server, EmitsGenericRequestEventFromNghttp3)
    {
        auto Server = Prism::Http3::MakeServer(
            Prism::Http3::ServerOptions{Prism::Memory::CurrentResource()});
        std::int64_t NextStream = 3;
        ASSERT_TRUE(Server->Init([&NextStream]
        {
            const auto Result = NextStream;
            NextStream += 4;
            return Result;
        }));

        // Peer unidirectional streams carry their stream type before the
        // control/QPACK payload consumed by nghttp3.
        const std::array<std::byte, 3> Settings{
            std::byte{0x00}, std::byte{0x04}, std::byte{0x00}};
        ASSERT_EQ(Server->Feed(2, Settings, false), Prism::Fault::Code::Success);
        const std::array<std::byte, 2> Encoder{std::byte{0x02}, std::byte{0x20}};
        ASSERT_EQ(Server->Feed(6, Encoder, false), Prism::Fault::Code::Success);

        std::array<std::uint8_t, 512> Block{};
        auto Offset = Qpack::EncodePrefix(Block);
        Offset += Qpack::EncodeLiteral(
            ":method", "GET", std::span(Block).subspan(Offset));
        Offset += Qpack::EncodeLiteral(
            ":scheme", "https", std::span(Block).subspan(Offset));
        Offset += Qpack::EncodeLiteral(
            ":authority", "generic", std::span(Block).subspan(Offset));
        Offset += Qpack::EncodeLiteral(
            ":path", "/generic", std::span(Block).subspan(Offset));

        std::array<std::byte, 600> Frame{};
        Frame[0] = std::byte{0x01};
        Frame[1] = static_cast<std::byte>(Offset);
        std::memcpy(Frame.data() + 2, Block.data(), Offset);
        ASSERT_EQ(Server->Feed(
                      0, std::span<const std::byte>(Frame.data(), Offset + 2), true),
                  Prism::Fault::Code::Success);
        auto Event = Server->TakeEvent();
        ASSERT_TRUE(Event.has_value());
        ASSERT_TRUE(std::holds_alternative<Prism::Http3::RequestEvent>(*Event));
        const auto &Request = std::get<Prism::Http3::RequestEvent>(*Event);
        EXPECT_EQ(Request.StreamId, 0);
        EXPECT_TRUE(Request.Head.Fin);
        ASSERT_EQ(Request.Head.Headers.Fields.size(), 4U);
        EXPECT_EQ(Request.Head.Headers.Fields[3].value, "/generic");
        Server->Close();
    }

} // namespace
