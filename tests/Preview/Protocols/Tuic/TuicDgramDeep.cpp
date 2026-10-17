/**
 * @file TuicDgramDeep.cpp
 * @brief Tuic UDP 数据包连接（Dgram 装饰器）深度测试
 * @details 覆盖 Dgram 全部方法：Executor / TransportType / 透传读写 /
 *          Close / Cancel / NextLayer / Release / Stream，以及
 *          AsyncSendTo / AsyncReceiveFrom 的成功与错误分支
 *          （EOF、坏帧、地址类型、底层 IO 错误）。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Unreliable.hpp>
#include <Preview/Protocols/Tuic/Dgram.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Tuic = Preview::Tuic;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::Transmission;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        // 同一 io_context 可能被多次驱动，restart() 重置 stopped 标志
        IoContext.restart();
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief 构造 ipv4 目标地址
     */
    auto MakeDestination() -> Tuic::Address
    {
        Tuic::Address Destination{};
        Destination.Type = Tuic::AddressType::Ipv4;
        Destination.Host = "93.184.216.34";
        Destination.Port = 443;
        return Destination;
    }

    auto WriteAllBytes(
        Transmission &Stream,
        std::span<const std::uint8_t> Buffer) -> Net::awaitable<Preview::Fault::Failure>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Remaining = Buffer.size() - Offset;
            const auto Part = co_await Stream.WriteSome(AsBytes(Buffer.subspan(Offset)));
            if (Part.Bytes > Remaining)
            {
                co_return Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument};
            }
            Offset += Part.Bytes;
            if (Part.Failure.Failed()) co_return Part.Failure;
            if (Part.Bytes == 0U)
            {
                co_return Preview::Fault::Failure{Preview::Fault::Code::WouldBlock};
            }
        }
        co_return Preview::Fault::Failure{};
    }

    TEST(TuicWireContract, UsesV5CommandAndAddressValues)
    {
        EXPECT_EQ(Tuic::ProtocolVersion, 0x05);
        EXPECT_EQ(Tuic::CmdAuthenticate, 0x00);
        EXPECT_EQ(Tuic::CmdConnect, 0x01);
        EXPECT_EQ(Tuic::CmdPacket, 0x02);
        EXPECT_EQ(Tuic::CmdDissociate, 0x03);
        EXPECT_EQ(Tuic::CmdHeartbeat, 0x04);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::Domain), 0x00);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::Ipv4), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::Ipv6), 0x02);
        EXPECT_EQ(static_cast<std::uint8_t>(Tuic::AddressType::None), 0xFF);
    }

    TEST(TuicWireContract, AuthenticateFrameCarriesExactCredentials)
    {
        const std::array<std::uint8_t, Tuic::UuidLen> Uuid{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
        const std::array<std::uint8_t, Tuic::TokenLen> Token{
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
        const auto Wire = Tuic::BuildAuthenticate(Uuid, Token);
        ASSERT_EQ(Wire.size(), Tuic::AuthenticateFrameLen);
        EXPECT_EQ(Wire[0], 0x05);
        EXPECT_EQ(Wire[1], 0x00);
        EXPECT_TRUE(std::equal(Uuid.begin(), Uuid.end(), Wire.begin() + 2));
        EXPECT_TRUE(std::equal(Token.begin(), Token.end(), Wire.begin() + 2 + Tuic::UuidLen));

        Tuic::AuthenticateFrame Parsed{};
        std::size_t Consumed = 0;
        EXPECT_EQ(Tuic::ParseAuthenticate(Wire, Parsed, Consumed), Error::None);
        EXPECT_EQ(Consumed, Tuic::AuthenticateFrameLen);
        EXPECT_EQ(Parsed.Uuid, Uuid);
        EXPECT_EQ(Parsed.Token, Token);
    }

    TEST(TuicDgramProvider, MemoryProviderRoundtrip)
    {
        Net::io_context ioc;
        auto [ClientProvider, ServerProvider] =
            Preview::Testing::MemoryDatagramProvider::MakePair(ioc.get_executor());
        auto Client = Tuic::ConnectPacket(ClientProvider, Tuic::ClientConfig{});
        auto Server = Tuic::AcceptPacket(ServerProvider, Tuic::ServerConfig{});
        ASSERT_TRUE(Client);
        ASSERT_TRUE(Server);

        const auto Target = MakeDestination();
        const auto Payload = AsU8Span(std::string_view{"tuic-provider"});
        Tuic::Address ReceivedTarget;
        std::vector<std::uint8_t> ReceivedPayload;
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     EXPECT_EQ(co_await Client.value()->AsyncSendTo(Target, Payload), Error::None);
                     EXPECT_EQ(co_await Server.value()->AsyncReceiveFrom(ReceivedTarget, ReceivedPayload),
                               Error::None);
                     EXPECT_EQ(co_await Server.value()->AsyncSendTo(ReceivedTarget, ReceivedPayload),
                               Error::None);
                     (void)Client.value()->Close();
                     (void)Server.value()->Close();
                 });

        EXPECT_EQ(ReceivedTarget.Host, Target.Host);
        EXPECT_EQ(ReceivedTarget.Port, Target.Port);
        EXPECT_EQ(std::string(ReceivedPayload.begin(), ReceivedPayload.end()), "tuic-provider");
    }

    TEST(TuicDgramProvider, ShortWriteAndCloseAreErrors)
    {
        Net::io_context ioc;
        auto [ClientProvider, ServerProvider] =
            Preview::Testing::MemoryDatagramProvider::MakePair(ioc.get_executor());
        auto Client = Tuic::ConnectPacket(ClientProvider, Tuic::ClientConfig{});
        auto Server = Tuic::AcceptPacket(ServerProvider, Tuic::ServerConfig{});
        ASSERT_TRUE(Client);
        ASSERT_TRUE(Server);
        const auto Target = MakeDestination();

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     ClientProvider->MaxSend = 2;
                     EXPECT_EQ(co_await Client.value()->AsyncSendTo(Target, AsU8Span(std::string_view{"short"})),
                               Error::IoError);
                     ClientProvider->MaxSend = 0;
                     const auto CloseCommand = Server.value()->Close();
                     EXPECT_TRUE(CloseCommand);
                     const auto CloseDrain = co_await Server.value()->Activity()->Drain();
                     EXPECT_TRUE(CloseDrain);
                     EXPECT_EQ(co_await Client.value()->AsyncSendTo(Target, AsU8Span(std::string_view{"closed"})),
                               Error::IoError);
                     (void)Client.value()->Close();
                 });
    }

    TEST(TuicDgram, RejectsOverreportedUdpRead)
    {
        Net::io_context ioc;
        auto raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        raw->TransportKind = Transmission::Type::Udp;
        raw->OverreportRead = true;
        auto Dgram = std::make_shared<Tuic::Dgram<>>(raw);

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Tuic::Address Source;
                     std::vector<std::uint8_t> Payload;
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(Source, Payload), Error::BadLength);
                 });
    }

    TEST(TuicDgram, RejectsOverreportedStreamRead)
    {
        Net::io_context ioc;
        auto raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        raw->OverreportRead = true;
        auto Dgram = std::make_shared<Tuic::Dgram<>>(raw);

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Tuic::Address Source;
                     std::vector<std::uint8_t> Payload;
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(Source, Payload), Error::UnexpectedEof);
                 });
    }

    TEST(TuicDgram, RejectsOverreportedWrite)
    {
        Net::io_context ioc;
        auto raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        raw->OverreportWrite = true;
        auto Dgram = std::make_shared<Tuic::Dgram<>>(raw);

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     EXPECT_EQ(co_await Dgram->AsyncSendTo(
                                   MakeDestination(), AsU8Span(std::string_view{"overreport"})),
                               Error::BadLength);
                 });
    }

    TEST(TuicDgram, DecoratorBasics)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        EXPECT_EQ(Dgram->TransportType(), Transmission::Type::Udp);
        (void)Dgram->Executor();
        EXPECT_NE(Dgram->NextLayer(), nullptr);
        const auto *cdgram = Dgram.get();
        EXPECT_NE(cdgram->NextLayer(), nullptr);
        EXPECT_NE(Dgram->Stream(), nullptr);
        EXPECT_EQ(Dgram->lowest_layer<MemoryStream>(), Dgram->Stream().get());

        // 透传读写（双向）
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::array<std::byte, 8> wbuf{std::byte{0x11}};
                     const auto w = co_await Dgram->WriteSome(std::span<const std::byte>(wbuf));
                     EXPECT_EQ(w.Bytes, 8u);
                     EXPECT_FALSE(w.Failure.Failed());
                     std::array<std::byte, 8> rbuf{};
                     const auto r = co_await peer->ReadSome(std::span<std::byte>(rbuf));
                     EXPECT_EQ(r.Bytes, 8u);
                     EXPECT_FALSE(r.Failure.Failed());
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x11);

                     const auto w2 = co_await peer->WriteSome(std::span<const std::byte>(wbuf));
                     EXPECT_EQ(w2.Bytes, 8u);
                     EXPECT_FALSE(w2.Failure.Failed());
                     const auto r2 = co_await Dgram->ReadSome(std::span<std::byte>(rbuf));
                     EXPECT_EQ(r2.Bytes, 8u);
                     EXPECT_FALSE(r2.Failure.Failed());
                     EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x11);
                 });

        (void)Dgram->Cancel();
        (void)Dgram->Close();
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::array<std::byte, 8> rbuf{};
                     const auto r = co_await Dgram->ReadSome(std::span<std::byte>(rbuf));
                     EXPECT_EQ(r.Bytes, 0u);
                     EXPECT_TRUE(r.Failure.Failed());
                 });
        // Release 转移底层所有权
        auto upstream = Dgram->Release();
        EXPECT_NE(upstream, nullptr);
        EXPECT_EQ(Dgram->Stream(), nullptr);
    }

    TEST(TuicDgram, SendAndReceiveRoundtrip)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 发送数据报（对端读取 wire 帧）
                     std::string payload(4096, '\0');
                     for (std::size_t Index = 0; Index < payload.size(); ++Index)
                         payload[Index] = static_cast<char>((Index * 37U) & 0xFFU);
                     const auto serr =
                         co_await Dgram->AsyncSendTo(MakeDestination(), AsU8Span(payload));
                     EXPECT_EQ(serr, Error::None);

                     // 对端用 Codec 解析帧
                     std::array<std::uint8_t, 8192> raw{};
                     const auto ReadResult = co_await peer->ReadSome(AsBytes(std::span<std::uint8_t>(raw)));
                     const auto n = ReadResult.Bytes;
                     EXPECT_FALSE(ReadResult.Failure.Failed());
                     Tuic::Message msg;
                     std::size_t consumed = 0;
                     const auto perr = Tuic::Parse(std::span<const std::uint8_t>(raw.data(), n), msg, consumed);
                     EXPECT_EQ(perr, Error::None);
                     EXPECT_EQ(consumed, n);
                     EXPECT_GT(n, Tuic::Detail::MaxDatagramFrameSize);
                     EXPECT_EQ(msg.Cmd, Tuic::CmdPacket);
                     EXPECT_EQ(msg.FragTotal, 1U);
                     EXPECT_EQ(msg.AssocId, 0u);
                      EXPECT_EQ(msg.PktId, 0u);
                     EXPECT_EQ(msg.dst.Host, "93.184.216.34");
                     EXPECT_EQ(msg.dst.Port, 443u);
                     EXPECT_EQ(msg.payload, payload);

                     // 回传一帧 packet（ipv4 地址）→ Dgram 接收
                      // 回传帧保持完整数据报边界，接收端一次解析整个 packet。
                     Tuic::Message Reply;
                     Reply.Cmd = Tuic::CmdPacket;
                     Reply.AssocId = 7;
                      Reply.PktId = 1;
                     Reply.dst = MakeDestination();
                     Reply.payload = "pong";
                    const auto wire = Tuic::Build(Reply);
                     const auto WriteError = co_await WriteAllBytes(*peer, wire);
                     EXPECT_FALSE(WriteError.Failed());

                     Tuic::Address src{};
                     std::vector<std::uint8_t> out;
                     const auto rerr = co_await Dgram->AsyncReceiveFrom(src, out);
                     EXPECT_EQ(rerr, Error::None);
                     EXPECT_EQ(src.Type, Tuic::AddressType::Ipv4);
                 });
    }

    TEST(TuicDgram, PacketCarriesSizeAndFragmentFields)
    {
        Tuic::Message Message;
        Message.Cmd = Tuic::CmdPacket;
        Message.AssocId = 0x1234;
        Message.PktId = 0x5678;
        Message.FragTotal = 2;
        Message.FragId = 0;
        Message.dst = MakeDestination();
        Message.payload = "payload";
        const auto Wire = Tuic::Build(Message);
        ASSERT_GE(Wire.size(), 10u);
        EXPECT_EQ(Wire[2], 0x12);
        EXPECT_EQ(Wire[3], 0x34);
        EXPECT_EQ(Wire[4], 0x56);
        EXPECT_EQ(Wire[5], 0x78);
        EXPECT_EQ(Wire[6], 2);
        EXPECT_EQ(Wire[7], 0);
        EXPECT_EQ(Wire[8], 0);
        EXPECT_EQ(Wire[9], 7);
        Tuic::Message Parsed;
        std::size_t Consumed = 0;
        EXPECT_EQ(Tuic::Parse(Wire, Parsed, Consumed), Error::None);
        EXPECT_EQ(Consumed, Wire.size());
        EXPECT_EQ(Parsed.AssocId, Message.AssocId);
        EXPECT_EQ(Parsed.PktId, Message.PktId);
        EXPECT_EQ(Parsed.FragTotal, Message.FragTotal);
        EXPECT_EQ(Parsed.FragId, Message.FragId);
        EXPECT_EQ(Parsed.Size, Message.payload.size());
        EXPECT_EQ(Parsed.payload, Message.payload);
    }

    TEST(TuicDgram, RawUdpDatagramKeepsFrameBoundary)
    {
        Net::io_context ioc;
        auto RawServer = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        auto RawClient = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        boost::system::error_code OpenEc;
        RawServer->NativeSocket().open(Net::ip::udp::v4(), OpenEc);
        RawServer->NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenEc);
        EXPECT_FALSE(OpenEc);
        const auto ServerEndpoint = RawServer->NativeSocket().local_endpoint();
        EXPECT_TRUE(RawClient->Connect("127.0.0.1:" + std::to_string(ServerEndpoint.port())));
        auto Server = std::make_shared<Tuic::Dgram<>>(RawServer);
        auto Client = std::make_shared<Tuic::Dgram<>>(RawClient);
        const auto Payload = std::string("tuic-udp-payload");
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto Sent = co_await Client->AsyncSendTo(MakeDestination(), AsU8Span(std::string_view(Payload)));
                     EXPECT_EQ(Sent, Error::None);
                     Tuic::Address Target;
                     std::vector<std::uint8_t> Received;
                     const auto Err = co_await Server->AsyncReceiveFrom(Target, Received);
                     EXPECT_EQ(Err, Error::None);
                     EXPECT_EQ(Target.Host, "93.184.216.34");
                     EXPECT_EQ(std::string(Received.begin(), Received.end()), Payload);
                     (void)Server->Close();
                     (void)Client->Close();
                 });
    }

    TEST(TuicDgram, RawUdpReplyPreservesAssociationId)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        Raw->TransportKind = Transmission::Type::Udp;
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Raw);
        constexpr std::array<std::uint16_t, 2> AssociationIds{0x1234U, 0xBEEFU};
        Tuic::Message Request;
        Request.Cmd = Tuic::CmdPacket;
        Request.FragTotal = 1;
        Request.FragId = 0;
        Request.dst = MakeDestination();
        Request.payload = "request";
        auto ReplySource = MakeDestination();
        ReplySource.Host = "192.0.2.9";
        ReplySource.Port = 5353;
        std::array<Error, AssociationIds.size()> ReceiveStatuses{};
        std::array<Error, AssociationIds.size()> SendStatuses{};
        std::array<Tuic::Address, AssociationIds.size()> ReceivedTargets{};
        std::array<std::vector<std::uint8_t>, AssociationIds.size()> ReceivedPayloads{};

        RunCoroutine(ioc,
                     [&]() -> Net::awaitable<void>
                     {
                         for (std::size_t Index = 0; Index < AssociationIds.size(); ++Index)
                         {
                             Request.AssocId = AssociationIds[Index];
                             Request.PktId = static_cast<std::uint16_t>(Index + 40U);
                             Raw->InjectRead(Tuic::Build(Request));
                             ReceiveStatuses[Index] = co_await Dgram->AsyncReceiveFrom(
                                 ReceivedTargets[Index], ReceivedPayloads[Index]);
                             SendStatuses[Index] = co_await Dgram->AsyncSendTo(
                                 ReplySource, AsU8Span(std::string_view{"reply"}));
                         }
                     });

        std::size_t Offset = 0;
        for (std::size_t Index = 0; Index < AssociationIds.size(); ++Index)
        {
            EXPECT_EQ(ReceiveStatuses[Index], Error::None);
            EXPECT_EQ(SendStatuses[Index], Error::None);
            EXPECT_EQ(ReceivedTargets[Index].Host, Request.dst.Host);
            EXPECT_EQ(ReceivedTargets[Index].Port, Request.dst.Port);
            EXPECT_EQ(std::string(ReceivedPayloads[Index].begin(), ReceivedPayloads[Index].end()),
                      "request");
            ASSERT_LT(Offset, Raw->Written.size());
            Tuic::Message Reply;
            std::size_t Consumed = 0;
            EXPECT_EQ(Tuic::Parse(
                          std::span<const std::uint8_t>(Raw->Written.data() + Offset,
                                                        Raw->Written.size() - Offset),
                          Reply, Consumed),
                      Error::None);
            ASSERT_GT(Consumed, 0U);
            EXPECT_EQ(Reply.Cmd, Tuic::CmdPacket);
            EXPECT_EQ(Reply.AssocId, AssociationIds[Index]);
            EXPECT_EQ(Reply.dst.Host, ReplySource.Host);
            EXPECT_EQ(Reply.dst.Port, ReplySource.Port);
            EXPECT_EQ(Reply.payload, "reply");
            Offset += Consumed;
        }
        EXPECT_EQ(Offset, Raw->Written.size());
        (void)Dgram->Close();
    }

    TEST(TuicDgram, StreamFragmentsReassembleOutOfOrderAndPreserveAssociation)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        Raw->TransportKind = Transmission::Type::Tcp;
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Raw);
        constexpr std::array<std::uint8_t, 4> FragmentOrder{1, 0, 1, 2};
        constexpr std::array<std::string_view, 3> Fragments{"abc", "def", "ghi"};
        constexpr std::uint16_t AssociationId = 0xCAFEU;
        for (const auto FragId : FragmentOrder)
        {
            Tuic::Message Fragment;
            Fragment.Cmd = Tuic::CmdPacket;
            Fragment.AssocId = AssociationId;
            Fragment.PktId = 37;
            Fragment.FragTotal = static_cast<std::uint8_t>(Fragments.size());
            Fragment.FragId = FragId;
            Fragment.dst = MakeDestination();
            if (FragId != 0U) Fragment.dst.Type = Tuic::AddressType::None;
            Fragment.payload = Fragments[FragId];
            Raw->InjectRead(Tuic::Build(Fragment));
        }

        Error ReceiveStatus = Error::IoError;
        Error SendStatus = Error::IoError;
        Tuic::Address Source{};
        std::vector<std::uint8_t> Payload;
        RunCoroutine(ioc,
                     [&]() -> Net::awaitable<void>
                     {
                         ReceiveStatus = co_await Dgram->AsyncReceiveFrom(Source, Payload);
                         if (ReceiveStatus == Error::None)
                             SendStatus = co_await Dgram->AsyncSendTo(
                                 MakeDestination(), AsU8Span(std::string_view{"reply"}));
                     });

        EXPECT_EQ(ReceiveStatus, Error::None);
        EXPECT_EQ(SendStatus, Error::None);
        EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "abcdefghi");
        Tuic::Message Reply;
        std::size_t Consumed = 0;
        ASSERT_FALSE(Raw->Written.empty());
        EXPECT_EQ(Tuic::Parse(Raw->Written, Reply, Consumed), Error::None);
        EXPECT_EQ(Consumed, Raw->Written.size());
        EXPECT_EQ(Reply.AssocId, AssociationId);
        EXPECT_EQ(Reply.payload, "reply");
        (void)Dgram->Close();
    }

    TEST(TuicDgram, PacketIdWrapDoesNotJoinStaleFragments)
    {
        Tuic::Detail::DatagramReassembler Reassembler;
        Tuic::Message OldFragment;
        OldFragment.Cmd = Tuic::CmdPacket;
        OldFragment.AssocId = 0xAABBU;
        OldFragment.PktId = 42;
        OldFragment.FragTotal = 2;
        OldFragment.FragId = 0;
        OldFragment.dst = MakeDestination();
        OldFragment.payload = "stale";
        const auto OldResult = Reassembler.Accept(OldFragment);
        ASSERT_TRUE(OldResult);
        ASSERT_FALSE(OldResult->has_value());

        for (std::uint32_t Offset = 1; Offset <= 0x10000U; ++Offset)
        {
            Tuic::Message Single;
            Single.Cmd = Tuic::CmdPacket;
            Single.AssocId = OldFragment.AssocId;
            Single.PktId = static_cast<std::uint16_t>(OldFragment.PktId + Offset);
            Single.dst = MakeDestination();
            Single.payload = "advance";
            const auto Seen = Reassembler.Accept(std::move(Single));
            if (!Seen || !Seen->has_value())
            {
                FAIL() << "single packet rejected during packet ID wrap at offset " << Offset;
                return;
            }
        }

        auto NewFirst = OldFragment;
        NewFirst.payload = "new0";
        const auto First = Reassembler.Accept(std::move(NewFirst));
        ASSERT_TRUE(First);
        ASSERT_FALSE(First->has_value());
        auto NewSecond = OldFragment;
        NewSecond.FragId = 1;
        NewSecond.dst.Type = Tuic::AddressType::None;
        NewSecond.payload = "new1";
        const auto Second = Reassembler.Accept(std::move(NewSecond));
        ASSERT_TRUE(Second);
        ASSERT_TRUE(Second->has_value());
        EXPECT_EQ((**Second).payload, "new0new1");
    }

    TEST(TuicDgram, NativeUdpLargePacketUsesBoundedFramesAndRoundtrips)
    {
        Net::io_context ioc;
        auto RawServer = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        auto RawClient = std::make_shared<Preview::Transport::Unreliable>(ioc.get_executor());
        boost::system::error_code OpenEc;
        RawServer->NativeSocket().open(Net::ip::udp::v4(), OpenEc);
        RawServer->NativeSocket().bind({Net::ip::address_v4::loopback(), 0}, OpenEc);
        ASSERT_FALSE(OpenEc);
        const auto ServerEndpoint = RawServer->NativeSocket().local_endpoint();
        ASSERT_TRUE(RawClient->Connect("127.0.0.1:" + std::to_string(ServerEndpoint.port())));
        auto Server = std::make_shared<Tuic::Dgram<>>(RawServer);
        auto Client = std::make_shared<Tuic::Dgram<>>(RawClient);
        std::vector<std::uint8_t> Expected(4096);
        for (std::size_t Index = 0; Index < Expected.size(); ++Index)
            Expected[Index] = static_cast<std::uint8_t>((Index * 37U) & 0xFFU);

        Error SendStatus = Error::IoError;
        Error ReceiveStatus = Error::IoError;
        Tuic::Address Target{};
        std::vector<std::uint8_t> Received;
        RunCoroutine(ioc,
                     [&]() -> Net::awaitable<void>
                     {
                         SendStatus = co_await Client->AsyncSendTo(MakeDestination(), Expected);
                         if (SendStatus == Error::None)
                             ReceiveStatus = co_await Server->AsyncReceiveFrom(Target, Received);
                     });

        EXPECT_EQ(SendStatus, Error::None);
        EXPECT_EQ(ReceiveStatus, Error::None);
        EXPECT_EQ(Target.Host, "93.184.216.34");
        EXPECT_EQ(Received, Expected);
        (void)Server->Close();
        (void)Client->Close();
    }

    TEST(TuicDgram, RawUdpLargePacketEmitsBoundedReassemblableFragments)
    {
        Net::io_context ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        Raw->TransportKind = Transmission::Type::Udp;
        auto Dgram = std::make_shared<Tuic::Dgram<>>(Raw);
        std::vector<std::uint8_t> Expected(4096);
        for (std::size_t Index = 0; Index < Expected.size(); ++Index)
            Expected[Index] = static_cast<std::uint8_t>((Index * 37U) & 0xFFU);
        Error SendStatus = Error::IoError;
        RunCoroutine(ioc,
                     [&]() -> Net::awaitable<void>
                     {
                         SendStatus = co_await Dgram->AsyncSendTo(MakeDestination(), Expected);
                     });

        EXPECT_EQ(SendStatus, Error::None);
        Tuic::Detail::DatagramReassembler Reassembler;
        std::optional<Tuic::Message> Complete;
        std::size_t Offset = 0;
        std::size_t FragmentCount = 0;
        std::uint8_t FragmentTotal = 0;
        while (Offset < Raw->Written.size())
        {
            Tuic::Message Fragment;
            std::size_t Consumed = 0;
            const auto ParseStatus = Tuic::Parse(
                std::span<const std::uint8_t>(Raw->Written).subspan(Offset), Fragment, Consumed);
            ASSERT_EQ(ParseStatus, Error::None);
            ASSERT_GT(Consumed, 0U);
            EXPECT_LE(Consumed, Tuic::Detail::MaxDatagramFrameSize);
            EXPECT_EQ(Fragment.FragId, FragmentCount);
            EXPECT_EQ(Fragment.dst.Type, FragmentCount == 0U
                ? Tuic::AddressType::Ipv4
                : Tuic::AddressType::None);
            if (FragmentCount == 0U) FragmentTotal = Fragment.FragTotal;
            EXPECT_EQ(Fragment.FragTotal, FragmentTotal);
            auto Result = Reassembler.Accept(std::move(Fragment));
            ASSERT_TRUE(Result);
            if (Result->has_value()) Complete = std::move(**Result);
            Offset += Consumed;
            ++FragmentCount;
        }
        EXPECT_GT(FragmentCount, 1U);
        ASSERT_TRUE(Complete.has_value());
        EXPECT_EQ(Complete->payload.size(), Expected.size());
        EXPECT_EQ(std::vector<std::uint8_t>(Complete->payload.begin(), Complete->payload.end()),
                  Expected);
        const auto Destination = MakeDestination();
        Tuic::Detail::DatagramBuildRequest PlanRequest{0x1234U, 0, Destination, 0, true};
        std::vector<std::uint8_t> Scratch;
        const auto EmptyPlan = Tuic::Detail::BuildDatagramPlan(PlanRequest, Scratch);
        ASSERT_TRUE(EmptyPlan);
        PlanRequest.PayloadSize = EmptyPlan->FirstPayloadSize;
        const auto BoundaryPlan = Tuic::Detail::BuildDatagramPlan(PlanRequest, Scratch);
        ASSERT_TRUE(BoundaryPlan);
        EXPECT_EQ(BoundaryPlan->FragTotal, 1U);
        ++PlanRequest.PayloadSize;
        const auto FragmentedPlan = Tuic::Detail::BuildDatagramPlan(PlanRequest, Scratch);
        ASSERT_TRUE(FragmentedPlan);
        EXPECT_GT(FragmentedPlan->FragTotal, 1U);
        (void)Dgram->Close();
    }

    TEST(TuicDgram, ReceiveIpv6AndDomain)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // IPv6 地址（地址类型由首片 ATYP 字段携带）
                     Tuic::Message m6;
                     m6.Cmd = Preview::Tuic::CmdPacket;
                     m6.PktId = 1;
                     m6.dst.Type = Tuic::AddressType::Ipv6;
                     m6.dst.Host.assign(16, 'x');
                     m6.dst.Port = 8080;
                    m6.payload = "v6";
                     const auto w6 = co_await WriteAllBytes(*peer, Tuic::Build(m6));
                     EXPECT_FALSE(w6.Failed());

                     Tuic::Address src{};
                     std::vector<std::uint8_t> out;
                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::None);
                     EXPECT_EQ(src.Type, Tuic::AddressType::Ipv6);

                     // 域名地址
                     Tuic::Message md;
                     md.Cmd = Preview::Tuic::CmdPacket;
                     md.PktId = 2;
                     md.dst.Type = Tuic::AddressType::Domain;
                     md.dst.Host = "example.com";
                     md.dst.Port = 80;
                    md.payload = "dom";
                     const auto wd = co_await WriteAllBytes(*peer, Tuic::Build(md));
                     EXPECT_FALSE(wd.Failed());

                     EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(src, out), Error::None);
                     EXPECT_EQ(src.Type, Tuic::AddressType::Domain);
                 });
    }

    TEST(TuicDgram, ReceiveErrorBranches)
    {
        Net::io_context ioc;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 每个错误分支使用独立的 memory pair，避免把已关闭端点当作
                     // 后续 wire 注入器，保持半关闭写语义与真实 TCP 一致。
                     {
                         auto [a, b] = MakeMemoryPair(ioc.get_executor());
                         auto Peer = std::make_shared<MemoryStream>(std::move(b));
                         auto Dgram = std::make_shared<Tuic::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(a)));
                         Tuic::Address Source{};
                         std::vector<std::uint8_t> Output;
                         const auto PeerClose = Peer->Close();
                         EXPECT_TRUE(PeerClose);
                         EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(Source, Output), Error::UnexpectedEof);
                     }

                     {
                         auto [a, b] = MakeMemoryPair(ioc.get_executor());
                         auto Peer = std::make_shared<MemoryStream>(std::move(b));
                         auto Dgram = std::make_shared<Tuic::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(a)));
                         Tuic::Address Source{};
                         std::vector<std::uint8_t> Output;
                         const std::array<std::uint8_t, 11> BadAtypWire{
                             0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7F};
                         const auto WriteError = co_await WriteAllBytes(*Peer, BadAtypWire);
                         EXPECT_FALSE(WriteError.Failed());
                         EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(Source, Output), Error::BadMessage);
                     }

                     {
                         auto [a, b] = MakeMemoryPair(ioc.get_executor());
                         auto Peer = std::make_shared<MemoryStream>(std::move(b));
                         auto Dgram = std::make_shared<Tuic::Dgram<>>(
                             std::make_shared<MemoryStream>(std::move(a)));
                         Tuic::Address Source{};
                         std::vector<std::uint8_t> Output;
                         const std::array<std::uint8_t, 5> ShortHead{0x05, 0x02, 0, 0, 0};
                         const auto WriteError = co_await WriteAllBytes(*Peer, ShortHead);
                         EXPECT_FALSE(WriteError.Failed());
                         const auto PeerClose = Peer->Close();
                         EXPECT_TRUE(PeerClose);
                         EXPECT_EQ(co_await Dgram->AsyncReceiveFrom(Source, Output), Error::UnexpectedEof);
                     }
                 });
    }

    TEST(TuicDgram, SendIoError)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Dgram = std::make_shared<Tuic::Dgram<>>(std::make_shared<MemoryStream>(std::move(a)));

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 对端全关 → 写入失败 → io_error
                     const auto PeerClose = peer->Close();
                     EXPECT_TRUE(PeerClose);
                     const std::string_view one{"x"};
                     const auto err = co_await Dgram->AsyncSendTo(MakeDestination(), AsU8Span(one));
                     EXPECT_EQ(err, Error::IoError);
                 });
    }

} // namespace
