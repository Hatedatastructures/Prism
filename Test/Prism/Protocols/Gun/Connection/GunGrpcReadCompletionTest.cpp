/**
 * @file GunGrpcReadCompletionTest.cpp
 * @brief gRPC read completion 在 HTTP/2 帧处理后的 EOF 与 native 终态契约。
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Gun/Detail/GrpcStreamDriver.hpp>
#include <Prism/Protocols/Http2/Detail/Frame.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Protocols/Http2/Types.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <system_error>
#include <vector>

namespace
{
    namespace H2 = Prism::Http2;
    namespace Grpc = Prism::Gun::Grpc;

    [[nodiscard]] auto MakeGrpcSettingsWire(boost::asio::io_context &IoContext)
        -> std::vector<std::byte>
    {
        H2::Session Client(IoContext.get_executor(), false);
        const std::array<H2::SettingsEntry, 1> Settings{{
            {H2::SettingsMaxConcurrentStreams, 10}}};
        Client.SendSettings(Settings);
        std::vector<std::byte> Wire;
        (void)Client.Collect(Wire);
        return Wire;
    }

    [[nodiscard]] auto CountSettingsAcknowledgments(H2::Session &Session) -> std::size_t
    {
        std::vector<std::byte> Output;
        if (!Session.Collect(Output))
        {
            return 0;
        }

        std::size_t Acknowledgments = 0;
        const auto Bytes = std::span<const std::byte>(Output);
        std::size_t Offset = 0;
        while (Offset < Bytes.size())
        {
            const auto Remaining = Bytes.subspan(Offset);
            if (Remaining.size() < H2::Detail::FrameHeaderSize)
            {
                return 0;
            }

            const auto Header = H2::Detail::ParseFrameHeader(Remaining);
            if (!Header)
            {
                return 0;
            }
            const auto FrameSize = H2::Detail::FrameHeaderSize +
                static_cast<std::size_t>(Header->Length);
            if (FrameSize > Remaining.size())
            {
                return 0;
            }
            if (Header->Type == H2::Detail::FrameType::Settings &&
                (Header->Flags & H2::Detail::FlagSettingsAck) != 0)
            {
                if (Header->Length != 0 ||
                    Header->StreamId != H2::Detail::ConnectionStreamId ||
                    Header->Flags != H2::Detail::FlagSettingsAck)
                {
                    return 0;
                }
                ++Acknowledgments;
            }
            Offset += FrameSize;
        }
        return Acknowledgments;
    }
}

TEST(GunGrpcContract, ReadDriverConsumesFramesBeforeEof)
{
    boost::asio::io_context Io;
    const auto Input = MakeGrpcSettingsWire(Io);
    ASSERT_FALSE(Input.empty());

    H2::Session Server(Io.get_executor(), true);
    const Grpc::Detail::GrpcReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), {Prism::Fault::Code::Eof}}};

    const auto Step = Grpc::Detail::ProcessGrpcReadCompletion(Server, Completion);
    const auto SettingsAckSeen = CountSettingsAcknowledgments(Server);

    EXPECT_TRUE(Step.Terminal);
    EXPECT_EQ(Step.Failure.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(SettingsAckSeen, 1U);
}

TEST(GunGrpcContract, ReadDriverConsumesFramesBeforeNativeFailure)
{
    boost::asio::io_context Io;
    const auto Input = MakeGrpcSettingsWire(Io);
    ASSERT_FALSE(Input.empty());

    H2::Session Server(Io.get_executor(), true);
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const Grpc::Detail::GrpcReadCompletion Completion{
        std::span<const std::byte>(Input),
        Prism::IoResult{Input.size(), Prism::Fault::FromNative(Native)}};

    const auto Step = Grpc::Detail::ProcessGrpcReadCompletion(Server, Completion);
    const auto SettingsAckSeen = CountSettingsAcknowledgments(Server);

    EXPECT_TRUE(Step.Terminal);
    EXPECT_EQ(Step.Failure.Native, Native);
    EXPECT_EQ(SettingsAckSeen, 1U);
}
