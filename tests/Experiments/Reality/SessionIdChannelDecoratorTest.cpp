/**
 * @file SessionIdChannelDecoratorTest.cpp
 * @brief Reality SessionId 实验通道的 Transmission decorator 行为。
 */

#include "SessionIdChannelTestSupport.hpp"
#include <Preview/Protocols/Reality/Detail/Key.hpp>
#include <Preview/Protocols/Reality/Types.hpp>
#include "SessionIdChannel.hpp"
#include <TestSupport/Preview/PreviewMockTransport.hpp>

#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Reality = Preview::Reality;
    using SessionIdChannel = Reality::Detail::SessionIdChannel<>;

    class ZeroProgressTransport final : public Preview::Transmission
    {
    public:
        explicit ZeroProgressTransport(Net::any_io_executor Executor)
            : Preview::Transmission(Executor), Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        {
            std::move(Handler)(Preview::IoResult{
                0, Preview::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            ++Writes_;
            BufferSize_ = Buffer.size();
            if (Writes_ == 1U)
            {
                const auto Bytes = Overreport_ ? BufferSize_ + 1U : 0U;
                std::move(Handler)(Preview::IoResult{Bytes, {}});
                return;
            }
            std::move(Handler)(Preview::IoResult{
                0, Preview::Fault::FromNative(std::make_error_code(std::errc::broken_pipe))});
        }

        auto OnClose() -> ControlResult override { return {}; }
        auto OnCancel() -> ControlResult override { return {}; }

        std::size_t Writes_{0};
        std::size_t BufferSize_{0};
        bool Overreport_{false};

    private:
        ExecutorType Executor_;

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
    };

    auto CheckDecorator(const std::shared_ptr<SessionIdChannel> &Channel,
                        Net::io_context &Context) -> void
    {
        (void)Channel->Executor();
        EXPECT_NE(Channel->NextLayer(), nullptr);
        const auto *Connection = Channel.get();
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_EQ(Channel->template lowest_layer<Preview::MemoryStream>(), Channel->NextLayer());
        Context.restart();
        const auto Cancel = Channel->Cancel();
        const auto Close = Channel->Close();
        Context.run();
        EXPECT_TRUE(Cancel.has_value());
        EXPECT_TRUE(Close.has_value());
        EXPECT_TRUE(Preview::Testing::DriveDrain(Context, Channel).has_value());
        auto Released = Channel->Release();
        EXPECT_NE(Released, nullptr);
        EXPECT_EQ(Channel->NextLayer(), nullptr);
        EXPECT_TRUE(Preview::Testing::DriveDrain(Context, Released).has_value());
    }

    TEST(ConnDecorator, RealityOverreportedReadFailsImmediately)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->OverreportRead = true;
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PeerPublicKey{};
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(PrivateKey, PeerPublicKey));
        auto Channel = std::make_shared<SessionIdChannel>(Transport, PrivateKey);
        const std::array<std::uint8_t, 32> ClientRandom{};
        const std::array<std::uint8_t, 1> Hello{};
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello};
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};
        Preview::Error Result = Preview::Error::None;

        Preview::Reality::Detail::Experiments::TestSupport::Run(Ioc,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Channel->ReadHandshake(PeerPublicKey, Params, ShortId);
            });

        EXPECT_EQ(Result, Preview::Error::UnexpectedEof);
        EXPECT_EQ(Transport->ReadsDone, 1u);
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Channel));
    }

    TEST(ConnDecorator, RealityOverreportedWriteFailsImmediately)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<ZeroProgressTransport>(Ioc.get_executor());
        Transport->Overreport_ = true;
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PeerPublicKey{};
        ASSERT_FALSE(Reality::Detail::GenerateKeypair(PrivateKey, PeerPublicKey));
        auto Channel = std::make_shared<SessionIdChannel>(Transport, PrivateKey);
        const std::array<std::uint8_t, 32> ClientRandom{};
        const std::array<std::uint8_t, 71> Hello{};
        const Reality::Detail::HandshakeParams Params{ClientRandom, Hello};
        Preview::Error Result = Preview::Error::None;

        Preview::Reality::Detail::Experiments::TestSupport::Run(Ioc,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Channel->WriteHandshake(PeerPublicKey, Params);
            });

        EXPECT_EQ(Result, Preview::Error::IoError);
        EXPECT_EQ(Transport->Writes_, 1u);
        Preview::Testing::ExpectFixtureCloseReceipt(Preview::Testing::DriveClose(Ioc, Channel));
    }

    TEST(ConnDecorator, RealityConn)
    {
        Net::io_context Ioc;
        auto Pair = Preview::Reality::Detail::Experiments::TestSupport::MakePair(Ioc.get_executor());
        auto Channel = std::make_shared<SessionIdChannel>(
            Pair.FirstOwner, std::array<std::uint8_t, Reality::KeyLen>{});
        CheckDecorator(Channel, Ioc);
        Preview::Testing::ExpectFixtureCloseReceipt(
            Preview::Testing::DriveClose(Ioc, Pair.SecondOwner));
    }
}
