/** @file Hysteria2FactoryTest.cpp @brief Hysteria2 实际 provider/native 消费、独立 owner 与正式 TCP wire 应答。 */
#include "QuicFixture.hpp"
#include <TestSupport/Prism/QuicStreamProviderActivity.hpp>
#include <Prism/Protocols/Hysteria2/StreamSession.hpp>
#include <gtest/gtest.h>
#include <boost/asio/co_spawn.hpp>
namespace
{
    class HeaderWriter final : public Prism::Quic::StreamProvider
    {
    public:
        explicit HeaderWriter(boost::asio::any_io_executor Executor)
            : Executor_(std::move(Executor)),
              Activity_(std::make_shared<Prism::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(std::span<std::byte>, std::error_code &Error)
            -> boost::asio::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            Error.clear();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            co_return 0;
        }

        [[nodiscard]] auto Write(std::span<const std::byte> Buffer, std::error_code &Error)
            -> boost::asio::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            Error.clear();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            if (Buffer.empty()) co_return 0;
            Bytes.push_back(Buffer.front());
            co_return 1;
        }

        [[nodiscard]] auto Close() -> ControlResult override
        {
            Closed_ = true;
            Activity_->CompleteClose();
            return {};
        }

        [[nodiscard]] auto ShutdownWrite() -> boost::asio::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            WriteShutdown_ = true;
            co_return ShutdownResult{};
        }

        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> boost::asio::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            if (!WriteShutdown_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            co_return ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override { return 1; }
        [[nodiscard]] auto IsClosed() const noexcept -> bool override { return Closed_; }

        std::vector<std::byte> Bytes;

    private:
        boost::asio::any_io_executor Executor_;
        std::shared_ptr<Prism::Testing::Quic::StreamProviderActivity> Activity_;
        bool Closed_{false};
        bool WriteShutdown_{false};
    };
}
TEST(Hysteria2Factory, PinsAlpnAndOwnsPerServerCallbacks)
{
    ProviderTesting::QuicFixture Fixture;
    auto Prepared=ProviderTesting::P::ProviderCatalog::Prepare(Fixture.Input("hysteria2"),Fixture.Services());ASSERT_TRUE(Prepared);
    auto Frozen=Prepared->Freeze();ASSERT_TRUE(Frozen);auto Bound=Frozen->Bind({});ASSERT_TRUE(Bound);
    auto Factory=Bound->Find("quic-instance")->Quic();std::size_t Closed=0;
    auto Request=Prism::Testing::Quic::MakeRequest({Factory,Fixture.Pin->Id(),"quic-instance",
        {std::byte{1}},{boost::asio::ip::address_v4::loopback(),4321},[&Closed]{++Closed;}});
    auto Accepted=Factory->Create(std::move(Request));
    ASSERT_TRUE(Accepted);auto Owner=Accepted->SharedOwner();ASSERT_TRUE(Owner);
    auto Run=[&]()->boost::asio::awaitable<void>
    {
        Owner->Start();
        EXPECT_TRUE(Accepted->RequestClose());
        EXPECT_TRUE(Accepted->RequestClose());
        EXPECT_TRUE(co_await Bound->Drain());
        EXPECT_EQ(Closed,1U);
    };
    boost::asio::co_spawn(Fixture.Io,Run(),[](std::exception_ptr Error){EXPECT_FALSE(Error);});Fixture.Io.run();
    EXPECT_TRUE(Owner->State().Closed);EXPECT_TRUE(Fixture.Socket->is_open());
}
TEST(Hysteria2Factory, BuildsCompleteTcpResponseHeader)
{
    boost::asio::io_context Io;auto Provider=std::make_shared<HeaderWriter>(Io.get_executor());
    boost::asio::co_spawn(Io,Prism::Hysteria2::StreamDetail::WriteTcpResponseHeader(Provider),
        [](std::exception_ptr Error,bool Written){EXPECT_FALSE(Error);EXPECT_TRUE(Written);});Io.run();
    EXPECT_EQ(Provider->Bytes,(std::vector<std::byte>{std::byte{0},std::byte{0},std::byte{0}}));
}
TEST(Hysteria2Factory, MapsTypedBindingIntoNativeServerOptions)
{
    ProviderTesting::QuicFixture Fixture;auto Input=Fixture.Input("hysteria2");
    Input.Instances[0].Protocol.Quic->ServerName="quic.example";
    Input.Instances[0].Protocol.Quic->MaxStreams=13;Input.Instances[0].Protocol.Quic->MaxDatagrams=29;
    auto Prepared=ProviderTesting::P::ProviderCatalog::Prepare(std::move(Input),Fixture.Services());ASSERT_TRUE(Prepared);
    const auto& Native=std::get<Prism::Hysteria2::Prepared>(Prepared->Entries().front());
    EXPECT_EQ(Native.Input.Config.Alpn,"h3");EXPECT_EQ(Native.Input.Config.ServerName,"quic.example");
    EXPECT_EQ(Native.Input.Config.MaxStreams,13U);EXPECT_EQ(Native.Input.Config.MaxDatagrams,29U);
    EXPECT_EQ(Native.Services.Network.Listener.Socket,Fixture.Socket);EXPECT_EQ(Native.Services.Network.Listener.Tls,Fixture.Tls);
}
