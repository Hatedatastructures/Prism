/**
 * @file Socks5UdpAssocRetirementTest.cpp
 * @brief SOCKS5 UDP_ASSOCIATE 显式取消与真实退役回执测试。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <utility>

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Protocols/Socks5/UdpAssoc.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Preview::Socks5;
    using Tcp = Net::ip::tcp;
    using Udp = Net::ip::udp;
    using Failure = Preview::Fault::Failure;
    using RunResult = std::expected<void, Failure>;

    enum class RetirementRequest
    {
        Cancel,
        Close,
    };

    struct UdpAssocCompletion final
    {
        explicit UdpAssocCompletion(Net::any_io_executor Executor)
            : Finished(std::move(Executor), 1)
        {
        }

        Net::experimental::channel<void(boost::system::error_code)> Finished;
        RunResult Result{std::unexpected(Failure{Preview::Fault::Code::Blocked})};
        std::exception_ptr Exception;
    };

    struct CanceledDrainReceipt final
    {
        std::atomic<bool> ReturnedCanceled{false};
        std::atomic<bool> UnderlyingRetired{false};
    };

    /** @brief 模拟取消结果先返回、底层物理退休回执已成立的载体 Activity。 */
    class CanceledAfterRetiredActivity final : public Preview::Contract::CarrierActivity
    {
    public:
        CanceledAfterRetiredActivity(
            std::shared_ptr<Preview::Contract::CarrierActivity> Underlying,
            std::shared_ptr<CanceledDrainReceipt> Receipt)
            : Underlying_(std::move(Underlying)), Receipt_(std::move(Receipt))
        {
        }

        auto Seal() noexcept -> void override
        {
            Underlying_->Seal();
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Underlying_->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Receipt_->ReturnedCanceled.load(std::memory_order_acquire) &&
                   Receipt_->UnderlyingRetired.load(std::memory_order_acquire) &&
                   Underlying_->IsRetired();
        }

        [[nodiscard]] auto Drain() -> Net::awaitable<RunResult> override
        {
            const auto Drained = co_await Underlying_->Drain();
            if (!Drained) co_return std::unexpected(Drained.error());
            Receipt_->UnderlyingRetired.store(
                Underlying_->IsRetired(), std::memory_order_release);
            Receipt_->ReturnedCanceled.store(true, std::memory_order_release);
            co_return std::unexpected(Failure{Preview::Fault::Code::Canceled});
        }

    private:
        std::shared_ptr<Preview::Contract::CarrierActivity> Underlying_;
        std::shared_ptr<CanceledDrainReceipt> Receipt_;
    };

    /** @brief 透传 TCP I/O，并为该层提供独立的取消退休回执。 */
    class CanceledDrainTransmission final : public Preview::Transmission
    {
    public:
        CanceledDrainTransmission(
            std::shared_ptr<Preview::Transmission> Underlying,
            std::shared_ptr<CanceledDrainReceipt> Receipt)
            : Preview::Transmission(Underlying->Executor()),
              Underlying_(std::move(Underlying)),
              Activity_(std::make_shared<CanceledAfterRetiredActivity>(
                  Preview::Transmission::Activity(), std::move(Receipt)))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Underlying_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Underlying_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Preview::Transmission * override
        {
            return Underlying_.get();
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Underlying_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Underlying_->WriteSome(Buffer, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Underlying_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Underlying_->Close();
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Underlying_->Cancel();
        }

        [[nodiscard]] auto OwnsClose() const noexcept -> bool override
        {
            return false;
        }

    private:
        std::shared_ptr<Preview::Transmission> Underlying_;
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity_;
    };

    struct UdpAssocScenario final
    {
        RunResult ActivityDrain{std::unexpected(Failure{Preview::Fault::Code::Blocked})};
        RunResult RunResultValue{std::unexpected(Failure{Preview::Fault::Code::Blocked})};
        RetirementRequest Request{RetirementRequest::Cancel};
        bool BindReplyReceived{false};
        bool UploadObserved{false};
        bool TargetReceived{false};
        bool ActivityRetired{false};
        std::shared_ptr<CanceledDrainReceipt> CanceledDrain;
    };

    class UploadBarrierTrafficSink final : public Preview::Foundation::TrafficSink
    {
    public:
        explicit UploadBarrierTrafficSink(Net::any_io_executor Executor)
            : Uploads_(std::move(Executor), 1)
        {
        }

        auto Report(Preview::Foundation::TrafficEvent Event) noexcept -> void override
        {
            if (Event.Kind == Preview::Foundation::TrafficEventKind::Bytes && Event.Up != 0)
                (void)Uploads_.try_send(boost::system::error_code{});
        }

        auto Retire(Preview::Foundation::TrafficRetirement)
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            co_return std::expected<void, Failure>{};
        }

        [[nodiscard]] auto WaitForUpload() -> Net::awaitable<void>
        {
            co_await Uploads_.async_receive(Net::use_awaitable);
        }

    private:
        Net::experimental::channel<void(boost::system::error_code)> Uploads_;
    };

    auto MakeTcpPair(Net::io_context &Io)
        -> Net::awaitable<std::pair<Tcp::socket, Tcp::socket>>
    {
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        Tcp::socket Client(Io.get_executor());
        co_await Client.async_connect(Acceptor.local_endpoint(), Net::use_awaitable);
        auto Server = co_await Acceptor.async_accept(Net::use_awaitable);
        co_return std::pair{std::move(Client), std::move(Server)};
    }

    auto RunScenario(Net::io_context &Io, UdpAssocScenario &Scenario)
        -> Net::awaitable<void>
    {
        Udp::socket DropTarget(Io.get_executor());
        boost::system::error_code ErrorCode;
        DropTarget.open(Udp::v4(), ErrorCode);
        if (ErrorCode) co_return;
        DropTarget.bind(Udp::endpoint(Net::ip::address_v4::loopback(), 0), ErrorCode);
        if (ErrorCode) co_return;
        const auto Target = DropTarget.local_endpoint(ErrorCode);
        if (ErrorCode) co_return;

        Udp::socket ClientDatagrams(Io.get_executor());
        ClientDatagrams.open(Udp::v4(), ErrorCode);
        if (ErrorCode) co_return;
        ClientDatagrams.bind(Udp::endpoint(Net::ip::address_v4::loopback(), 0), ErrorCode);
        if (ErrorCode) co_return;

        auto [ClientControl, ServerControl] = co_await MakeTcpPair(Io);
        std::shared_ptr<Preview::Transmission> Carrier =
            std::make_shared<Preview::Transport::Reliable>(std::move(ServerControl));
        if (Scenario.CanceledDrain)
        {
            Carrier = std::make_shared<CanceledDrainTransmission>(
                std::move(Carrier), Scenario.CanceledDrain);
        }
        auto Connection = std::make_shared<Socks5::Conn<>>(std::move(Carrier));
        Socks5::UdpAssocOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds::zero();
        auto Traffic = std::make_shared<UploadBarrierTrafficSink>(Io.get_executor());
        Options.Traffic = Traffic;
        auto Association = std::make_shared<Socks5::UdpAssoc>(
            Io.get_executor(), std::move(Connection), std::move(Options));
        const auto Activity = Association->Activity();
        auto Completion = std::make_shared<UdpAssocCompletion>(Io.get_executor());
        Net::co_spawn(Io, Association->Run(),
            [Completion](std::exception_ptr Exception, RunResult Result)
            {
                Completion->Exception = std::move(Exception);
                Completion->Result = std::move(Result);
                (void)Completion->Finished.try_send(boost::system::error_code{});
            });

        using boost::asio::experimental::awaitable_operators::operator||;
        std::array<std::byte, 10> Reply{};
        Net::steady_timer BindWatchdog(Io.get_executor());
        BindWatchdog.expires_after(std::chrono::seconds(2));
        auto BindRace = co_await (
            Net::async_read(ClientControl, Net::buffer(Reply),
                Net::redirect_error(Net::use_awaitable, ErrorCode)) ||
            BindWatchdog.async_wait(Net::use_awaitable));
        BindWatchdog.cancel();
        Scenario.BindReplyReceived = BindRace.index() == 0 && !ErrorCode &&
            std::get<0>(BindRace) == Reply.size();
        if (Scenario.BindReplyReceived)
        {
            const std::array<std::uint8_t, 1> Payload{0x5a};
            const auto Frame = Socks5::BuildUdpDatagram(
                {Socks5::AddressType::Ipv4, "127.0.0.1", Target.port()}, Payload);
            co_await ClientDatagrams.async_send_to(
                Net::buffer(Frame), Association->BindEndpoint(),
                Net::redirect_error(Net::use_awaitable, ErrorCode));
            if (!ErrorCode)
            {
                using boost::asio::experimental::awaitable_operators::operator||;
                Net::steady_timer Watchdog(Io.get_executor());
                Watchdog.expires_after(std::chrono::seconds(2));
                auto UploadRace = co_await (
                    Traffic->WaitForUpload() || Watchdog.async_wait(Net::use_awaitable));
                Watchdog.cancel();
                Scenario.UploadObserved = UploadRace.index() == 0;
                if (Scenario.UploadObserved)
                {
                    co_await Net::post(Io.get_executor(), Net::use_awaitable);
                }

                Watchdog.expires_after(std::chrono::seconds(2));
                std::array<std::uint8_t, 8> Received{};
                Udp::endpoint Peer;
                auto Receive = DropTarget.async_receive_from(
                    Net::buffer(Received), Peer,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                auto ReceiveRace = co_await (
                    std::move(Receive) || Watchdog.async_wait(Net::use_awaitable));
                Watchdog.cancel();
                if (ReceiveRace.index() == 0)
                {
                    const auto Size = std::get<0>(ReceiveRace);
                    Scenario.TargetReceived = !ErrorCode && Size == Payload.size() &&
                        Received[0] == Payload[0];
                }
            }
        }

        if (Scenario.Request == RetirementRequest::Cancel)
            Association->Cancel();
        else
            Association->Close();
        Scenario.ActivityDrain = co_await Activity->Drain();
        Scenario.ActivityRetired = Activity->IsRetired();
        boost::system::error_code Ignore;
        ClientControl.close(Ignore);
        co_await Completion->Finished.async_receive(
            Net::redirect_error(Net::use_awaitable, Ignore));
        if (Completion->Exception) std::rethrow_exception(Completion->Exception);
        Scenario.RunResultValue = Completion->Result;
    }

    auto RunCoroutine(Net::io_context &Io, Net::awaitable<void> Scenario) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Scenario),
            [&Exception](std::exception_ptr Value) { Exception = std::move(Value); });
        Io.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    auto ExpectPhysicalRetirement(const UdpAssocScenario &Scenario) -> void
    {
        EXPECT_TRUE(Scenario.BindReplyReceived);
        EXPECT_TRUE(Scenario.UploadObserved);
        EXPECT_TRUE(Scenario.TargetReceived);
        if (!Scenario.ActivityDrain)
        {
            ADD_FAILURE() << "Activity::Drain returned code="
                          << static_cast<unsigned>(Scenario.ActivityDrain.error().Code)
                          << " retired=" << Scenario.ActivityRetired;
        }
        ASSERT_TRUE(Scenario.ActivityDrain);
        EXPECT_TRUE(Scenario.ActivityRetired);
    }

    TEST(Socks5UdpAssocRetirement, ExplicitCancelWaitsForPhysicalRetirement)
    {
        Net::io_context Io;
        UdpAssocScenario Scenario;
        RunCoroutine(Io, RunScenario(Io, Scenario));
        ExpectPhysicalRetirement(Scenario);
        ASSERT_FALSE(Scenario.RunResultValue);
        EXPECT_EQ(Scenario.RunResultValue.error().Code, Preview::Fault::Code::Canceled);
    }

    TEST(Socks5UdpAssocRetirement, CloseWaitsForPhysicalRetirement)
    {
        Net::io_context Io;
        UdpAssocScenario Scenario;
        Scenario.Request = RetirementRequest::Close;
        RunCoroutine(Io, RunScenario(Io, Scenario));
        ExpectPhysicalRetirement(Scenario);
        EXPECT_TRUE(Scenario.RunResultValue);
    }

    TEST(Socks5UdpAssocRetirement, AcceptsCanceledTcpDrainAfterPhysicalRetirement)
    {
        Net::io_context Io;
        UdpAssocScenario Scenario;
        Scenario.CanceledDrain = std::make_shared<CanceledDrainReceipt>();
        RunCoroutine(Io, RunScenario(Io, Scenario));

        ExpectPhysicalRetirement(Scenario);
        EXPECT_TRUE(Scenario.CanceledDrain->ReturnedCanceled.load(
            std::memory_order_acquire));
        EXPECT_TRUE(Scenario.CanceledDrain->UnderlyingRetired.load(
            std::memory_order_acquire));
        ASSERT_FALSE(Scenario.RunResultValue);
        EXPECT_EQ(Scenario.RunResultValue.error().Code,
                  Preview::Fault::Code::Canceled);
    }

}
