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
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Protocols/Socks5/UdpAssoc.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Socks5 = Prism::Socks5;
    using Tcp = Net::ip::tcp;
    using Udp = Net::ip::udp;
    using Failure = Prism::Fault::Failure;
    using RunResult = std::expected<void, Failure>;
    using BindResult = Socks5::ReplyResult<std::size_t>;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;

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
        RunResult Result{std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        std::exception_ptr Exception;
    };

    struct CanceledDrainReceipt final
    {
        std::atomic<bool> ReturnedCanceled{false};
        std::atomic<bool> UnderlyingRetired{false};
    };

    /** @brief 模拟取消结果先返回、底层物理退休回执已成立的载体 Activity。 */
    class CanceledAfterRetiredActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        CanceledAfterRetiredActivity(
            std::shared_ptr<Prism::Contract::CarrierActivity> Underlying,
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
            co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
        }

    private:
        std::shared_ptr<Prism::Contract::CarrierActivity> Underlying_;
        std::shared_ptr<CanceledDrainReceipt> Receipt_;
    };

    /** @brief 透传 TCP I/O，并为该层提供独立的取消退休回执。 */
    class CanceledDrainTransmission final : public Prism::Transmission
    {
    public:
        CanceledDrainTransmission(
            std::shared_ptr<Prism::Transmission> Underlying,
            std::shared_ptr<CanceledDrainReceipt> Receipt)
            : Prism::Transmission(Underlying->Executor()),
              Underlying_(std::move(Underlying)),
              Activity_(std::make_shared<CanceledAfterRetiredActivity>(
                  Prism::Transmission::Activity(), std::move(Receipt)))
        {
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Underlying_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Underlying_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override
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
        std::shared_ptr<Prism::Transmission> Underlying_;
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity_;
    };

    struct UdpAssocScenario final
    {
        RunResult ActivityDrain{std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        RunResult RunResultValue{std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        RetirementRequest Request{RetirementRequest::Cancel};
        bool BindReplyReceived{false};
        bool UploadObserved{false};
        bool TargetReceived{false};
        bool ActivityRetired{false};
        std::shared_ptr<CanceledDrainReceipt> CanceledDrain;
    };

    class UploadBarrierTrafficSink final : public Prism::Foundation::TrafficSink
    {
    public:
        explicit UploadBarrierTrafficSink(Net::any_io_executor Executor)
            : Uploads_(std::move(Executor), 1)
        {
        }

        auto Report(Prism::Foundation::TrafficEvent Event) noexcept -> void override
        {
            if (Event.Kind == Prism::Foundation::TrafficEventKind::Bytes && Event.Up != 0)
                (void)Uploads_.try_send(boost::system::error_code{});
        }

        auto Retire(Prism::Foundation::TrafficRetirement)
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
        std::shared_ptr<Prism::Transmission> Carrier =
            std::make_shared<Prism::Transport::Reliable>(std::move(ServerControl));
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
            const auto Cause = Scenario.ActivityDrain.error();
            ADD_FAILURE() << "Activity::Drain returned code="
                          << static_cast<unsigned>(Cause.Code)
                          << " native=" << Cause.Native.category().name() << ':'
                          << Cause.Native.value()
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
        EXPECT_EQ(Scenario.RunResultValue.error().Code, Prism::Fault::Code::Canceled);
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
                  Prism::Fault::Code::Canceled);
    }

    constexpr auto ReplySize = std::size_t{10};
    constexpr auto WatchdogDuration = std::chrono::seconds{1};

    struct BindFailureOutcome final
    {
        BindResult Result;
        std::array<std::byte, ReplySize> Wire{};
        std::size_t WireBytes{0U};
        Failure WireFailure;
        bool WireTimedOut{false};
        std::byte ExtraByte{};
        std::size_t ExtraBytes{0U};
        Failure ExtraFailure;
        bool ExtraTimedOut{false};
        bool DrainSucceeded{false};
        Failure DrainFailure;
        bool ActivityRetired{false};
        bool ControlClosed{false};
        bool PeerCloseSucceeded{false};
        bool PeerDrainSucceeded{false};
    };

    struct NativeBindFailureOutcome final
    {
        BindResult Result;
        std::error_code ExpectedNative;
        boost::system::error_code SocketOpenError;
        boost::system::error_code SocketBindError;
        boost::system::error_code RemoteEndpointError;
        bool DrainSucceeded{false};
        Failure DrainFailure;
        bool ActivityRetired{false};
        bool ControlClosed{false};
    };

    struct AssociationRunCompletion final
    {
        explicit AssociationRunCompletion(Net::any_io_executor Executor)
            : Finished(std::move(Executor), 1)
        {
        }

        Net::experimental::channel<void(boost::system::error_code)> Finished;
        std::expected<void, Failure> Result{
            std::unexpected(Failure{Prism::Fault::Code::Blocked})};
        std::exception_ptr Exception;
    };

    auto RunMemoryBindFailure(Net::io_context &IoContext)
        -> Net::awaitable<BindFailureOutcome>
    {
        using Net::experimental::awaitable_operators::operator||;
        auto [PeerEndpoint, ControlEndpoint] = MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerEndpoint));
        auto Control = std::make_shared<MemoryStream>(std::move(ControlEndpoint));
        auto Connection = std::make_shared<Socks5::Conn<>>(Control);
        auto Association = std::make_shared<Socks5::UdpAssoc>(
            IoContext.get_executor(), Connection, Socks5::UdpAssocOptions{});
        const auto Activity = Association->Activity();

        BindFailureOutcome Outcome;
        Outcome.Result = co_await Association->BindAndReply();

        Net::steady_timer Watchdog(IoContext.get_executor());
        Watchdog.expires_after(WatchdogDuration);
        const auto ReplyRace = co_await (
            Peer->ReadExact(std::span<std::byte>(Outcome.Wire)) ||
            Watchdog.async_wait(Net::use_awaitable));
        Watchdog.cancel();
        Outcome.WireTimedOut = ReplyRace.index() != 0U;
        if (!Outcome.WireTimedOut)
        {
            const auto Read = std::get<0>(ReplyRace);
            Outcome.WireBytes = Read.Bytes;
            Outcome.WireFailure = Read.Failure;
        }

        const auto Drain = co_await Activity->Drain();
        Outcome.DrainSucceeded = Drain.has_value();
        if (!Drain) Outcome.DrainFailure = Drain.error();
        Outcome.ActivityRetired = Activity->IsRetired();
        Outcome.ControlClosed = !Control->IsOpen();

        Watchdog.expires_after(WatchdogDuration);
        const auto ExtraRace = co_await (
            Peer->ReadSome(std::span<std::byte>{&Outcome.ExtraByte, 1U}) ||
            Watchdog.async_wait(Net::use_awaitable));
        Watchdog.cancel();
        Outcome.ExtraTimedOut = ExtraRace.index() != 0U;
        if (!Outcome.ExtraTimedOut)
        {
            const auto Read = std::get<0>(ExtraRace);
            Outcome.ExtraBytes = Read.Bytes;
            Outcome.ExtraFailure = Read.Failure;
        }

        const auto PeerClose = Peer->Close();
        Outcome.PeerCloseSucceeded = PeerClose.has_value();
        const auto PeerDrain = co_await Peer->Activity()->Drain();
        Outcome.PeerDrainSucceeded = PeerDrain.has_value();
        co_return Outcome;
    }

    auto RunNativeBindFailure(Net::io_context &IoContext)
        -> Net::awaitable<NativeBindFailureOutcome>
    {
        auto NativeSocket = Tcp::socket(IoContext.get_executor());
        NativeBindFailureOutcome Outcome;
        NativeSocket.open(Tcp::v4(), Outcome.SocketOpenError);
        if (Outcome.SocketOpenError) co_return Outcome;
        NativeSocket.bind(
            Tcp::endpoint(Net::ip::address_v4::loopback(), 0), Outcome.SocketBindError);
        if (Outcome.SocketBindError) co_return Outcome;

        (void)NativeSocket.remote_endpoint(Outcome.RemoteEndpointError);
        Outcome.ExpectedNative = static_cast<std::error_code>(Outcome.RemoteEndpointError);
        auto Reliable = std::make_shared<Prism::Transport::Reliable>(std::move(NativeSocket));
        auto Connection = std::make_shared<Socks5::Conn<>>(Reliable);
        auto Association = std::make_shared<Socks5::UdpAssoc>(
            IoContext.get_executor(), Connection, Socks5::UdpAssocOptions{});
        const auto Activity = Association->Activity();

        Outcome.Result = co_await Association->BindAndReply();
        const auto Drain = co_await Activity->Drain();
        Outcome.DrainSucceeded = Drain.has_value();
        if (!Drain) Outcome.DrainFailure = Drain.error();
        Outcome.ActivityRetired = Activity->IsRetired();
        Outcome.ControlClosed = !Reliable->IsOpen();
        co_return Outcome;
    }

    template <typename T>
    auto RunCoroutine(Net::io_context &IoContext, Net::awaitable<T> Coroutine) -> T
    {
        std::exception_ptr Exception;
        std::optional<T> Result;
        Net::co_spawn(IoContext, std::move(Coroutine),
            [&](std::exception_ptr ErrorValue, T Value)
            {
                Exception = std::move(ErrorValue);
                if (!Exception) Result.emplace(std::move(Value));
                IoContext.stop();
            });
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);
        return std::move(*Result);
    }

    enum class AssocExceptionKind
    {
        Standard,
        Boost,
        Unknown,
    };

    struct AssocExceptionOutcome final
    {
        bool BindReplyReceived{false};
        bool RunCompleted{false};
        bool RunFailed{false};
        Failure RunFailure{Prism::Fault::Code::Blocked};
        bool ClientEndpointMatches{false};
        std::size_t DatagramCount{0U};
        bool DrainSucceeded{false};
        Failure DrainFailure{Prism::Fault::Code::Blocked};
        bool ActivityRetired{false};
        bool ClientDatagramsClosed{false};
        bool ClientControlClosed{false};
    };

    /** @brief 计算异常类型应有的稳定 typed/native 投影。 */
    [[nodiscard]] auto ExpectedAssocFailure(AssocExceptionKind Exception) -> Failure
    {
        switch (Exception)
        {
            case AssocExceptionKind::Standard:
            {
                const auto Native = std::make_error_code(std::errc::permission_denied);
                return {Prism::Fault::ToCode(Native), Native};
            }
            case AssocExceptionKind::Boost:
            {
                const auto Native = static_cast<std::error_code>(
                    boost::system::errc::make_error_code(
                        boost::system::errc::permission_denied));
                return {Prism::Fault::ToCode(Native), Native};
            }
            case AssocExceptionKind::Unknown:
                return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::Blocked};
    }

    /** @brief 在具名协程帧内投递异常，避免 coroutine lambda 借用闭包状态。 */
    auto RaiseAssocResolveException(AssocExceptionKind Exception)
        -> Net::awaitable<std::expected<Udp::endpoint, Failure>>
    {
        switch (Exception)
        {
            case AssocExceptionKind::Standard:
                throw std::system_error(std::make_error_code(std::errc::permission_denied));
            case AssocExceptionKind::Boost:
                throw boost::system::system_error(
                    boost::system::errc::make_error_code(
                        boost::system::errc::permission_denied));
            case AssocExceptionKind::Unknown:
                throw std::runtime_error("unexpected association failure");
        }
        co_return std::unexpected(Failure{Prism::Fault::Code::IoError});
    }

    /** @brief 经 UDP_ASSOCIATE 公共 Run/Drain 路径投递一次 resolver 异常。 */
    auto RunAssocExceptionScenario(
        Net::io_context& IoContext,
        AssocExceptionKind Exception,
        AssocExceptionOutcome& Outcome)
        -> Net::awaitable<void>
    {
        auto [ClientControl, ServerControl] = co_await MakeTcpPair(IoContext);
        auto Connection = std::make_shared<Socks5::Conn<>>(
            std::make_shared<Prism::Transport::Reliable>(std::move(ServerControl)));
        Socks5::UdpAssocOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds::zero();
        Options.Resolve = [Exception](const Socks5::Address &)
        {
            return RaiseAssocResolveException(Exception);
        };
        auto Association = std::make_shared<Socks5::UdpAssoc>(
            IoContext.get_executor(), std::move(Connection), std::move(Options));
        const auto Activity = Association->Activity();
        auto Completion = std::make_shared<AssociationRunCompletion>(IoContext.get_executor());
        Net::co_spawn(IoContext, Association->Run(),
            [Completion](std::exception_ptr RunException,
                         std::expected<void, Failure> Result)
            {
                Completion->Exception = std::move(RunException);
                Completion->Result = std::move(Result);
                (void)Completion->Finished.try_send(boost::system::error_code{});
            });

        std::array<std::byte, ReplySize> Reply{};
        const auto ReplyBytes = co_await Net::async_read(
            ClientControl, Net::buffer(Reply), Net::use_awaitable);
        Outcome.BindReplyReceived = ReplyBytes == Reply.size();

        Udp::socket ClientDatagrams(IoContext.get_executor());
        ClientDatagrams.open(Udp::v4());
        ClientDatagrams.bind(Udp::endpoint(Net::ip::address_v4::loopback(), 0));
        if (Outcome.BindReplyReceived)
        {
            const std::array<std::uint8_t, 19> Frame{
                0x00, 0x00, 0x00, 0x03, 0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.',
                'c', 'o', 'm', 0, 53, 0x5A};
            const auto Sent = co_await ClientDatagrams.async_send_to(Net::buffer(Frame),
                Association->BindEndpoint(), Net::use_awaitable);
            EXPECT_EQ(Sent, Frame.size());
        }
        else
        {
            Association->Close();
        }

        co_await Completion->Finished.async_receive(Net::use_awaitable);
        Outcome.RunCompleted = true;
        if (Completion->Exception) std::rethrow_exception(Completion->Exception);
        Outcome.RunFailed = !Completion->Result;
        if (!Completion->Result) Outcome.RunFailure = Completion->Result.error();
        const auto ClientUdpEndpoint = ClientDatagrams.local_endpoint();
        Outcome.ClientEndpointMatches =
            ClientUdpEndpoint.address() == ClientControl.local_endpoint().address();
        Outcome.DatagramCount = Association->DatagramCount();

        const auto Drain = co_await Activity->Drain();
        Outcome.DrainSucceeded = Drain.has_value();
        if (!Drain) Outcome.DrainFailure = Drain.error();
        Outcome.ActivityRetired = Activity->IsRetired();
        if (ClientDatagrams.is_open()) ClientDatagrams.close();
        Outcome.ClientDatagramsClosed = !ClientDatagrams.is_open();
        ClientControl.close();
        Outcome.ClientControlClosed = !ClientControl.is_open();
    }

    /** @brief 在同一 executor 上顺序退休多条关联，覆盖 worker 复用路径。 */
    auto RunAssocExceptionScenarios(
        Net::io_context& IoContext,
        std::array<AssocExceptionOutcome, 3>& Outcomes)
        -> Net::awaitable<void>
    {
        co_await RunAssocExceptionScenario(
            IoContext, AssocExceptionKind::Standard, Outcomes[0]);
        co_await RunAssocExceptionScenario(
            IoContext, AssocExceptionKind::Boost, Outcomes[1]);
        co_await RunAssocExceptionScenario(
            IoContext, AssocExceptionKind::Unknown, Outcomes[2]);
    }

    TEST(Socks5UdpAssocBindFailure,
         SetupFailureWritesOneGeneralFailureReplyAndDrains)
    {
        Net::io_context IoContext;
        const auto Outcome = RunCoroutine(IoContext, RunMemoryBindFailure(IoContext));

        ASSERT_FALSE(Outcome.Result);
        EXPECT_EQ(Outcome.Result.error().Protocol, Error::IoError);
        EXPECT_EQ(Outcome.Result.error().Transport.Code, Prism::Fault::Code::IoError);
        EXPECT_FALSE(Outcome.Result.error().Transport.Native);
        EXPECT_EQ(Outcome.Result.error().Bytes, 0U);
        EXPECT_FALSE(Outcome.WireTimedOut);
        EXPECT_FALSE(Outcome.WireFailure.Failed());
        EXPECT_EQ(Outcome.WireBytes, ReplySize);
        const std::array<std::uint8_t, ReplySize> Expected{
            0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        for (std::size_t Index = 0; Index < Expected.size(); ++Index)
        {
            EXPECT_EQ(std::to_integer<std::uint8_t>(Outcome.Wire[Index]), Expected[Index]);
        }
        EXPECT_FALSE(Outcome.ExtraTimedOut);
        EXPECT_EQ(Outcome.ExtraBytes, 0U);
        EXPECT_EQ(Outcome.ExtraFailure.Code, Prism::Fault::Code::Eof);
        EXPECT_FALSE(Outcome.ExtraFailure.Native);
        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Prism::Fault::Code::IoError);
        EXPECT_FALSE(Outcome.DrainFailure.Native);
        EXPECT_TRUE(Outcome.ActivityRetired);
        EXPECT_TRUE(Outcome.ControlClosed);
        EXPECT_TRUE(Outcome.PeerCloseSucceeded);
        EXPECT_TRUE(Outcome.PeerDrainSucceeded);
    }

    TEST(Socks5UdpAssocBindFailure,
         NativeSetupFailureSurvivesGeneralFailureWriteFailure)
    {
        Net::io_context IoContext;
        const auto Outcome = RunCoroutine(IoContext, RunNativeBindFailure(IoContext));

        ASSERT_FALSE(Outcome.SocketOpenError);
        ASSERT_FALSE(Outcome.SocketBindError);
        EXPECT_EQ(Outcome.RemoteEndpointError, Net::error::not_connected);
        EXPECT_EQ(Outcome.ExpectedNative,
                  static_cast<std::error_code>(Outcome.RemoteEndpointError));
        ASSERT_FALSE(Outcome.Result);
        EXPECT_EQ(Outcome.Result.error().Protocol, Error::IoError);
        EXPECT_EQ(Outcome.Result.error().Transport.Code,
                  Prism::Fault::ToCode(Outcome.ExpectedNative));
        EXPECT_EQ(Outcome.Result.error().Transport.Native, Outcome.ExpectedNative);
        EXPECT_EQ(Outcome.Result.error().Bytes, 0U);
        EXPECT_FALSE(Outcome.DrainSucceeded);
        EXPECT_EQ(Outcome.DrainFailure.Code, Prism::Fault::ToCode(Outcome.ExpectedNative));
        EXPECT_EQ(Outcome.DrainFailure.Native, Outcome.ExpectedNative);
        EXPECT_TRUE(Outcome.ActivityRetired);
        EXPECT_TRUE(Outcome.ControlClosed);
    }

    TEST(Socks5DeferredReply, AssociationExceptionReturnsMappedNativeFailure)
    {
        Net::io_context IoContext;
        std::array<AssocExceptionOutcome, 3> Outcomes{};
        RunCoroutine(IoContext, RunAssocExceptionScenarios(IoContext, Outcomes));
        constexpr std::array ExceptionKinds{
            AssocExceptionKind::Standard,
            AssocExceptionKind::Boost,
            AssocExceptionKind::Unknown};
        for (std::size_t Index = 0; Index < Outcomes.size(); ++Index)
        {
            const auto& Outcome = Outcomes[Index];
            const auto Expected = ExpectedAssocFailure(ExceptionKinds[Index]);
            EXPECT_TRUE(Outcome.BindReplyReceived);
            EXPECT_TRUE(Outcome.RunCompleted);
            EXPECT_TRUE(Outcome.RunFailed);
            EXPECT_EQ(Outcome.RunFailure.Code, Expected.Code);
            EXPECT_EQ(Outcome.RunFailure.Native, Expected.Native);
            EXPECT_TRUE(Outcome.ClientEndpointMatches);
            EXPECT_EQ(Outcome.DatagramCount, 1U);
            EXPECT_FALSE(Outcome.DrainSucceeded);
            EXPECT_EQ(Outcome.DrainFailure.Code, Expected.Code);
            EXPECT_EQ(Outcome.DrainFailure.Native, Expected.Native);
            EXPECT_TRUE(Outcome.ActivityRetired);
            EXPECT_TRUE(Outcome.ClientDatagramsClosed);
            EXPECT_TRUE(Outcome.ClientControlClosed);
        }
    }
}
