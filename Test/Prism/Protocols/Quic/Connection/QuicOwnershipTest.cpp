/**
 * @file QuicOwnershipTest.cpp
 * @brief 外部 QUIC server 的 owner 与 packet 注入契约。
 */

#include <gtest/gtest.h>

#include <boost/asio/error.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <ngtcp2/ngtcp2.h>
#include <Prism/Protocols/Quic/Detail/NativeConnectionStreamAdmission.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <Prism/Protocols/Quic/QuicConnectionLifecycle.hpp>
#include <TestSupport/Prism/QuicFactory.hpp>

namespace
{

    /** @brief 记录租约在延迟启动、等待完成和最终析构时的真实 owner 存续。 */
    struct LeaseObservation final
    {
        std::size_t CloseCalls{0};
        std::size_t DrainCalls{0};
        bool Destroyed{false};
    };

    class ObservedLeaseOwner final : public Prism::Contract::QuicConnectionOwner
    {
    public:
        explicit ObservedLeaseOwner(std::shared_ptr<LeaseObservation> Observation)
            : Observation_(std::move(Observation)) {}
        ~ObservedLeaseOwner() override { Observation_->Destroyed = true; }
        auto Start() -> void override {}
        [[nodiscard]] auto ReceivePacket(std::span<const std::byte>,
            const boost::asio::ip::udp::endpoint&) -> bool override { return false; }
        [[nodiscard]] auto State() const noexcept -> Prism::Contract::QuicConnectionState override
        { return {false, Observation_->CloseCalls != 0U}; }
        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Prism::Fault::Failure> override
        {
            ++Observation_->CloseCalls;
            return {};
        }
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            ++Observation_->DrainCalls;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
    private:
        std::shared_ptr<LeaseObservation> Observation_;
    };

    class ThrowingProtocolLifecycle final : public Prism::Protocols::QuicConnectionLifecycle
    {
    public:
        explicit ThrowingProtocolLifecycle(Prism::Protocols::QuicConnectionPreparation Input)
            : Prism::Protocols::QuicConnectionLifecycle(std::move(Input))
        {
            Install(Options());
        }

        std::size_t CloseCalls{0};
        std::size_t DrainCalls{0};

    protected:
        auto CloseProtocol() -> void override
        {
            ++CloseCalls;
            throw std::runtime_error("protocol close fixture failure");
        }

        [[nodiscard]] auto DrainProtocol()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            ++DrainCalls;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
    };

    struct TerminalBufferedReadObservation final
    {
        std::array<std::byte, 4> FirstBuffer{};
        std::size_t FirstBytes{0};
        std::size_t SecondBytes{0};
        std::size_t ThirdBytes{0};
        std::error_code FirstError{};
        std::error_code SecondError{};
        std::error_code ThirdError{};
        std::expected<void, Prism::Fault::Failure> CloseResult{};
        std::expected<void, Prism::Fault::Failure> DrainResult{};
    };

    struct TerminalBufferedDrainObservation final
    {
        bool LateReadRejected{false};
        bool DrainCompletedWhileReadReserved{false};
        bool DrainCompleted{false};
        std::exception_ptr DrainException{};
        std::expected<void, Prism::Fault::Failure> DrainResult{};
    };

    auto RunTerminalBufferedRead(
        std::shared_ptr<Prism::Quic::Detail::NativeStream> Stream,
        TerminalBufferedReadObservation &Observation)
        -> boost::asio::awaitable<void>
    {
        Observation.FirstBytes = co_await Stream->Read(
            std::span<std::byte>{}, Observation.FirstError);
        std::array<std::byte, 2> Buffered{};
        Observation.SecondBytes = co_await Stream->Read(
            Buffered, Observation.SecondError);
        std::copy(Buffered.begin(), Buffered.end(),
            Observation.FirstBuffer.begin());
        std::array<std::byte, 1> EofBuffer{};
        Observation.ThirdBytes = co_await Stream->Read(
            EofBuffer, Observation.ThirdError);
        Observation.CloseResult = Stream->Close();
        const auto Activity = Stream->Activity();
        Activity->Seal();
        Observation.DrainResult = co_await Activity->Drain();
    }

    auto RunTerminalBufferedDrainBarrier(
        std::shared_ptr<Prism::Quic::Detail::NativeStream> Stream,
        TerminalBufferedDrainObservation &Observation)
        -> boost::asio::awaitable<void>
    {
        const auto Executor = co_await boost::asio::this_coro::executor;
        const auto Activity = std::static_pointer_cast<
            Prism::Quic::Detail::NativeStreamActivity>(Stream->Activity());
        {
            auto ReadLease = Activity->BeginBufferedRead(Stream);
            if (!ReadLease)
            {
                throw std::runtime_error("terminal buffered read lease was rejected");
            }
            boost::asio::co_spawn(Executor, Activity->Drain(),
                [&Observation](std::exception_ptr Error,
                    std::expected<void, Prism::Fault::Failure> Result)
                {
                    Observation.DrainException = std::move(Error);
                    Observation.DrainResult = std::move(Result);
                    Observation.DrainCompleted = true;
                });
            co_await boost::asio::post(Executor, boost::asio::use_awaitable);
            Observation.LateReadRejected =
                !Activity->BeginBufferedRead(Stream).has_value();
            Observation.DrainCompletedWhileReadReserved = Observation.DrainCompleted;
        }
        while (!Observation.DrainCompleted)
        {
            co_await boost::asio::post(Executor, boost::asio::use_awaitable);
        }
    }

    auto RunReadAfterTerminalClose(
        std::shared_ptr<Prism::Quic::Detail::NativeStream> Stream,
        TerminalBufferedReadObservation &Observation)
        -> boost::asio::awaitable<void>
    {
        Observation.FirstBytes = co_await Stream->Read(
            Observation.FirstBuffer, Observation.FirstError);
        const auto Activity = Stream->Activity();
        Observation.DrainResult = co_await Activity->Drain();
    }

} // namespace

TEST(QuicOwnership, LeaseDrainPinsOwnerBeforeFirstScheduling)
{
    boost::asio::io_context Io;
    const auto Observation = std::make_shared<LeaseObservation>();
    auto Owner = std::make_shared<ObservedLeaseOwner>(Observation);
    const std::weak_ptr<ObservedLeaseOwner> Weak = Owner;
    auto Lease = std::make_unique<Prism::Contract::QuicConnectionLease>(Owner);
    auto Work = Lease->Drain();
    Owner.reset();
    Lease.reset();
    ASSERT_FALSE(Weak.expired());
    EXPECT_FALSE(Observation->Destroyed);
    EXPECT_EQ(Observation->CloseCalls, 1U);
    EXPECT_EQ(Observation->DrainCalls, 0U);
    bool Completed = false;
    std::exception_ptr Failure;
    boost::asio::co_spawn(Io, std::move(Work),
        [&Completed, &Failure](std::exception_ptr Error,
            std::expected<void, Prism::Fault::Failure> Result)
        { Failure = std::move(Error); Completed = Result.has_value(); });
    Io.run();
    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
    EXPECT_EQ(Observation->DrainCalls, 1U);
    EXPECT_TRUE(Observation->Destroyed);
    EXPECT_TRUE(Weak.expired());
}

TEST(QuicOwnership, NativeDrainPinsFacadeBeforeFirstScheduling)
{
    boost::asio::io_context Io;
    Prism::Quic::ServerOptions Options;
    Options.Executor = Io.get_executor();
    Options.ExternalReceive = true;
    auto Owner = std::make_shared<Prism::Quic::Server>(std::move(Options));
    const std::weak_ptr<Prism::Quic::Server> Weak = Owner;
    auto Work = Owner->Drain();
    Owner.reset();
    ASSERT_FALSE(Weak.expired());
    bool Completed = false;
    std::exception_ptr Failure;
    boost::asio::co_spawn(Io, std::move(Work),
        [&Completed, &Failure](std::exception_ptr Error,
            std::expected<void, Prism::Fault::Failure> Result)
        { Failure = std::move(Error); Completed = Result.has_value(); });
    Io.run();
    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
    EXPECT_TRUE(Weak.expired());
}

TEST(QuicOwnership, ClientDrainPinsConnectionBeforeFirstScheduling)
{
    boost::asio::io_context Io;
    Prism::Quic::ClientOptions Options;
    Options.Executor = Io.get_executor();
    std::optional<Prism::Quic::Client> Owner;
    Owner.emplace(Options);
    auto Work = Owner->Drain();
    Owner.reset();
    Owner.emplace(Options);

    std::exception_ptr Failure;
    auto RunDrain = [&]() -> boost::asio::awaitable<void>
    {
        const auto Result = co_await std::move(Work);
        EXPECT_TRUE(Result);
        EXPECT_FALSE(Owner->Health().Closed);
        Owner->Close();
        const auto Cleanup = co_await Owner->Drain();
        EXPECT_TRUE(Cleanup);
    };
    boost::asio::co_spawn(Io, RunDrain(),
        [&Failure](std::exception_ptr Error)
        {
            Failure = std::move(Error);
        });
    Io.run();
    EXPECT_FALSE(Failure);
}

TEST(QuicOwnership, GatewayDrainPinsConnectionBeforeFirstScheduling)
{
    boost::asio::io_context Io;
    Prism::Quic::ServerOptions Options;
    Options.Executor = Io.get_executor();
    Options.ExternalReceive = true;
    std::optional<Prism::Quic::Gateway> Owner;
    Owner.emplace(std::move(Options));
    auto Server = Owner->Connection();
    const std::weak_ptr<Prism::Quic::Server> WeakServer = Server;
    auto Work = Owner->Drain();
    Server.reset();
    Owner.reset();
    ASSERT_FALSE(WeakServer.expired());

    bool Completed = false;
    std::exception_ptr Failure;
    boost::asio::co_spawn(Io, std::move(Work),
        [&Completed, &Failure](std::exception_ptr Error,
            std::expected<void, Prism::Fault::Failure> Result)
        {
            Failure = std::move(Error);
            Completed = Result.has_value();
        });
    Io.run();
    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
    EXPECT_TRUE(WeakServer.expired());
}

TEST(QuicOwnership, NgTcp2ErrorsCompareAcrossAdmissionAndShutdown)
{
    const auto Admission = Prism::Quic::Detail::NgTcp2Failure(NGTCP2_ERR_NOBUF);
    const auto Shutdown = Prism::Quic::Detail::NgTcp2IoFailure(NGTCP2_ERR_NOBUF);

    EXPECT_EQ(Admission.Code, Prism::Fault::Code::ResourceUnavailable);
    EXPECT_EQ(Shutdown.Code, Prism::Fault::Code::IoError);
    ASSERT_TRUE(Admission.Native);
    ASSERT_TRUE(Shutdown.Native);
    EXPECT_EQ(Admission.Native, Shutdown.Native);
    const auto StreamBlocked = Prism::Quic::Detail::NgTcp2Failure(
        NGTCP2_ERR_STREAM_ID_BLOCKED);
    EXPECT_EQ(StreamBlocked.Code, Prism::Fault::Code::WouldBlock);
    EXPECT_EQ(StreamBlocked.Native.category(), Shutdown.Native.category());
}

TEST(QuicOwnership, NativeTerminalReadDrainsBufferedBytesBeforeFin)
{
    boost::asio::io_context Io;
    auto State = std::make_shared<Prism::Quic::Detail::StreamState>(
        Io.get_executor(), 4);
    State->Received.push_back({std::byte{0x41}, std::byte{0x42}});
    State->PeerFin = true;
    State->Closed = true;
    State->NativeTerminal.store(true, std::memory_order_release);
    auto Stream = std::make_shared<Prism::Quic::Detail::NativeStream>(
        std::weak_ptr<Prism::Quic::Detail::NativeConnection>{}, State);

    TerminalBufferedReadObservation Observation;
    std::exception_ptr Exception;
    boost::asio::co_spawn(Io, RunTerminalBufferedRead(Stream, Observation),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();

    EXPECT_FALSE(Exception);
    EXPECT_EQ(Observation.FirstBytes, 0U);
    EXPECT_FALSE(Observation.FirstError);
    EXPECT_EQ(Observation.SecondBytes, 2U);
    EXPECT_EQ(Observation.FirstBuffer[0], std::byte{0x41});
    EXPECT_EQ(Observation.FirstBuffer[1], std::byte{0x42});
    EXPECT_FALSE(Observation.SecondError);
    EXPECT_EQ(Observation.ThirdBytes, 0U);
    EXPECT_EQ(Observation.ThirdError, static_cast<std::error_code>(
        boost::asio::error::make_error_code(boost::asio::error::eof)));
    EXPECT_TRUE(Observation.CloseResult.has_value());
    ASSERT_TRUE(Observation.DrainResult.has_value());
    EXPECT_TRUE(Stream->Activity()->IsRetired());
}

TEST(QuicOwnership, NativeTerminalReadDrainsBufferedBytesBeforeReset)
{
    boost::asio::io_context Io;
    auto State = std::make_shared<Prism::Quic::Detail::StreamState>(
        Io.get_executor(), 8);
    State->Received.push_back({std::byte{0x51}, std::byte{0x52}});
    State->PeerReset = true;
    State->PeerReadFailure = std::make_error_code(std::errc::connection_reset);
    State->Closed = true;
    State->NativeTerminal.store(true, std::memory_order_release);
    auto Stream = std::make_shared<Prism::Quic::Detail::NativeStream>(
        std::weak_ptr<Prism::Quic::Detail::NativeConnection>{}, State);

    TerminalBufferedReadObservation Observation;
    std::exception_ptr Exception;
    boost::asio::co_spawn(Io, RunTerminalBufferedRead(Stream, Observation),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();

    EXPECT_FALSE(Exception);
    EXPECT_EQ(Observation.FirstBytes, 0U);
    EXPECT_FALSE(Observation.FirstError);
    EXPECT_EQ(Observation.SecondBytes, 2U);
    EXPECT_EQ(Observation.FirstBuffer[0], std::byte{0x51});
    EXPECT_EQ(Observation.FirstBuffer[1], std::byte{0x52});
    EXPECT_FALSE(Observation.SecondError);
    EXPECT_EQ(Observation.ThirdBytes, 0U);
    EXPECT_EQ(Observation.ThirdError, std::make_error_code(std::errc::connection_reset));
    EXPECT_TRUE(Observation.CloseResult.has_value());
    ASSERT_TRUE(Observation.DrainResult.has_value());
    EXPECT_TRUE(Stream->Activity()->IsRetired());
}

TEST(QuicOwnership, TerminalBufferedReadLeaseBlocksDrainAndDrainRejectsNewReads)
{
    boost::asio::io_context Io;
    const auto Executor = boost::asio::make_strand(Io);
    auto State = std::make_shared<Prism::Quic::Detail::StreamState>(
        Executor, 12);
    State->Closed = true;
    State->PeerFin = true;
    State->NativeTerminal.store(true, std::memory_order_release);
    auto Stream = std::make_shared<Prism::Quic::Detail::NativeStream>(
        std::weak_ptr<Prism::Quic::Detail::NativeConnection>{}, State);

    TerminalBufferedDrainObservation Observation;
    std::exception_ptr Exception;
    boost::asio::co_spawn(Executor, RunTerminalBufferedDrainBarrier(Stream, Observation),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();

    EXPECT_FALSE(Exception);
    EXPECT_TRUE(Observation.LateReadRejected);
    EXPECT_FALSE(Observation.DrainCompletedWhileReadReserved);
    EXPECT_TRUE(Observation.DrainCompleted);
    EXPECT_FALSE(Observation.DrainException);
    ASSERT_TRUE(Observation.DrainResult.has_value());
    EXPECT_TRUE(Stream->Activity()->IsRetired());
}

TEST(QuicOwnership, TerminalCloseRejectsNewBufferedReads)
{
    boost::asio::io_context Io;
    auto State = std::make_shared<Prism::Quic::Detail::StreamState>(
        Io.get_executor(), 16);
    State->Received.push_back({std::byte{0x61}, std::byte{0x62}});
    State->Closed = true;
    State->PeerFin = true;
    State->NativeTerminal.store(true, std::memory_order_release);
    auto Stream = std::make_shared<Prism::Quic::Detail::NativeStream>(
        std::weak_ptr<Prism::Quic::Detail::NativeConnection>{}, State);

    const auto CloseResult = Stream->Close();
    TerminalBufferedReadObservation Observation;
    std::exception_ptr Exception;
    boost::asio::co_spawn(Io, RunReadAfterTerminalClose(Stream, Observation),
        [&Exception](std::exception_ptr Error) { Exception = std::move(Error); });
    Io.run();

    EXPECT_TRUE(CloseResult.has_value());
    EXPECT_FALSE(Exception);
    ASSERT_EQ(Observation.FirstBytes, 0U);
    EXPECT_EQ(Observation.FirstError, Prism::Fault::ToNative(
        Prism::Fault::Failure{Prism::Fault::Code::Canceled}));
    ASSERT_FALSE(State->Received.empty());
    EXPECT_EQ(State->Received.front().size(), 2U);
    ASSERT_TRUE(Observation.DrainResult.has_value());
    EXPECT_TRUE(Stream->Activity()->IsRetired());
}

TEST(QuicOwnership, ExternalReceiveServersExposeIndependentInjectionState)
{
    using Server = Prism::Quic::Server;
    using Udp = boost::asio::ip::udp;

    boost::asio::io_context Io;
    auto Socket = std::make_shared<Udp::socket>(Io);
    std::array<std::byte, 8> Packet{};
    const auto Peer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4433);

    Prism::Quic::ServerOptions FirstOptions;
    FirstOptions.Executor = Io.get_executor();
    FirstOptions.Socket = Socket;
    FirstOptions.Sender = Prism::Testing::Quic::MakeSender(Socket);
    FirstOptions.ExternalReceive = true;
    FirstOptions.ExpectedAlpn = "h3";
    Prism::Quic::ServerOptions SecondOptions = FirstOptions;

    auto First = std::make_shared<Server>(std::move(FirstOptions));
    auto Second = std::make_shared<Server>(std::move(SecondOptions));

    EXPECT_FALSE(First->ReceivePacket(Packet, Peer));
    EXPECT_FALSE(Second->ReceivePacket(Packet, Peer));
    First->Close();
    Second->Close();
}

TEST(QuicOwnership, ServerCallbacksAreInstanceOwnedAndCloseOnce)
{
    using Server = Prism::Quic::Server;
    using Udp = boost::asio::ip::udp;

    boost::asio::io_context Io;
    auto Socket = std::make_shared<Udp::socket>(Io);
    int FirstClosed = 0;
    int SecondClosed = 0;
    int FirstStreams = 0;
    int SecondStreams = 0;
    int FirstDatagrams = 0;
    int SecondDatagrams = 0;

    Prism::Quic::ServerOptions FirstOptions;
    FirstOptions.Executor = Io.get_executor();
    FirstOptions.Socket = Socket;
    FirstOptions.Sender = Prism::Testing::Quic::MakeSender(Socket);
    FirstOptions.ExternalReceive = true;
    FirstOptions.OnEstablished = [](std::string Alpn)
    { EXPECT_TRUE(Alpn.empty()); return std::expected<void, Prism::Fault::Failure>{}; };
    FirstOptions.OnStream = [&FirstStreams](Prism::Quic::SharedStreamProvider)
    { ++FirstStreams; return std::expected<void, Prism::Fault::Failure>{}; };
    FirstOptions.OnDatagram = [&FirstDatagrams](Prism::Quic::SharedDatagramProvider)
    { ++FirstDatagrams; return std::expected<void, Prism::Fault::Failure>{}; };
    FirstOptions.OnClosed = [&FirstClosed] { ++FirstClosed; };

    Prism::Quic::ServerOptions SecondOptions;
    SecondOptions.Executor = Io.get_executor();
    SecondOptions.Socket = Socket;
    SecondOptions.Sender = Prism::Testing::Quic::MakeSender(Socket);
    SecondOptions.ExternalReceive = true;
    SecondOptions.ExpectedAlpn = "h3";
    SecondOptions.OnEstablished = [](std::string Alpn)
    { EXPECT_TRUE(Alpn.empty()); return std::expected<void, Prism::Fault::Failure>{}; };
    SecondOptions.OnStream = [&SecondStreams](Prism::Quic::SharedStreamProvider)
    { ++SecondStreams; return std::expected<void, Prism::Fault::Failure>{}; };
    SecondOptions.OnDatagram = [&SecondDatagrams](Prism::Quic::SharedDatagramProvider)
    { ++SecondDatagrams; return std::expected<void, Prism::Fault::Failure>{}; };
    SecondOptions.OnClosed = [&SecondClosed] { ++SecondClosed; };

    auto First = std::make_shared<Server>(std::move(FirstOptions));
    auto Second = std::make_shared<Server>(std::move(SecondOptions));
    First->Start();
    Second->Start();
    First->Close();
    Second->Close();
    Io.run();

    EXPECT_EQ(FirstClosed, 1);
    EXPECT_EQ(SecondClosed, 1);
    EXPECT_EQ(FirstStreams, 0);
    EXPECT_EQ(SecondStreams, 0);
    EXPECT_EQ(FirstDatagrams, 0);
    EXPECT_EQ(SecondDatagrams, 0);
}

TEST(QuicOwnership, ServerOptionsExposeTuicAuthenticationHooks)
{
    Prism::Quic::ServerOptions Options;
    Options.OnUnidirectional = [](Prism::Quic::SharedStreamProvider)
    { return std::expected<void, Prism::Fault::Failure>{}; };
    Options.OnExporter = [](Prism::Quic::ServerOptions::KeyingMaterialExporter Exporter)
    {
        EXPECT_TRUE(static_cast<bool>(Exporter));
        return std::expected<void, Prism::Fault::Failure>{};
    };

    EXPECT_TRUE(static_cast<bool>(Options.OnUnidirectional));
    EXPECT_TRUE(static_cast<bool>(Options.OnExporter));
}

TEST(QuicOwnership, ProtocolCloseFailureStillAttemptsProtocolDrain)
{
    boost::asio::io_context Io;
    auto Owner = std::make_shared<ThrowingProtocolLifecycle>(
        Prism::Protocols::QuicConnectionPreparation{
            Prism::Contract::QuicListenerResources{Io.get_executor(), {}, {}},
            Prism::Contract::QuicAcceptRequest{}, {}, {}});

    const auto CloseRequest = Owner->RequestClose();
    ASSERT_TRUE(CloseRequest);
    Io.run();

    EXPECT_EQ(Owner->CloseCalls, 1U);
    EXPECT_EQ(Owner->DrainCalls, 1U);

    Io.restart();
    Prism::Fault::Failure DrainFailure;
    std::exception_ptr DrainException;
    boost::asio::co_spawn(Io, Owner->Drain(),
        [&DrainFailure, &DrainException](std::exception_ptr Error,
            std::expected<void, Prism::Fault::Failure> Result)
        {
            DrainException = std::move(Error);
            if (!Result) DrainFailure = Result.error();
        });
    Io.run();
    EXPECT_FALSE(DrainException);
    EXPECT_EQ(DrainFailure.Code, Prism::Fault::Code::Blocked);
    EXPECT_EQ(Owner->CloseCalls, 1U);
    EXPECT_EQ(Owner->DrainCalls, 1U);
}
