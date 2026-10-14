/**
 * @file QuicOwnershipTest.cpp
 * @brief 外部 QUIC server 的 owner 与 packet 注入契约。
 */

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <utility>

#include <Preview/Protocols/Quic/ConnectionLifecycle.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <TestSupport/Preview/QuicFactory.hpp>

namespace
{

    /** @brief 记录租约在延迟启动、等待完成和最终析构时的真实 owner 存续。 */
    struct LeaseObservation final
    {
        std::size_t CloseCalls{0};
        std::size_t DrainCalls{0};
        bool Destroyed{false};
    };

    class ObservedLeaseOwner final : public Preview::Contract::QuicConnectionOwner
    {
    public:
        explicit ObservedLeaseOwner(std::shared_ptr<LeaseObservation> Observation)
            : Observation_(std::move(Observation)) {}
        ~ObservedLeaseOwner() override { Observation_->Destroyed = true; }
        auto Start() -> void override {}
        [[nodiscard]] auto ReceivePacket(std::span<const std::byte>,
            const boost::asio::ip::udp::endpoint&) -> bool override { return false; }
        [[nodiscard]] auto State() const noexcept -> Preview::Contract::QuicConnectionState override
        { return {false, Observation_->CloseCalls != 0U}; }
        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> override
        {
            ++Observation_->CloseCalls;
            return {};
        }
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            ++Observation_->DrainCalls;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
    private:
        std::shared_ptr<LeaseObservation> Observation_;
    };

    class ThrowingProtocolLifecycle final : public Preview::Protocols::QuicConnectionLifecycle
    {
    public:
        explicit ThrowingProtocolLifecycle(Preview::Protocols::QuicConnectionPreparation Input)
            : Preview::Protocols::QuicConnectionLifecycle(std::move(Input))
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
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            ++DrainCalls;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }
    };

} // namespace

TEST(QuicOwnership, LeaseDrainPinsOwnerBeforeFirstScheduling)
{
    boost::asio::io_context Io;
    const auto Observation = std::make_shared<LeaseObservation>();
    auto Owner = std::make_shared<ObservedLeaseOwner>(Observation);
    const std::weak_ptr<ObservedLeaseOwner> Weak = Owner;
    auto Lease = std::make_unique<Preview::Contract::QuicConnectionLease>(Owner);
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
            std::expected<void, Preview::Fault::Failure> Result)
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
    Preview::Quic::ServerOptions Options;
    Options.Executor = Io.get_executor();
    Options.ExternalReceive = true;
    auto Owner = std::make_shared<Preview::Quic::Server>(std::move(Options));
    const std::weak_ptr<Preview::Quic::Server> Weak = Owner;
    auto Work = Owner->Drain();
    Owner.reset();
    ASSERT_FALSE(Weak.expired());
    bool Completed = false;
    std::exception_ptr Failure;
    boost::asio::co_spawn(Io, std::move(Work),
        [&Completed, &Failure](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        { Failure = std::move(Error); Completed = Result.has_value(); });
    Io.run();
    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
    EXPECT_TRUE(Weak.expired());
}

TEST(QuicOwnership, ExternalReceiveServersExposeIndependentInjectionState)
{
    using Server = Preview::Quic::Server;
    using Udp = boost::asio::ip::udp;

    boost::asio::io_context Io;
    auto Socket = std::make_shared<Udp::socket>(Io);
    std::array<std::byte, 8> Packet{};
    const auto Peer = Udp::endpoint(boost::asio::ip::address_v4::loopback(), 4433);

    Preview::Quic::ServerOptions FirstOptions;
    FirstOptions.Executor = Io.get_executor();
    FirstOptions.Socket = Socket;
    FirstOptions.Sender = Preview::Testing::Quic::MakeSender(Socket);
    FirstOptions.ExternalReceive = true;
    FirstOptions.ExpectedAlpn = "h3";
    Preview::Quic::ServerOptions SecondOptions = FirstOptions;

    auto First = std::make_shared<Server>(std::move(FirstOptions));
    auto Second = std::make_shared<Server>(std::move(SecondOptions));

    EXPECT_FALSE(First->ReceivePacket(Packet, Peer));
    EXPECT_FALSE(Second->ReceivePacket(Packet, Peer));
    First->Close();
    Second->Close();
}

TEST(QuicOwnership, ServerCallbacksAreInstanceOwnedAndCloseOnce)
{
    using Server = Preview::Quic::Server;
    using Udp = boost::asio::ip::udp;

    boost::asio::io_context Io;
    auto Socket = std::make_shared<Udp::socket>(Io);
    int FirstClosed = 0;
    int SecondClosed = 0;
    int FirstStreams = 0;
    int SecondStreams = 0;
    int FirstDatagrams = 0;
    int SecondDatagrams = 0;

    Preview::Quic::ServerOptions FirstOptions;
    FirstOptions.Executor = Io.get_executor();
    FirstOptions.Socket = Socket;
    FirstOptions.Sender = Preview::Testing::Quic::MakeSender(Socket);
    FirstOptions.ExternalReceive = true;
    FirstOptions.OnEstablished = [](std::string Alpn)
    { EXPECT_TRUE(Alpn.empty()); return std::expected<void, Preview::Fault::Failure>{}; };
    FirstOptions.OnStream = [&FirstStreams](Preview::Quic::SharedStreamProvider)
    { ++FirstStreams; return std::expected<void, Preview::Fault::Failure>{}; };
    FirstOptions.OnDatagram = [&FirstDatagrams](Preview::Quic::SharedDatagramProvider)
    { ++FirstDatagrams; return std::expected<void, Preview::Fault::Failure>{}; };
    FirstOptions.OnClosed = [&FirstClosed] { ++FirstClosed; };

    Preview::Quic::ServerOptions SecondOptions;
    SecondOptions.Executor = Io.get_executor();
    SecondOptions.Socket = Socket;
    SecondOptions.Sender = Preview::Testing::Quic::MakeSender(Socket);
    SecondOptions.ExternalReceive = true;
    SecondOptions.ExpectedAlpn = "h3";
    SecondOptions.OnEstablished = [](std::string Alpn)
    { EXPECT_TRUE(Alpn.empty()); return std::expected<void, Preview::Fault::Failure>{}; };
    SecondOptions.OnStream = [&SecondStreams](Preview::Quic::SharedStreamProvider)
    { ++SecondStreams; return std::expected<void, Preview::Fault::Failure>{}; };
    SecondOptions.OnDatagram = [&SecondDatagrams](Preview::Quic::SharedDatagramProvider)
    { ++SecondDatagrams; return std::expected<void, Preview::Fault::Failure>{}; };
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
    Preview::Quic::ServerOptions Options;
    Options.OnUnidirectional = [](Preview::Quic::SharedStreamProvider)
    { return std::expected<void, Preview::Fault::Failure>{}; };
    Options.OnExporter = [](Preview::Quic::ServerOptions::KeyingMaterialExporter Exporter)
    {
        EXPECT_TRUE(static_cast<bool>(Exporter));
        return std::expected<void, Preview::Fault::Failure>{};
    };

    EXPECT_TRUE(static_cast<bool>(Options.OnUnidirectional));
    EXPECT_TRUE(static_cast<bool>(Options.OnExporter));
}

TEST(QuicOwnership, ProtocolCloseFailureStillAttemptsProtocolDrain)
{
    boost::asio::io_context Io;
    auto Owner = std::make_shared<ThrowingProtocolLifecycle>(
        Preview::Protocols::QuicConnectionPreparation{
            Preview::Contract::QuicListenerResources{Io.get_executor(), {}, {}},
            Preview::Contract::QuicAcceptRequest{}, {}, {}});

    const auto CloseRequest = Owner->RequestClose();
    ASSERT_TRUE(CloseRequest);
    Io.run();

    EXPECT_EQ(Owner->CloseCalls, 1U);
    EXPECT_EQ(Owner->DrainCalls, 1U);

    Io.restart();
    Preview::Fault::Failure DrainFailure;
    std::exception_ptr DrainException;
    boost::asio::co_spawn(Io, Owner->Drain(),
        [&DrainFailure, &DrainException](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            DrainException = std::move(Error);
            if (!Result) DrainFailure = Result.error();
        });
    Io.run();
    EXPECT_FALSE(DrainException);
    EXPECT_EQ(DrainFailure.Code, Preview::Fault::Code::Blocked);
    EXPECT_EQ(Owner->CloseCalls, 1U);
    EXPECT_EQ(Owner->DrainCalls, 1U);
}
