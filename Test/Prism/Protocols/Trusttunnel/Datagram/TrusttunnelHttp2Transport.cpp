#include <expected>
#include <array>
#include <system_error>
#include <vector>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/TlsStream.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedCarrierActivity.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/AcceptedClientTransport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Client.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/CarrierCloseReceipt.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <memory>
#include <optional>

#include "TrustTunnelSupport.hpp"

namespace
{
    using Transport = Trusttunnel::Detail::Http2Transport;
    using WriteResult = std::expected<void, Prism::Fault::Failure>;

    auto NoopHttp2Write(std::int32_t, std::span<const std::byte>)
        -> Net::awaitable<WriteResult>
    {
        co_return WriteResult{};
    }

    auto ReadQueuedData(
        const std::shared_ptr<Transport> &Stream,
        std::size_t &Blocks,
        std::size_t &Eof) -> Net::awaitable<void>
    {
        std::array<std::byte, 1> Buffer{};
        while (Blocks < 64)
        {
            const auto Part = co_await Stream->ReadSome(Buffer);
            EXPECT_FALSE(Part.Failure.Failed());
            EXPECT_EQ(Part.Bytes, 1u);
            if (Part.Failure.Failed() || Part.Bytes != 1u) co_return;
            ++Blocks;
        }
        const auto End = co_await Stream->ReadSome(Buffer);
        Eof = End.Bytes;
        EXPECT_FALSE(End.Failure.Failed());
    }

    struct OrderedWrite final
    {
        std::string *Order;

        auto operator()(std::int32_t, std::span<const std::byte> Data) const
            -> Net::awaitable<WriteResult>
        {
            Order->append(reinterpret_cast<const char *>(Data.data()), Data.size());
            co_return WriteResult{};
        }
    };

    class TrusttunnelActivityProbe final : public Prism::Contract::CarrierActivity
    {
    public:
        explicit TrusttunnelActivityProbe(Net::any_io_executor Executor)
            : Executor_(std::move(Executor))
        {
        }

        auto Seal() noexcept -> void override { Sealed_ = true; }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Executor_; }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_; }
        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (!Sealed_)
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            Retired_ = true;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

    private:
        Net::any_io_executor Executor_;
        bool Sealed_{false};
        bool Retired_{false};
    };

    class TrusttunnelCloseReceiptProbe final
        : public Prism::Contract::CarrierCloseReceipt
    {
    public:
        auto ConfirmExternalClose() noexcept -> void override { Confirmed = true; }
        auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            if (!Confirmed)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        bool Confirmed{false};
    };

    struct OrderedFinish final
    {
        bool *Finished;

        auto operator()(std::int32_t) const -> Net::awaitable<WriteResult>
        {
            *Finished = true;
            co_return WriteResult{};
        }
    };

    auto WriteThenFinish(const std::shared_ptr<Transport> &Stream)
        -> Net::awaitable<void>
    {
        const std::array<std::byte, 1> Byte{std::byte{'A'}};
        const auto Written = co_await Stream->WriteSome(Byte);
        EXPECT_EQ(Written.Bytes, 1u);
        EXPECT_FALSE(Written.Failure.Failed());
        const auto FinishResult = co_await Stream->WriteShutdown();
        EXPECT_TRUE(FinishResult);
    }

    auto ReadLargePayload(
        const std::shared_ptr<Transport> &Stream,
        std::vector<std::byte> &Received) -> Net::awaitable<void>
    {
        std::array<std::byte, 4096> Buffer{};
        while (true)
        {
            const auto Part = co_await Stream->ReadSome(Buffer);
            EXPECT_FALSE(Part.Failure.Failed());
            if (Part.Bytes > Buffer.size()) co_return;
            const auto End = Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes);
            Received.insert(Received.end(), Buffer.begin(), End);
            if (Part.Failure.Failed() || Part.Bytes == 0) co_return;
        }
    }

    struct ReadTerminalObservation final
    {
        std::vector<std::byte> Data;
        std::array<std::size_t, 6> Counts{};
        std::array<Prism::Fault::Failure, 2> Terminal{};
    };

    auto ReadQueuedDataAndRepeatTerminal(
        const std::shared_ptr<Transport> &Stream,
        const std::shared_ptr<ReadTerminalObservation> &Observation) -> Net::awaitable<void>
    {
        std::array<std::byte, 2> Buffer{};
        for (std::size_t Index = 0; Index < Observation->Counts.size(); ++Index)
        {
            const auto Part = co_await Stream->ReadSome(Buffer);
            EXPECT_LE(Part.Bytes, Buffer.size());
            if (Part.Bytes > Buffer.size()) co_return;
            Observation->Counts[Index] = Part.Bytes;
            Observation->Data.insert(
                Observation->Data.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Index >= 4) Observation->Terminal[Index - 4] = Part.Failure;
            if (Index < 4) EXPECT_FALSE(Part.Failure.Failed());
        }
    }
}

TEST(TrusttunnelHttp2Transport, EofSurvivesFullReceiveQueue)
{
    Net::io_context IoContext;
    auto Stream = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    const std::array<std::byte, 1> Byte{std::byte{'x'}};
    for (std::size_t Index = 0; Index < 64; ++Index)
    {
        Stream->Push(Byte);
    }
    Stream->NotifyEof();

    std::size_t Blocks = 0;
    std::size_t Eof = 1;
    RunCoro(IoContext, ReadQueuedData(Stream, Blocks, Eof));
    EXPECT_EQ(Blocks, 64u);
    EXPECT_EQ(Eof, 0u);
}

TEST(TrusttunnelHttp2Transport, FinishIsQueuedAfterData)
{
    Net::io_context IoContext;
    std::string Order;
    bool Finished = false;
    auto Stream = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{OrderedWrite{&Order}},
        Transport::FinishCb{OrderedFinish{&Finished}}, Transport::CloseCb{}});
    Stream->BindStream(1);
    RunCoro(IoContext, WriteThenFinish(Stream));
    EXPECT_EQ(Order, "A");
    EXPECT_TRUE(Finished);
}

TEST(TrusttunnelHttp2Transport, LargeInboundDataSurvivesWindowRefresh)
{
    Net::io_context IoContext;
    auto Stream = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    const std::vector<std::byte> Payload(128 * 1024, std::byte{0x4C});
    Stream->Push(Payload);
    Stream->NotifyEof();

    std::vector<std::byte> Received;
    RunCoro(IoContext, ReadLargePayload(Stream, Received));
    EXPECT_EQ(Received, Payload);
}

TEST(TrusttunnelHttp2Transport, DeliversQueuedDataBeforeStickyNativeReadFailure)
{
    Net::io_context IoContext;
    auto Stream = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    const std::array<std::byte, 3> First{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    const std::array<std::byte, 4> Second{
        std::byte{'d'}, std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Failure = Prism::Fault::FromNative(Native);
    Stream->Push(First);
    Stream->Push(Second);
    Stream->NotifyReadTerminal(Failure);
    const auto Observation = std::make_shared<ReadTerminalObservation>();

    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Stream, Observation));

    const std::array<std::byte, 7> Expected{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
        std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Expected.begin(), Expected.end()));
    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 1U, 2U, 2U, 0U, 0U}));
    EXPECT_EQ(Observation->Terminal[0].Code, Failure.Code);
    EXPECT_EQ(Observation->Terminal[0].Native, Native);
    EXPECT_EQ(Observation->Terminal[1].Code, Failure.Code);
    EXPECT_EQ(Observation->Terminal[1].Native, Native);
    IoContext.restart();
    const auto Retired = Stream->Close();
    ASSERT_TRUE(Retired) << (Retired ? 0U : static_cast<unsigned>(Retired.error().Code));
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Stream->Activity()->Drain();
    }());
    ASSERT_TRUE(Drain) << (Drain ? 0U : static_cast<unsigned>(Drain.error().Code));
}

TEST(TrusttunnelHttp2Transport, DeliversQueuedDataBeforeStickyCanceledRead)
{
    Net::io_context IoContext;
    auto Stream = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    const std::array<std::byte, 3> First{std::byte{'x'}, std::byte{'y'}, std::byte{'z'}};
    const std::array<std::byte, 4> Second{
        std::byte{'1'}, std::byte{'2'}, std::byte{'3'}, std::byte{'4'}};
    const auto Native = std::make_error_code(std::errc::operation_canceled);
    const auto Failure = Prism::Fault::FromNative(Native);
    Stream->Push(First);
    Stream->Push(Second);
    Stream->NotifyReadTerminal(Failure);
    const auto Observation = std::make_shared<ReadTerminalObservation>();

    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Stream, Observation));

    const std::array<std::byte, 7> Expected{
        std::byte{'x'}, std::byte{'y'}, std::byte{'z'}, std::byte{'1'},
        std::byte{'2'}, std::byte{'3'}, std::byte{'4'}};
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Expected.begin(), Expected.end()));
    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 1U, 2U, 2U, 0U, 0U}));
    EXPECT_EQ(Observation->Terminal[0].Code, Prism::Fault::Code::Canceled);
    EXPECT_EQ(Observation->Terminal[0].Native, Native);
    EXPECT_EQ(Observation->Terminal[1].Code, Prism::Fault::Code::Canceled);
    EXPECT_EQ(Observation->Terminal[1].Native, Native);
    IoContext.restart();
    const auto Closed = Stream->Close();
    ASSERT_TRUE(Closed) << (Closed ? 0U : static_cast<unsigned>(Closed.error().Code));
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Stream->Activity()->Drain();
    }());
    ASSERT_TRUE(Drain) << (Drain ? 0U : static_cast<unsigned>(Drain.error().Code));
}

TEST(TrusttunnelHttp2Transport, DeliversQueuedDataBeforeStickyReadEof)
{
    Net::io_context IoContext;
    auto Stream = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    const std::array<std::byte, 3> First{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    const std::array<std::byte, 4> Second{
        std::byte{'d'}, std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    const Prism::Fault::Failure Failure{Prism::Fault::Code::Eof};
    Stream->Push(First);
    Stream->Push(Second);
    Stream->NotifyReadTerminal(Failure);
    const auto Observation = std::make_shared<ReadTerminalObservation>();

    RunCoro(IoContext, ReadQueuedDataAndRepeatTerminal(Stream, Observation));

    EXPECT_EQ(Observation->Counts, (std::array<std::size_t, 6>{2U, 1U, 2U, 2U, 0U, 0U}));
    EXPECT_EQ(Observation->Terminal[0].Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Observation->Terminal[1].Code, Prism::Fault::Code::Eof);
    const std::array<std::byte, 7> Expected{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'},
        std::byte{'e'}, std::byte{'f'}, std::byte{'g'}};
    EXPECT_EQ(Observation->Data, std::vector<std::byte>(Expected.begin(), Expected.end()));
    IoContext.restart();
    const auto Closed = Stream->Close();
    ASSERT_TRUE(Closed) << (Closed ? 0U : static_cast<unsigned>(Closed.error().Code));
    IoContext.restart();
    std::expected<void, Prism::Fault::Failure> Drain;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        Drain = co_await Stream->Activity()->Drain();
    }());
    ASSERT_TRUE(Drain) << (Drain ? 0U : static_cast<unsigned>(Drain.error().Code));
}
namespace
{
    using TlsStreamResult = std::expected<
        Prism::Transport::Encrypted::SharedStream,
        Prism::Fault::Failure>;

    struct TlsSetupFailureRequest final
    {
        Prism::SharedTransmission Raw;
        Ssl::context *Context;
        std::optional<TlsStreamResult> *Result;
        std::optional<Prism::Fault::Failure> *AdmissionFailure;
    };

    auto RunTlsSetupFailure(TlsSetupFailureRequest Request) -> Net::awaitable<void>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared)
        {
            Request.AdmissionFailure->emplace(Prepared.error());
            co_return;
        }
        auto Admission = std::move(*Prepared);
        *Request.Result = co_await Trusttunnel::Detail::ConnectHttp2Tls(
            Trusttunnel::Detail::Http2TlsClientRequest{
                .Raw = std::move(Request.Raw),
                .SslContext = *Request.Context,
                .ServerName = "example.com",
                .Bytes = {}},
            Admission);
    }
}

TEST(TrusttunnelHttp2Transport, AcceptedOwnerPreservesFailureAndReportsPhysicalRetirement)
{
    Net::io_context IoContext;
    const auto Native = std::make_error_code(std::errc::broken_pipe);
    auto Lifecycle = std::make_shared<Trusttunnel::Detail::CarrierLifecycle>(
        IoContext.get_executor());
    Lifecycle->RecordFailure(Prism::Fault::FromNative(Native));
    auto Binding = Trusttunnel::MakeWireAuthBinding(
        Trusttunnel::ServerConfig{"user", "password"}, {});
    std::weak_ptr<const Trusttunnel::WireAuthBinding> BindingReceipt = Binding;
    auto CarrierTransport = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    auto Owner = std::make_shared<Trusttunnel::Detail::CarrierOwner>(
        Trusttunnel::Detail::CarrierOwnerLayers{
            CarrierTransport, {}, {}, Lifecycle, Binding});
    Binding.reset();
    ASSERT_FALSE(BindingReceipt.expired());
    auto Front = std::make_shared<TrusttunnelActivityProbe>(IoContext.get_executor());
    auto Receipt = std::make_shared<TrusttunnelCloseReceiptProbe>();
    auto Activity = std::make_shared<Trusttunnel::Detail::AcceptedCarrierActivity<
        Trusttunnel::Detail::CarrierOwner>>(Front, Owner, Receipt);

    std::expected<void, Prism::Fault::Failure> DrainResult;
    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        DrainResult = co_await Activity->Drain();
    }());

    ASSERT_FALSE(DrainResult);
    EXPECT_EQ(DrainResult.error().Native, Native);
    EXPECT_TRUE(Owner->IsRetired());
    EXPECT_TRUE(Activity->IsRetired());
    EXPECT_TRUE(BindingReceipt.expired());
    EXPECT_TRUE(Receipt->Confirmed);
}

TEST(TrusttunnelHttp2Transport, ClientAcceptedOwnerRetainsNativeCauseAfterRetirement)
{
    Net::io_context IoContext;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    auto State = std::make_shared<Trusttunnel::Detail::Http2ClientState>(
        IoContext.get_executor());
    State->Transport = std::make_shared<Transport>(Transport::Options{
        IoContext.get_executor(), Transport::WriteCb{NoopHttp2Write},
        Transport::FinishCb{}, Transport::CloseCb{}});
    State->Lifecycle->RecordFailure(Prism::Fault::FromNative(Native));
    State->Carrier = std::make_shared<Trusttunnel::Detail::CarrierOwner>(
        Trusttunnel::Detail::CarrierOwnerLayers{
            State->Transport, {}, {}, State->Lifecycle, {}});
    auto Accepted = std::make_shared<
        Trusttunnel::Detail::AcceptedClientTransport<
            Trusttunnel::Detail::Http2ClientState>>(State);
    std::expected<void, Prism::Fault::Failure> DrainResult;

    RunCoro(IoContext, [&]() -> Net::awaitable<void>
    {
        const auto Closed = Accepted->Close();
        EXPECT_TRUE(Closed);
        DrainResult = co_await Accepted->Activity()->Drain();
    }());

    ASSERT_FALSE(DrainResult);
    EXPECT_EQ(DrainResult.error().Native, Native);
    EXPECT_TRUE(Accepted->Activity()->IsRetired());
    EXPECT_TRUE(State->IsRetired());
}

TEST(TrusttunnelHttp2Transport, Http2TlsSetupFailureRetiresAdmissionTicket)
{
    Net::io_context IoContext;
    Tcp::socket Socket(IoContext.get_executor());
    auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
    Ssl::context Tls(Ssl::context::tlsv13_client);
    std::optional<TlsStreamResult> Result;
    std::optional<Prism::Fault::Failure> AdmissionFailure;

    RunCoro(IoContext, RunTlsSetupFailure(
        TlsSetupFailureRequest{Raw, &Tls, &Result, &AdmissionFailure}));

    ASSERT_FALSE(AdmissionFailure.has_value());
    ASSERT_TRUE(Result.has_value());
    ASSERT_FALSE(Result->has_value());
    EXPECT_EQ(Result->error().Code, Prism::Fault::Code::InvalidArgument);
    EXPECT_FALSE(Result->error().Native);
    EXPECT_FALSE(Raw->IsOpen());
}
namespace
{
    struct ProbeConnection final
    {
        std::shared_ptr<Prism::Transport::Reliable> Server;
        std::shared_ptr<Tcp::socket> Client;
    };

    struct HandshakeCapacityRetirementRequest final
    {
        Prism::SharedTransmission Inbound;
        std::shared_ptr<Tcp::socket> Peer;
        std::array<Prism::SharedTransmission, 8> CapacityOwners;
        Ssl::context *Context;
        std::optional<Prism::Fault::Failure> *Result;
        std::weak_ptr<Prism::Transport::TlsStream> *TlsReceipt;
        bool *HandshakeCompleted;
        Prism::Fault::Failure Cause;
    };

    [[nodiscard]] auto MakeProbeConnection(Tcp::acceptor &Listener) -> ProbeConnection
    {
        auto Client = std::make_shared<Tcp::socket>(Listener.get_executor());
        Client->connect(Listener.local_endpoint());
        Tcp::socket Server(Listener.get_executor());
        Listener.accept(Server);
        return {std::make_shared<Prism::Transport::Reliable>(std::move(Server)),
                std::move(Client)};
    }

    auto RunHandshakeCapacityRetirement(HandshakeCapacityRetirementRequest Request)
        -> Net::awaitable<void>
    {
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Request.Inbound);
        if (!Prepared)
        {
            Request.Result->emplace(Prepared.error());
            co_return;
        }
        auto Admission = std::move(*Prepared);
        if (!Request.Peer || !Request.Peer->is_open())
        {
            Request.Result->emplace(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            co_return;
        }
        for (const auto &Owner : Request.CapacityOwners)
        {
            const auto Tracked = Admission.Track(Owner);
            if (!Tracked)
            {
                Request.Result->emplace(Tracked.error());
                co_return;
            }
        }
        auto Stream = std::make_shared<Prism::Transport::TlsStream>(
            Prism::Transport::Connector(Request.Inbound), *Request.Context);
        *Request.TlsReceipt = Stream;
        Stream->async_handshake(Net::ssl::stream_base::server,
            [Completed = Request.HandshakeCompleted](boost::system::error_code) -> void
            {
                *Completed = true;
            });
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockSize = 1024, .BlockCount = 1});
        const auto Failure = co_await Trusttunnel::Detail::RetireHttp2HandshakeFailure(
            Admission, Prism::Transport::Encrypted::HandshakeResult{
                Request.Cause, std::move(Stream), {}, std::move(Bytes)});
        Request.Result->emplace(Failure);
    }
}

TEST(TrusttunnelHttp2Transport, TlsHandshakeCapacityRejectionRetiresEncryptedOwner)
{
    Net::io_context IoContext;
    Tcp::acceptor Listener(
        IoContext, Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
    auto InboundPair = MakeProbeConnection(Listener);
    std::array<Prism::SharedTransmission, 8> CapacityOwners{};
    for (auto &Owner : CapacityOwners)
    {
        auto Pair = MakeProbeConnection(Listener);
        Owner = std::move(Pair.Server);
    }
    Ssl::context Context(Ssl::context::tlsv13_server);
    std::optional<Prism::Fault::Failure> Result;
    std::weak_ptr<Prism::Transport::TlsStream> TlsReceipt;
    bool HandshakeCompleted = false;
    const auto Native = std::make_error_code(std::errc::broken_pipe);
    const Prism::Fault::Failure Cause{Prism::Fault::Code::TlsHsfail, Native};

    RunCoro(IoContext, RunHandshakeCapacityRetirement(
        HandshakeCapacityRetirementRequest{
            InboundPair.Server, InboundPair.Client, CapacityOwners, &Context, &Result,
            &TlsReceipt, &HandshakeCompleted, Cause}));

    ASSERT_TRUE(Result.has_value());
    EXPECT_EQ(Result->Code, Cause.Code);
    EXPECT_EQ(Result->Native, Native);
    EXPECT_TRUE(HandshakeCompleted);
    EXPECT_TRUE(TlsReceipt.expired());
    EXPECT_FALSE(InboundPair.Server->IsOpen());
    for (const auto &Owner : CapacityOwners)
    {
        EXPECT_FALSE(Owner->IsOpen());
    }
}
