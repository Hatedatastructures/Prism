#include <expected>
#include <array>
#include <Preview/Transport/Connector.hpp>
#include <Preview/Transport/Encrypted.hpp>
#include <Preview/Transport/Detail/TlsStream.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Http2Client.hpp>
#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Contract/Io/CarrierCloseReceipt.hpp>
#include <memory>
#include <optional>

#include "TrusttunnelHttp2TransportSupport.hpp"

namespace
{
    using Transport = Trusttunnel::Detail::Http2Transport;
    using WriteResult = std::expected<void, Preview::Fault::Failure>;

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

    class TrusttunnelActivityProbe final : public Preview::Contract::CarrierActivity
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
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (!Sealed_)
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            Retired_ = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

    private:
        Net::any_io_executor Executor_;
        bool Sealed_{false};
        bool Retired_{false};
    };

    class TrusttunnelCloseReceiptProbe final
        : public Preview::Contract::CarrierCloseReceipt
    {
    public:
        auto ConfirmExternalClose() noexcept -> void override { Confirmed = true; }
        auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (!Confirmed)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
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
namespace
{
    using TlsStreamResult = std::expected<
        Preview::Transport::Encrypted::SharedStream,
        Preview::Fault::Failure>;

    struct TlsSetupFailureRequest final
    {
        Preview::SharedTransmission Raw;
        Ssl::context *Context;
        std::optional<TlsStreamResult> *Result;
        std::optional<Preview::Fault::Failure> *AdmissionFailure;
    };

    auto RunTlsSetupFailure(TlsSetupFailureRequest Request) -> Net::awaitable<void>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Request.Raw);
        if (!Prepared)
        {
            Request.AdmissionFailure->emplace(Prepared.error());
            co_return;
        }
        auto Admission = std::move(*Prepared);
        *Request.Result = co_await Trusttunnel::Detail::ConnectHttp2Tls(
            Trusttunnel::Detail::Http2TlsClientRequest{
                std::move(Request.Raw), *Request.Context, "example.com", {}},
            Admission);
    }
}

TEST(TrusttunnelHttp2Transport, AcceptedOwnerPreservesFailureAndReportsPhysicalRetirement)
{
    Net::io_context IoContext;
    const auto Native = std::make_error_code(std::errc::broken_pipe);
    auto Lifecycle = std::make_shared<Trusttunnel::Detail::CarrierLifecycle>(
        IoContext.get_executor());
    Lifecycle->RecordFailure(Preview::Fault::FromNative(Native));
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

    std::expected<void, Preview::Fault::Failure> DrainResult;
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
    State->Lifecycle->RecordFailure(Preview::Fault::FromNative(Native));
    State->Carrier = std::make_shared<Trusttunnel::Detail::CarrierOwner>(
        Trusttunnel::Detail::CarrierOwnerLayers{
            State->Transport, {}, {}, State->Lifecycle, {}});
    auto Accepted = std::make_shared<
        Trusttunnel::Detail::AcceptedClientTransport<
            Trusttunnel::Detail::Http2ClientState>>(State);
    std::expected<void, Preview::Fault::Failure> DrainResult;

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
    auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
    Ssl::context Tls(Ssl::context::tlsv13_client);
    std::optional<TlsStreamResult> Result;
    std::optional<Preview::Fault::Failure> AdmissionFailure;

    RunCoro(IoContext, RunTlsSetupFailure(
        TlsSetupFailureRequest{Raw, &Tls, &Result, &AdmissionFailure}));

    ASSERT_FALSE(AdmissionFailure.has_value());
    ASSERT_TRUE(Result.has_value());
    ASSERT_FALSE(Result->has_value());
    EXPECT_EQ(Result->error().Code, Preview::Fault::Code::InvalidArgument);
    EXPECT_FALSE(Result->error().Native);
    EXPECT_FALSE(Raw->IsOpen());
}
namespace
{
    struct ProbeConnection final
    {
        std::shared_ptr<Preview::Transport::Reliable> Server;
        std::shared_ptr<Tcp::socket> Client;
    };

    struct HandshakeCapacityRetirementRequest final
    {
        Preview::SharedTransmission Inbound;
        std::shared_ptr<Tcp::socket> Peer;
        std::array<Preview::SharedTransmission, 8> CapacityOwners;
        Ssl::context *Context;
        std::optional<Preview::Fault::Failure> *Result;
        std::weak_ptr<Preview::Transport::Detail::TlsStream> *TlsReceipt;
        bool *HandshakeCompleted;
        Preview::Fault::Failure Cause;
    };

    [[nodiscard]] auto MakeProbeConnection(Tcp::acceptor &Listener) -> ProbeConnection
    {
        auto Client = std::make_shared<Tcp::socket>(Listener.get_executor());
        Client->connect(Listener.local_endpoint());
        Tcp::socket Server(Listener.get_executor());
        Listener.accept(Server);
        return {std::make_shared<Preview::Transport::Reliable>(std::move(Server)),
                std::move(Client)};
    }

    auto RunHandshakeCapacityRetirement(HandshakeCapacityRetirementRequest Request)
        -> Net::awaitable<void>
    {
        auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Request.Inbound);
        if (!Prepared)
        {
            Request.Result->emplace(Prepared.error());
            co_return;
        }
        auto Admission = std::move(*Prepared);
        if (!Request.Peer || !Request.Peer->is_open())
        {
            Request.Result->emplace(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
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
        auto Stream = std::make_shared<Preview::Transport::Detail::TlsStream>(
            Preview::Transport::Connector(Request.Inbound), *Request.Context);
        *Request.TlsReceipt = Stream;
        Stream->async_handshake(Net::ssl::stream_base::server,
            [Completed = Request.HandshakeCompleted](boost::system::error_code) -> void
            {
                *Completed = true;
            });
        auto Bytes = std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{.BlockSize = 1024, .BlockCount = 1});
        const auto Failure = co_await Trusttunnel::Detail::RetireHttp2HandshakeFailure(
            Admission, Preview::Transport::Encrypted::HandshakeResult{
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
    std::array<Preview::SharedTransmission, 8> CapacityOwners{};
    for (auto &Owner : CapacityOwners)
    {
        auto Pair = MakeProbeConnection(Listener);
        Owner = std::move(Pair.Server);
    }
    Ssl::context Context(Ssl::context::tlsv13_server);
    std::optional<Preview::Fault::Failure> Result;
    std::weak_ptr<Preview::Transport::Detail::TlsStream> TlsReceipt;
    bool HandshakeCompleted = false;
    const auto Native = std::make_error_code(std::errc::broken_pipe);
    const Preview::Fault::Failure Cause{Preview::Fault::Code::TlsHsfail, Native};

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
