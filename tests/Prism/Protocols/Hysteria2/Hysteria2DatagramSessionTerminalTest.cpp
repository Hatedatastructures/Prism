/**
 * @file Hysteria2DatagramSessionTerminalTest.cpp
 * @brief Hysteria2 完整 UDPMessage 先交付、同读终态后停止 admission 子会话。
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Account/Account.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Hysteria2/Admission.hpp>
#include <Prism/Protocols/Hysteria2/Dgram.hpp>
#include <Prism/Protocols/Hysteria2/DatagramSession.hpp>
#include <Prism/Protocols/Hysteria2/Detail/DatagramFragments.hpp>
#include <Prism/Protocols/Http3/Auth.hpp>
#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Hysteria = Prism::Hysteria2;

    struct DatagramReadPlan final
    {
        std::vector<std::byte> Datagram;
        std::error_code Terminal;
        bool InitiallyClosed{false};
    };

    class ScriptedDatagramProvider final : public Prism::Quic::DatagramProvider
    {
    public:
        ScriptedDatagramProvider(
            Net::any_io_executor Executor,
            DatagramReadPlan Plan)
            : Executor_(std::move(Executor)), Datagram_(std::move(Plan.Datagram)),
              Terminal_(Plan.Terminal), Closed_(Plan.InitiallyClosed)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Receive(
            const std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ++ReceiveCalls_;
            ErrorCode.clear();
            if (Delivered_)
            {
                if (Closed_) ErrorCode = Prism::make_error_code(Prism::Error::BrokenPipe);
                co_return 0U;
            }
            const auto Count = (std::min)(Buffer.size(), Datagram_.size());
            std::copy_n(Datagram_.begin(), Count, Buffer.begin());
            Delivered_ = true;
            if (!Closed_) ErrorCode = Terminal_;
            co_return Count;
        }

        [[nodiscard]] auto Send(
            const std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ++SendCalls_;
            ErrorCode.clear();
            if (Closed_)
            {
                ErrorCode = Prism::make_error_code(Prism::Error::BrokenPipe);
                co_return 0U;
            }
            Sends_.emplace_back(Buffer.begin(), Buffer.end());
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            ++CloseCalls_;
            Closed_ = true;
        }

        auto Cancel() -> void override
        {
            ++CancelCalls_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        std::size_t ReceiveCalls_{0U};
        std::size_t SendCalls_{0U};
        std::size_t CloseCalls_{0U};
        std::size_t CancelCalls_{0U};
        std::vector<std::vector<std::byte>> Sends_;

    private:
        Net::any_io_executor Executor_;
        std::vector<std::byte> Datagram_;
        std::error_code Terminal_;
        bool Delivered_{false};
        bool Closed_{false};
    };

    struct AuthFixture final
    {
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Hysteria::Http3AuthSession> Session;
    };

    auto MakeAuthFixture(Net::any_io_executor Executor) -> AuthFixture
    {
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token("secret"), Prism::AccountId{42},
            {.MaxConnections = 1, .MaxStreams = 1});
        auto Authenticator = Directory->Authenticator;
        return {Directory, std::make_shared<Hysteria::Http3AuthSession>(
            Hysteria::Http3AuthSessionOptions{std::move(Executor), Authenticator})};
    }

    auto MakeAuthRequest() -> Prism::Http3::RequestEvent
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({":method", "POST"});
        Headers.Fields.push_back({":scheme", "https"});
        Headers.Fields.push_back({":authority", "hysteria"});
        Headers.Fields.push_back({":path", "/auth"});
        Headers.Fields.push_back({"hysteria-auth", "secret"});
        Headers.Fields.push_back({"hysteria-cc-rx", "0"});
        return {0, Prism::Http3::RequestHead{std::move(Headers), true}};
    }

    [[nodiscard]] auto MakeStandardDatagram(
        const std::span<const std::uint8_t> Payload,
        const bool Malformed = false) -> std::vector<std::byte>
    {
        constexpr std::string_view Target{"example.com:443"};
        std::vector<std::uint8_t> Wire;
        const Hysteria::Detail::ReferenceUdpBuildInput Input{
            .SessionId = 7U,
            .PacketId = 9U,
            .FragmentId = 0U,
            .FragmentCount = 1U,
            .Address = Target,
            .Payload = Payload};
        if (!Hysteria::Detail::BuildReferenceUdpFragment(Input, Wire))
        {
            return {};
        }
        if (Malformed && Wire.size() > 7U)
        {
            Wire[7] = 0U;
        }
        std::vector<std::byte> Result;
        Result.reserve(Wire.size());
        for (const auto Byte : Wire)
        {
            Result.push_back(static_cast<std::byte>(Byte));
        }
        return Result;
    }

    struct DatagramSessionOutcome final
    {
        bool Authenticated{false};
        bool LeaseAcquired{false};
        bool ChildCreated{false};
        bool CompletionCalled{false};
        std::exception_ptr CompletionError;
        std::size_t ResolveCalls{0U};
        std::size_t ExchangeCalls{0U};
        std::size_t CompletedReports{0U};
        std::uint64_t ValidDatagrams{0U};
        std::uint64_t MalformedDatagrams{0U};
        std::uint64_t UploadedBytes{0U};
        std::uint64_t DownloadedBytes{0U};
        std::uint64_t DroppedDatagrams{0U};
        std::size_t ReceiveCalls{0U};
        std::size_t SendCalls{0U};
        std::size_t CloseCalls{0U};
        std::size_t CancelCalls{0U};
        bool ProviderClosed{false};
        bool ProviderInitiallyClosed{false};
    };

    enum class DatagramShape : std::uint8_t
    {
        Complete,
        Partial,
        Malformed,
    };

    class DatagramSessionServicesProbe final
    {
    public:
        explicit DatagramSessionServicesProbe(DatagramSessionOutcome &Outcome)
            : Outcome_(Outcome)
        {
        }

        auto Resolve(Hysteria::ResolveRequest Request)
            -> Net::awaitable<Hysteria::ResolveResult>
        {
            ++Outcome_.ResolveCalls;
            co_return Hysteria::ResolveResult{Prism::Fault::Code::Success,
                {std::move(Request.Target)}};
        }

        auto Exchange(Hysteria::DatagramRequest Request)
            -> Net::awaitable<Hysteria::DatagramResult>
        {
            ++Outcome_.ExchangeCalls;
            const auto UploadedBytes = Request.Payload.size();
            co_return Hysteria::DatagramResult{Prism::Fault::Code::Success,
                std::move(Request.Target), {0xA5U}, UploadedBytes, 1U};
        }

        auto Report(Hysteria::DatagramSessionReport ReportValue) -> void
        {
            if (ReportValue.Kind != Prism::Foundation::TrafficEventKind::Completed)
            {
                return;
            }
            ++Outcome_.CompletedReports;
            Outcome_.ValidDatagrams = ReportValue.ValidDatagrams;
            Outcome_.MalformedDatagrams = ReportValue.MalformedDatagrams;
            Outcome_.UploadedBytes = ReportValue.UploadedBytes;
            Outcome_.DownloadedBytes = ReportValue.DownloadedBytes;
            Outcome_.DroppedDatagrams = ReportValue.DroppedDatagrams;
        }

    private:
        DatagramSessionOutcome &Outcome_;
    };

    auto RunDatagramSession(
        const Prism::Fault::Failure Terminal,
        const DatagramShape Shape,
        const bool InitiallyClosed = false) -> DatagramSessionOutcome
    {
        Net::io_context Io;
        auto Fixture = MakeAuthFixture(Io.get_executor());
        DatagramSessionOutcome Outcome;
        const auto Authenticated = Fixture.Session->HandleRequest(MakeAuthRequest());
        Outcome.Authenticated = Authenticated.has_value();
        if (!Authenticated)
        {
            return Outcome;
        }
        auto Lease = Fixture.Session->AcquireStream();
        Outcome.LeaseAcquired = Lease.has_value();
        if (!Lease)
        {
            return Outcome;
        }

        const std::array<std::uint8_t, 3> Payload{0x61U, 0x62U, 0x63U};
        auto Datagram = MakeStandardDatagram(
            Payload, Shape == DatagramShape::Malformed);
        if (Shape == DatagramShape::Partial && Datagram.size() > 7U)
        {
            Datagram.resize(7U);
        }
        auto Provider = std::make_shared<ScriptedDatagramProvider>(
            Io.get_executor(), DatagramReadPlan{
                std::move(Datagram), Prism::Fault::ToNative(Terminal), InitiallyClosed});
        Outcome.ProviderInitiallyClosed = Provider->IsClosed();
        auto ServiceProbe = std::make_shared<DatagramSessionServicesProbe>(Outcome);
        Hysteria::AdmissionServices Services;
        Services.Resolve = [ServiceProbe](Hysteria::ResolveRequest Request)
        {
            return ServiceProbe->Resolve(std::move(Request));
        };
        Services.ExchangeDatagram = [ServiceProbe](Hysteria::DatagramRequest Request)
        {
            return ServiceProbe->Exchange(std::move(Request));
        };
        Services.ReportDatagram = [ServiceProbe](Hysteria::DatagramSessionReport Report)
        {
            ServiceProbe->Report(std::move(Report));
        };
        auto Child = Hysteria::DatagramSession::Create({
            Io.get_executor(), Provider, std::move(*Lease), Fixture.Session->AccountId(),
            std::move(Services), [&Outcome](std::exception_ptr Error)
            {
                Outcome.CompletionCalled = true;
                Outcome.CompletionError = std::move(Error);
            }});
        Outcome.ChildCreated = static_cast<bool>(Child);
        if (Child)
        {
            Child->Start();
            Io.run();
        }
        Outcome.ReceiveCalls = Provider->ReceiveCalls_;
        Outcome.SendCalls = Provider->SendCalls_;
        Outcome.CloseCalls = Provider->CloseCalls_;
        Outcome.CancelCalls = Provider->CancelCalls_;
        Outcome.ProviderClosed = Provider->IsClosed();
        Fixture.Session->Close();
        return Outcome;
    }

    auto VerifyMalformedDatagramStickyNativeTerminal(
        Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        const auto Native = std::make_error_code(std::errc::connection_reset);
        const std::array<std::uint8_t, 3> Payload{0x61U, 0x62U, 0x63U};
        auto Provider = std::make_shared<ScriptedDatagramProvider>(
            std::move(Executor), DatagramReadPlan{
                MakeStandardDatagram(Payload, true), Native});
        auto Adapter = std::make_shared<Prism::Quic::DatagramAdapter>(Provider);
        auto Datagram = std::make_shared<Hysteria::Dgram<>>(
            Adapter, true);
        Hysteria::Address Source;
        std::vector<std::uint8_t> ReceivedPayload;

        EXPECT_EQ(
            co_await Datagram->AsyncReceiveFrom(Source, ReceivedPayload),
            Prism::Error::BadMessage);
        EXPECT_EQ(Provider->ReceiveCalls_, 1U);
        EXPECT_EQ(
            co_await Datagram->AsyncReceiveFrom(Source, ReceivedPayload),
            Prism::Error::IoError);
        EXPECT_EQ(
            co_await Datagram->AsyncReceiveFrom(Source, ReceivedPayload),
            Prism::Error::IoError);
        EXPECT_EQ(Provider->ReceiveCalls_, 1U);

        const auto DatagramActivity = Datagram->Activity();
        const auto CloseResult = Datagram->Close();
        EXPECT_TRUE(DatagramActivity);
        EXPECT_TRUE(CloseResult);
        if (DatagramActivity && CloseResult)
        {
            const auto Drained = co_await DatagramActivity->Drain();
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(DatagramActivity->IsRetired());
        }

        const auto AdapterActivity = Adapter->Activity();
        const auto AdapterClose = Adapter->Close();
        EXPECT_TRUE(AdapterActivity);
        EXPECT_TRUE(AdapterClose);
        if (AdapterActivity && AdapterClose)
        {
            const auto Drained = co_await AdapterActivity->Drain();
            EXPECT_TRUE(Drained);
            EXPECT_TRUE(AdapterActivity->IsRetired());
        }
        EXPECT_TRUE(Provider->IsClosed());
        EXPECT_GE(Provider->CloseCalls_, 1U);
    }
}

TEST(Hysteria2DatagramTerminal, MalformedWirePrecedesStickyNativeReset)
{
    Net::io_context Io;
    auto Coroutine = VerifyMalformedDatagramStickyNativeTerminal(Io.get_executor());
    std::exception_ptr Exception;
    Net::co_spawn(Io, std::move(Coroutine), [&Exception](std::exception_ptr Error)
    {
        Exception = std::move(Error);
    });
    Io.run();
    EXPECT_FALSE(Exception);
}

TEST(Hysteria2DatagramSessionTerminal, CompleteDatagramIsExchangedBeforeEof)
{
    const auto Outcome = RunDatagramSession(
        Prism::Fault::Failure{Prism::Fault::Code::Eof}, DatagramShape::Complete);
    ASSERT_TRUE(Outcome.Authenticated);
    ASSERT_TRUE(Outcome.LeaseAcquired);
    ASSERT_TRUE(Outcome.ChildCreated);
    EXPECT_TRUE(Outcome.CompletionCalled);
    EXPECT_FALSE(Outcome.CompletionError);
    EXPECT_EQ(Outcome.ResolveCalls, 1U);
    EXPECT_EQ(Outcome.ExchangeCalls, 1U);
    EXPECT_EQ(Outcome.ValidDatagrams, 1U);
    EXPECT_EQ(Outcome.MalformedDatagrams, 0U);
    EXPECT_EQ(Outcome.UploadedBytes, 3U);
    EXPECT_EQ(Outcome.DownloadedBytes, 1U);
    EXPECT_EQ(Outcome.CompletedReports, 1U);
    EXPECT_EQ(Outcome.ReceiveCalls, 1U);
    EXPECT_EQ(Outcome.SendCalls, 1U);
    EXPECT_TRUE(Outcome.ProviderClosed);
    EXPECT_GE(Outcome.CloseCalls, 1U);
    EXPECT_GE(Outcome.CancelCalls, 1U);
}

TEST(Hysteria2DatagramSessionTerminal, CompleteDatagramIsExchangedBeforeNativeReset)
{
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Outcome = RunDatagramSession(
        Prism::Fault::FromNative(Native), DatagramShape::Complete);
    ASSERT_TRUE(Outcome.Authenticated);
    ASSERT_TRUE(Outcome.LeaseAcquired);
    ASSERT_TRUE(Outcome.ChildCreated);
    EXPECT_TRUE(Outcome.CompletionCalled);
    EXPECT_FALSE(Outcome.CompletionError);
    EXPECT_EQ(Outcome.ResolveCalls, 1U);
    EXPECT_EQ(Outcome.ExchangeCalls, 1U);
    EXPECT_EQ(Outcome.ValidDatagrams, 1U);
    EXPECT_EQ(Outcome.MalformedDatagrams, 0U);
    EXPECT_EQ(Outcome.CompletedReports, 1U);
    EXPECT_EQ(Outcome.ReceiveCalls, 1U);
    EXPECT_EQ(Outcome.SendCalls, 1U);
    EXPECT_TRUE(Outcome.ProviderClosed);
    EXPECT_GE(Outcome.CloseCalls, 1U);
    EXPECT_GE(Outcome.CancelCalls, 1U);
}

TEST(Hysteria2DatagramSessionTerminal, MalformedDatagramPrecedesNativeReset)
{
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Outcome = RunDatagramSession(
        Prism::Fault::FromNative(Native), DatagramShape::Malformed);
    ASSERT_TRUE(Outcome.Authenticated);
    ASSERT_TRUE(Outcome.LeaseAcquired);
    ASSERT_TRUE(Outcome.ChildCreated);
    EXPECT_TRUE(Outcome.CompletionCalled);
    EXPECT_FALSE(Outcome.CompletionError);
    EXPECT_EQ(Outcome.ResolveCalls, 0U);
    EXPECT_EQ(Outcome.ExchangeCalls, 0U);
    EXPECT_EQ(Outcome.ValidDatagrams, 0U);
    EXPECT_EQ(Outcome.MalformedDatagrams, 1U);
    EXPECT_EQ(Outcome.CompletedReports, 1U);
    EXPECT_EQ(Outcome.ReceiveCalls, 1U);
    EXPECT_EQ(Outcome.SendCalls, 0U);
    EXPECT_TRUE(Outcome.ProviderClosed);
    EXPECT_EQ(Outcome.CloseCalls, 1U);
    EXPECT_EQ(Outcome.CancelCalls, 1U);
}

TEST(Hysteria2DatagramSessionTerminal, PartialDatagramIsNotExchangedBeforeEof)
{
    const auto Outcome = RunDatagramSession(
        Prism::Fault::Failure{Prism::Fault::Code::Eof}, DatagramShape::Partial);
    ASSERT_TRUE(Outcome.Authenticated);
    ASSERT_TRUE(Outcome.LeaseAcquired);
    ASSERT_TRUE(Outcome.ChildCreated);
    EXPECT_TRUE(Outcome.CompletionCalled);
    EXPECT_FALSE(Outcome.CompletionError);
    EXPECT_EQ(Outcome.ResolveCalls, 0U);
    EXPECT_EQ(Outcome.ExchangeCalls, 0U);
    EXPECT_EQ(Outcome.ValidDatagrams, 0U);
    EXPECT_EQ(Outcome.MalformedDatagrams, 1U);
    EXPECT_EQ(Outcome.CompletedReports, 1U);
    EXPECT_EQ(Outcome.ReceiveCalls, 1U);
    EXPECT_EQ(Outcome.SendCalls, 0U);
    EXPECT_TRUE(Outcome.ProviderClosed);
    EXPECT_GE(Outcome.CloseCalls, 1U);
    EXPECT_GE(Outcome.CancelCalls, 1U);
}

TEST(Hysteria2DatagramSessionTerminal, ClosedProviderStillDeliversQueuedDatagram)
{
    const auto BrokenPipe = Prism::make_error_code(Prism::Error::BrokenPipe);
    const auto Outcome = RunDatagramSession(
        Prism::Fault::FromNative(BrokenPipe), DatagramShape::Complete, true);
    ASSERT_TRUE(Outcome.Authenticated);
    ASSERT_TRUE(Outcome.LeaseAcquired);
    ASSERT_TRUE(Outcome.ChildCreated);
    EXPECT_TRUE(Outcome.ProviderInitiallyClosed);
    EXPECT_TRUE(Outcome.CompletionCalled);
    EXPECT_FALSE(Outcome.CompletionError);
    EXPECT_EQ(Outcome.ReceiveCalls, 1U);
    EXPECT_EQ(Outcome.ResolveCalls, 1U);
    EXPECT_EQ(Outcome.ExchangeCalls, 1U);
    EXPECT_EQ(Outcome.ValidDatagrams, 1U);
    EXPECT_EQ(Outcome.MalformedDatagrams, 0U);
    EXPECT_EQ(Outcome.UploadedBytes, 3U);
    EXPECT_EQ(Outcome.DownloadedBytes, 0U);
    EXPECT_EQ(Outcome.DroppedDatagrams, 1U);
    EXPECT_EQ(Outcome.SendCalls, 1U);
    EXPECT_EQ(Outcome.CompletedReports, 1U);
    EXPECT_TRUE(Outcome.ProviderClosed);
}
