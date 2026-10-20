/**
 * @file Hysteria2StreamRequestTerminalTest.cpp
 * @brief Hysteria2 TCPRequest 读取终态与 stream relay 半关闭测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Account/Account.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Protocols/Hysteria2/Http3Auth.hpp>
#include <Prism/Protocols/Hysteria2/StreamSession.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/QuicStreamProviderActivity.hpp>

namespace
{
    namespace Net = boost::asio;

    constexpr std::size_t RelayBufferSize{4096U};

    class ScriptedStreamProvider final : public Prism::Quic::StreamProvider
    {
    public:
        ScriptedStreamProvider(Net::any_io_executor Executor, std::vector<std::byte> Wire)
            : Executor_(std::move(Executor)), Chunks_{std::move(Wire)},
              Activity_(std::make_shared<Prism::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(
            std::span<std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            ++Reads;
            Error.clear();
            if (Closed_)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            if (Chunks_.empty())
            {
                Error = EmptyReadFailure;
                co_return 0;
            }
            const auto Count = (std::min)(Buffer.size(), Chunks_.front().size());
            std::copy_n(Chunks_.front().begin(), Count, Buffer.begin());
            Chunks_.front().erase(
                Chunks_.front().begin(),
                Chunks_.front().begin() + static_cast<std::ptrdiff_t>(Count));
            if (Chunks_.front().empty())
            {
                Chunks_.erase(Chunks_.begin());
            }
            if (Chunks_.empty() && FinalReadFailure)
            {
                Error = FinalReadFailure;
                FinalReadFailure.clear();
            }
            co_return Count;
        }

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &Error) -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                Error = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            Writes.emplace_back(Buffer.begin(), Buffer.end());
            co_return Buffer.size();
        }

        [[nodiscard]] auto Close() -> ControlResult override
        {
            if (!Closed_)
            {
                Closed_ = true;
                Activity_->CompleteClose();
            }
            return {};
        }

        [[nodiscard]] auto ShutdownWrite() -> Net::awaitable<ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            WriteShutdown = true;
            co_return ShutdownResult{};
        }

        [[nodiscard]] auto WaitForWriteAcknowledgement()
            -> Net::awaitable<ShutdownResult> override
        {
            if (!WriteShutdown)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            co_return ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return 1;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_;
        }

        std::error_code FinalReadFailure;
        std::error_code EmptyReadFailure;
        std::size_t Reads{0};
        std::vector<std::vector<std::byte>> Writes;
        bool WriteShutdown{false};

    private:
        Net::any_io_executor Executor_;
        std::vector<std::vector<std::byte>> Chunks_;
        std::shared_ptr<Prism::Testing::Quic::StreamProviderActivity> Activity_;
        bool Closed_{false};
    };

    struct AuthFixture final
    {
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<Prism::Hysteria2::Http3AuthSession> Session;
    };

    struct RelayState final
    {
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        Prism::SharedTransmission Outbound;
        Prism::SharedTransmission Upstream;
        std::vector<std::byte> Uploaded;
        std::vector<std::byte> Response;
        std::size_t DialCalls{0};
        std::size_t RelayCalls{0};
        bool InitialFin{true};
    };

    [[nodiscard]] auto MakeAuthRequest() -> Prism::Http3::RequestEvent
    {
        auto Owner = std::make_shared<Prism::Memory::SessionResource<>>();
        Prism::Http3::HeaderBlock Headers(Owner);
        Headers.Fields.push_back({":method", "POST"});
        Headers.Fields.push_back({":scheme", "https"});
        Headers.Fields.push_back({":authority", "hysteria"});
        Headers.Fields.push_back({":path", "/auth"});
        Headers.Fields.push_back({"hysteria-auth", "secret"});
        Headers.Fields.push_back({"hysteria-cc-rx", "0"});
        return Prism::Http3::RequestEvent{
            0, Prism::Http3::RequestHead{std::move(Headers), true}};
    }

    /** @brief 按 QUIC varint 编码一个 TCPRequest 与尾随数据。 */
    auto AppendVarint(std::vector<std::byte> &Output, const std::uint64_t Value) -> void
    {
        if (Value <= 63U)
        {
            Output.push_back(static_cast<std::byte>(Value));
            return;
        }
        Output.push_back(static_cast<std::byte>((Value >> 8U) | 0x40U));
        Output.push_back(static_cast<std::byte>(Value));
    }

    [[nodiscard]] auto MakeRawRequest(std::span<const std::byte> Tail)
        -> std::vector<std::byte>
    {
        constexpr std::string_view Target{"example.com:443"};
        std::vector<std::byte> Wire;
        AppendVarint(Wire, 0x401U);
        AppendVarint(Wire, Target.size());
        for (const auto Character : Target)
        {
            Wire.push_back(static_cast<std::byte>(static_cast<unsigned char>(Character)));
        }
        AppendVarint(Wire, 0U);
        Wire.insert(Wire.end(), Tail.begin(), Tail.end());
        return Wire;
    }

    [[nodiscard]] auto MakeAuthFixture(Net::any_io_executor Executor) -> AuthFixture
    {
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token("secret"), Prism::AccountId{42},
            {.MaxConnections = 1, .MaxStreams = 1});
        auto Session = std::make_shared<Prism::Hysteria2::Http3AuthSession>(
            Prism::Hysteria2::Http3AuthSessionOptions{std::move(Executor), Directory->Authenticator});
        return {std::move(Directory), std::move(Session)};
    }

    [[nodiscard]] auto WriteAll(
        const Prism::SharedTransmission &Transport,
        std::span<const std::byte> Payload) -> Net::awaitable<Prism::Fault::Failure>
    {
        const auto Result = co_await Transport->WriteExact(Payload);
        if (Result.Failure.Failed()) co_return Result.Failure;
        if (Result.Bytes != Payload.size())
            co_return Prism::Fault::Failure{Prism::Fault::Code::WouldBlock};
        co_return Prism::Fault::Failure{};
    }

    [[nodiscard]] auto ReadUntilEof(const Prism::SharedTransmission &Transport)
        -> Net::awaitable<std::vector<std::byte>>
    {
        std::vector<std::byte> Result;
        std::array<std::byte, RelayBufferSize> Buffer{};
        while (true)
        {
            const auto Part = co_await Transport->ReadSome(std::span<std::byte>(Buffer));
            if (Part.Bytes > Buffer.size())
                throw std::runtime_error("relay read reported an oversized byte count");
            Result.insert(Result.end(), Buffer.begin(),
                Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Part.Failure.Code == Prism::Fault::Code::Eof) co_return Result;
            if (Part.Failure.Failed() || Part.Bytes == 0U)
                throw std::runtime_error("relay read ended without an EOF terminal");
        }
    }

    [[nodiscard]] auto DialForTest(
        const std::shared_ptr<RelayState> &State,
        Prism::Hysteria2::DialRequest) -> Net::awaitable<std::expected<Prism::SharedTransmission,
            Prism::Fault::Failure>>
    {
        ++State->DialCalls;
        co_return State->Outbound;
    }

    [[nodiscard]] auto RelayForTest(
        const std::shared_ptr<RelayState> &State,
        Prism::Hysteria2::StreamRelayRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        ++State->RelayCalls;
        State->InitialFin = Request.InitialFin;
        State->Uploaded = Request.InitialPayload;
        const auto InitialWrite = co_await WriteAll(
            Request.Outbound, std::span<const std::byte>(Request.InitialPayload));
        if (InitialWrite.Failed()) co_return std::unexpected(InitialWrite);

        auto Inbound = std::make_shared<Prism::Quic::StreamAdapter>(
            Request.Inbound->Executor(), Request.Inbound,
            std::move(Request.InitialReadTerminal));
        const auto Relayed = co_await Prism::Network::Relay::Run(
            Prism::Network::Relay::Request{
                .Inbound = std::move(Inbound),
                .Outbound = std::move(Request.Outbound),
                .BufferSize = RelayBufferSize,
                .Bytes = State->Bytes});
        if (Relayed.Failure.Failed())
            co_return std::unexpected(Relayed.Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto MakeServices(const std::shared_ptr<RelayState> &State)
        -> Prism::Hysteria2::AdmissionServices
    {
        Prism::Hysteria2::AdmissionServices Result;
        Result.Dial = [State](Prism::Hysteria2::DialRequest Request)
        {
            return DialForTest(State, std::move(Request));
        };
        Result.RelayStream = [State](Prism::Hysteria2::StreamRelayRequest Request)
        {
            return RelayForTest(State, std::move(Request));
        };
        return Result;
    }

    /** @brief 驱动 upstream 读取到 FIN、返回响应并写半关闭。 */
    auto CompleteHalfCloseExchange(const std::shared_ptr<RelayState> &State)
        -> Net::awaitable<void>
    {
        State->Uploaded = co_await ReadUntilEof(State->Upstream);
        const auto Sent = co_await WriteAll(
            State->Upstream, std::span<const std::byte>(State->Response));
        EXPECT_TRUE(Sent.Succeeded());
        const auto Shutdown = co_await State->Upstream->WriteShutdown();
        EXPECT_TRUE(Shutdown.has_value());
    }

    template <typename Operation>
    auto RunIo(Net::io_context &Io, Operation OperationValue) -> void
    {
        std::exception_ptr Failure;
        Io.restart();
        Net::co_spawn(Io, std::move(OperationValue),
            [&Failure](std::exception_ptr Error) { Failure = std::move(Error); });
        Io.run();
        if (Failure) std::rethrow_exception(Failure);
    }

    /** @brief 等待测试 stream provider 的操作预约退栈并核对物理退休。 */
    auto DrainStreamProvider(
        std::shared_ptr<ScriptedStreamProvider> Provider) -> Net::awaitable<void>
    {
        const auto Activity = Provider->Activity();
        if (!Activity)
        {
            ADD_FAILURE() << "stream provider must expose its activity owner";
            co_return;
        }
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
    }

    class Hysteria2StreamRequestTest : public ::testing::Test
    {
    protected:
        auto SetUp() -> void override
        {
            Fixture_ = MakeAuthFixture(Io_.get_executor());
            ASSERT_TRUE(Fixture_.Session->HandleRequest(MakeAuthRequest()).has_value());
            auto Pair = Prism::MakeMemoryPair(Io_.get_executor());
            auto Outbound = std::make_shared<Prism::MemoryStream>(std::move(Pair.first));
            auto Upstream = std::make_shared<Prism::MemoryStream>(std::move(Pair.second));
            Relay_ = std::make_shared<RelayState>(RelayState{
                std::make_shared<Prism::Memory::BytePool>(
                    Prism::Memory::BytePoolOptions{RelayBufferSize, 2U}),
                std::move(Outbound), std::move(Upstream)});
        }

        auto TearDown() -> void override
        {
            if (Child_) Child_->Close();
            else if (Provider_) Provider_->Close();
            if (Fixture_.Session) Fixture_.Session->Close();
            if (Provider_) RunIo(Io_, DrainStreamProvider(Provider_));
        }

        [[nodiscard]] auto StartChild(std::vector<std::byte> Wire)
            -> std::shared_ptr<ScriptedStreamProvider>
        {
            Provider_ = std::make_shared<ScriptedStreamProvider>(
                Io_.get_executor(), std::move(Wire));
            auto Lease = Fixture_.Session->AcquireStream();
            if (!Lease) return {};
            Child_ = Prism::Hysteria2::StreamSession::Create(
                Prism::Hysteria2::StreamSession::Options{
                    .Executor = Io_.get_executor(),
                    .Id = 1,
                    .Provider = Provider_,
                    .AccountId = Fixture_.Session->AccountId(),
                    .Identity = std::string(Fixture_.Session->Identity()),
                    .Lease = std::move(*Lease),
                    .Services = MakeServices(Relay_),
                    .Completed = [this](std::uint64_t, Prism::Fault::Code Status)
                    {
                        ++CompletionCalls_;
                        CompletionStatus_ = Status;
                    }});
            return Provider_;
        }

        Net::io_context Io_;
        AuthFixture Fixture_;
        std::shared_ptr<RelayState> Relay_;
        std::shared_ptr<ScriptedStreamProvider> Provider_;
        std::shared_ptr<Prism::Hysteria2::StreamSession> Child_;
        std::size_t CompletionCalls_{0};
        Prism::Fault::Code CompletionStatus_{Prism::Fault::Code::Success};
    };

    TEST_F(Hysteria2StreamRequestTest, QueuedRequestThenPeerFinAllowsResponse)
    {
        const std::array<std::byte, 4> Tail{
            std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
        const std::array<std::byte, 5> Response{
            std::byte{0xA1}, std::byte{0xA2}, std::byte{0xA3}, std::byte{0xA4}, std::byte{0xA5}};
        Relay_->Response.assign(Response.begin(), Response.end());
        const auto Provider = StartChild(MakeRawRequest(Tail));
        ASSERT_TRUE(Child_);
        ASSERT_TRUE(Provider);
        Provider->EmptyReadFailure = static_cast<std::error_code>(
            boost::system::error_code(boost::asio::error::eof));
        Child_->Start();

        RunIo(Io_, CompleteHalfCloseExchange(Relay_));

        EXPECT_EQ(Relay_->DialCalls, 1U);
        EXPECT_EQ(Relay_->RelayCalls, 1U);
        EXPECT_FALSE(Relay_->InitialFin);
        EXPECT_EQ(Relay_->Uploaded, std::vector<std::byte>(Tail.begin(), Tail.end()));
        EXPECT_EQ(CompletionCalls_, 1U);
        EXPECT_EQ(CompletionStatus_, Prism::Fault::Code::Success);
        EXPECT_EQ(Provider->Reads, 2U);
        EXPECT_TRUE(Provider->WriteShutdown);
        ASSERT_FALSE(Provider->Writes.empty());
        ASSERT_EQ(Provider->Writes.front().size(), 3U);
        EXPECT_EQ(Provider->Writes.front()[0], std::byte{0});
        EXPECT_EQ(Provider->Writes.front()[1], std::byte{0});
        EXPECT_EQ(Provider->Writes.front()[2], std::byte{0});
        std::vector<std::byte> ForwardedResponse;
        for (std::size_t Index = 1; Index < Provider->Writes.size(); ++Index)
        {
            ForwardedResponse.insert(
                ForwardedResponse.end(), Provider->Writes[Index].begin(),
                Provider->Writes[Index].end());
        }
        EXPECT_EQ(ForwardedResponse, std::vector<std::byte>(Response.begin(), Response.end()));
    }

    TEST_F(Hysteria2StreamRequestTest, PartialRequestWithEofDoesNotDial)
    {
        auto Provider = StartChild({std::byte{0x44}});
        ASSERT_TRUE(Child_);
        ASSERT_TRUE(Provider);
        Provider->FinalReadFailure = static_cast<std::error_code>(
            boost::system::error_code(boost::asio::error::eof));
        Child_->Start();
        RunIo(Io_, []() -> Net::awaitable<void> { co_return; }());

        EXPECT_EQ(Relay_->DialCalls, 0U);
        EXPECT_EQ(Relay_->RelayCalls, 0U);
        EXPECT_TRUE(Provider->Writes.empty());
        EXPECT_EQ(CompletionCalls_, 1U);
        EXPECT_EQ(CompletionStatus_, Prism::Fault::Code::BadMessage);
        EXPECT_EQ(Provider->Reads, 1U);
    }

    TEST_F(Hysteria2StreamRequestTest, EmptyRequestWithEofKeepsEof)
    {
        auto Provider = StartChild({});
        ASSERT_TRUE(Child_);
        ASSERT_TRUE(Provider);
        Provider->EmptyReadFailure = static_cast<std::error_code>(
            boost::system::error_code(boost::asio::error::eof));
        Child_->Start();
        RunIo(Io_, []() -> Net::awaitable<void> { co_return; }());

        EXPECT_EQ(Relay_->DialCalls, 0U);
        EXPECT_EQ(Relay_->RelayCalls, 0U);
        EXPECT_TRUE(Provider->Writes.empty());
        EXPECT_EQ(CompletionCalls_, 1U);
        EXPECT_EQ(CompletionStatus_, Prism::Fault::Code::Eof);
        EXPECT_EQ(Provider->Reads, 1U);
    }

    TEST_F(Hysteria2StreamRequestTest, CompleteRequestWithSameReadEofAllowsResponse)
    {
        const std::array<std::byte, 4> Tail{
            std::byte{0x31}, std::byte{0x32}, std::byte{0x33}, std::byte{0x34}};
        const std::array<std::byte, 3> Response{
            std::byte{0xB1}, std::byte{0xB2}, std::byte{0xB3}};
        Relay_->Response.assign(Response.begin(), Response.end());
        const auto Provider = StartChild(MakeRawRequest(Tail));
        ASSERT_TRUE(Child_);
        ASSERT_TRUE(Provider);
        Provider->FinalReadFailure = static_cast<std::error_code>(
            boost::system::error_code(boost::asio::error::eof));
        Child_->Start();

        RunIo(Io_, CompleteHalfCloseExchange(Relay_));

        EXPECT_EQ(Relay_->DialCalls, 1U);
        EXPECT_EQ(Relay_->RelayCalls, 1U);
        EXPECT_FALSE(Relay_->InitialFin);
        EXPECT_EQ(Relay_->Uploaded, std::vector<std::byte>(Tail.begin(), Tail.end()));
        EXPECT_EQ(CompletionCalls_, 1U);
        EXPECT_EQ(CompletionStatus_, Prism::Fault::Code::Success);
        EXPECT_EQ(Provider->Reads, 1U);
        EXPECT_TRUE(Provider->WriteShutdown);
        std::vector<std::byte> ForwardedResponse;
        for (std::size_t Index = 1; Index < Provider->Writes.size(); ++Index)
        {
            ForwardedResponse.insert(
                ForwardedResponse.end(), Provider->Writes[Index].begin(),
                Provider->Writes[Index].end());
        }
        EXPECT_EQ(ForwardedResponse, std::vector<std::byte>(Response.begin(), Response.end()));
    }

    TEST_F(Hysteria2StreamRequestTest, SameReadResetAfterCompleteRequestPreservesFailure)
    {
        const std::array<std::byte, 2> Tail{std::byte{0x51}, std::byte{0x52}};
        auto Provider = StartChild(MakeRawRequest(Tail));
        ASSERT_TRUE(Child_);
        ASSERT_TRUE(Provider);
        Provider->FinalReadFailure = std::make_error_code(std::errc::connection_reset);
        Child_->Start();
        RunIo(Io_, []() -> Net::awaitable<void> { co_return; }());

        EXPECT_EQ(Relay_->DialCalls, 0U);
        EXPECT_EQ(Relay_->RelayCalls, 0U);
        EXPECT_TRUE(Provider->Writes.empty());
        EXPECT_EQ(CompletionCalls_, 1U);
        EXPECT_EQ(CompletionStatus_, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Provider->Reads, 1U);
    }
} // namespace
