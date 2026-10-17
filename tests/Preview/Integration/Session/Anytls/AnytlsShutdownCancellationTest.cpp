/** @file AnytlsShutdownCancellationTest.cpp @brief AnyTLS 本地关闭取消与根退休回归。 */
#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Anytls/IngressFactory.hpp>
#include <Preview/Runtime/ActiveTransports.hpp>
#include <Preview/Runtime/CarrierDomain.hpp>
#include <Preview/Transport/Detail/ForwardActivity.hpp>
#include <Preview/Transport/MemoryStream.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Failure = Preview::Fault::Failure;
    using Outcome = std::expected<void, Failure>;

    class IdleEgress final : public Preview::Contract::StreamEgress
    {
    public:
        auto Connect(Preview::Network::Target)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Failure>> override
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::NotSupported});
        }
    };

    /** @brief 观察真实挂起读，并等待下层载体的物理 drain 回执。 */
    class ReadProbeTransmission final : public Preview::Transmission
    {
    public:
        explicit ReadProbeTransmission(Preview::SharedTransmission Next)
            : Preview::Transmission(Next->Executor()), Next_(std::move(Next)),
              Activity_(std::make_shared<Preview::Transport::Detail::ForwardActivity>(
                  Preview::Transmission::Activity(), Next_->Activity())),
              ReadChanged_(Executor(), 1U)
        {
        }

        /** @brief 等待真实挂起读请求，避免依赖控制帧写入与客户端读回的调度顺序。 */
        [[nodiscard]] auto WaitForPendingRead() -> Net::awaitable<void>
        {
            while (PendingReads_.load(std::memory_order_acquire) == 0U)
                co_await ReadChanged_.async_receive(Net::use_awaitable);
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto ChildActivity() const -> std::shared_ptr<Preview::Contract::CarrierActivity>
        {
            return Next_->Activity();
        }

        [[nodiscard]] auto CloseForwarded() const noexcept -> bool
        {
            return ChildCloseForwarded_.load(std::memory_order_acquire);
        }

    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            const auto Self = std::static_pointer_cast<ReadProbeTransmission>(
                Preview::Transmission::shared_from_this());
            const auto Observation = std::make_shared<ReadObservation>();
            Next_->ReadSome(Buffer, [Self, Observation, Handler = std::move(Handler)](auto Result) mutable
            {
                if (Observation->Phase.exchange(3U, std::memory_order_acq_rel) == 1U)
                {
                    Self->PendingReads_.fetch_sub(1U, std::memory_order_acq_rel);
                    (void)Self->ReadChanged_.try_send(boost::system::error_code{});
                }
                Handler(std::move(Result));
            });
            Self->PendingReads_.fetch_add(1U, std::memory_order_acq_rel);
            std::uint8_t Starting = 0U;
            if (Observation->Phase.compare_exchange_strong(
                    Starting, 1U, std::memory_order_acq_rel))
            {
                (void)Self->ReadChanged_.try_send(boost::system::error_code{});
            }
            else
            {
                Self->PendingReads_.fetch_sub(1U, std::memory_order_acq_rel);
            }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Next_->WriteSome(Buffer, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Next_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            const auto Closed = Next_->Close();
            if (Closed)
            {
                ChildCloseForwarded_.store(true, std::memory_order_release);
                Activity_->RequireChildDrain();
            }
            return Closed;
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return Next_->Cancel(); }

    private:
        struct ReadObservation final
        {
            std::atomic<std::uint8_t> Phase{0U};
        };

        Preview::SharedTransmission Next_;
        std::shared_ptr<Preview::Transport::Detail::ForwardActivity> Activity_;
        Net::experimental::channel<void(boost::system::error_code)> ReadChanged_;
        std::atomic<std::size_t> PendingReads_{0U};
        std::atomic<bool> ChildCloseForwarded_{false};
    };

    struct ShutdownResult final
    {
        bool SetupSucceeded{false};
        std::string SetupStage{"NotStarted"};
        Failure SetupFailure{};
        bool ServerSettingsReceived{false};
        bool NextFrameReadPending{false};
        bool CancelAccepted{false};
        bool RootCompleted{false};
        bool RootSucceeded{false};
        bool RootRetired{false};
        bool RootActivityDrained{false};
        bool ServerActivityDrained{false};
        bool ServerActivityRetired{false};
        bool ServerCloseForwarded{false};
        bool ChildActivityDrained{false};
        bool ChildActivityRetired{false};
        bool ActiveTransportsFinalized{false};
        Failure RootFailure{};
        Failure RootActivityFailure{};
        Failure ServerActivityFailure{};
        Failure ChildActivityFailure{};
        Failure ActiveTransportsFailure{};
        std::exception_ptr RootException;
        std::exception_ptr ScenarioException;
    };

    struct ShutdownFixture final
    {
        explicit ShutdownFixture(Net::any_io_executor Executor)
            : RootCompleted(Executor, 1U)
        {
        }

        Preview::SharedTransmission Client;
        std::shared_ptr<ReadProbeTransmission> Server;
        std::shared_ptr<Preview::Contract::MuxSession> Owner;
        std::shared_ptr<Preview::Contract::CarrierActivity> Activity;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        Preview::Runtime::ActiveTransports ActiveTransports;
        Net::experimental::channel<void(boost::system::error_code)> RootCompleted;
        Outcome RootOutcome;
        std::exception_ptr RootException;
        ShutdownResult Result;
    };

    /** @brief 在发送 frame 时循环处理短写与真实传输错误。 */
    [[nodiscard]] auto WriteAll(
        const Preview::SharedTransmission &Stream,
        const std::span<const std::byte> Bytes) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0U;
        while (Offset < Bytes.size())
        {
            const auto Result = co_await Stream->WriteSome(Bytes.subspan(Offset));
            if (Result.Failure.Failed() || Result.Bytes == 0U ||
                Result.Bytes > Bytes.size() - Offset)
            {
                co_return false;
            }
            Offset += Result.Bytes;
        }
        co_return true;
    }

    /** @brief 读取一条 AnyTLS frame 并返回命令字；畸形或 EOF 返回 0xff。 */
    [[nodiscard]] auto ReadCommand(const Preview::SharedTransmission &Stream)
        -> Net::awaitable<std::uint8_t>
    {
        std::array<std::byte, 7> Header{};
        const auto HeaderRead = co_await Stream->ReadExact(Header);
        if (HeaderRead.Failure.Failed()) co_return 0xffU;
        const auto Length = (std::to_integer<std::size_t>(Header[5]) << 8U) |
                            std::to_integer<std::size_t>(Header[6]);
        std::vector<std::byte> Payload(Length);
        const auto PayloadRead = co_await Stream->ReadExact(Payload);
        if (PayloadRead.Failure.Failed()) co_return 0xffU;
        co_return std::to_integer<std::uint8_t>(Header[0]);
    }

    /** @brief 构造 AnyTLS ingress 输入并为本次根会话固定 GenerationUseState。 */
    [[nodiscard]] auto MakeAcceptInput(
        Preview::SharedTransmission Inbound,
        const std::shared_ptr<Preview::Foundation::GenerationUseState> &UseState)
        -> Preview::Contract::StreamAcceptInput
    {
        Preview::Contract::StreamAcceptInput Input{
            std::move(Inbound), {},
            std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 8U})};
        Input.GenerationUseState = UseState;
        return Input;
    }

    /** @brief 完成认证、SETTINGS 后在确定的下一次 frame 读上触发本地或外部取消。 */
    [[nodiscard]] auto RunShutdownScenario(
        const std::shared_ptr<ShutdownFixture> &State,
        const bool StopOwner) -> Net::awaitable<void>
    {
        State->Result.SetupStage = "MemoryPair";
        auto [ClientRaw, ServerRaw] = Preview::MakeMemoryPair(
            co_await Net::this_coro::executor);
        State->Client = std::make_shared<Preview::MemoryStream>(std::move(ClientRaw));
        auto RawServer = std::make_shared<Preview::MemoryStream>(std::move(ServerRaw));
        State->Server = std::make_shared<ReadProbeTransmission>(std::move(RawServer));

        std::string Auth;
        State->Result.SetupStage = "BuildAuthFrame";
        if (Preview::Anytls::BuildAuthFrame("shutdown-secret", 0U, Auth) != Preview::Error::None)
        {
            co_return;
        }
        State->Result.SetupStage = "WriteAuthFrame";
        if (!co_await WriteAll(State->Client, std::as_bytes(std::span(Auth)))) co_return;

        State->UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        Preview::Anytls::IngressFactory Factory({.Configuration = {"shutdown-secret"},
            .Streams = {.Egress = std::make_shared<IdleEgress>()}});
        State->Result.SetupStage = "FactoryAccept";
        auto Accepted = co_await Factory.Accept(MakeAcceptInput(State->Server, State->UseState));
        if (!Accepted)
        {
            State->Result.SetupFailure = Accepted.error();
            co_return;
        }
        State->Owner = Accepted->Mux()->Session;
        State->Activity = State->Owner->Activity();
        State->Result.SetupStage = "CarrierDomain";
        const auto Domain = Preview::Runtime::CarrierDomain::Create(
            State->Activity->Executor(), State->Activity);
        if (!Domain)
        {
            State->Result.SetupFailure = Domain.error();
            co_return;
        }
        Preview::Contract::MuxRootRequest Request;
        Request.Lease = std::move(Accepted->AccountLease);
        Request.GenerationUseState = State->UseState;
        State->Result.SetupStage = "StoreMux";
        auto Stored = State->ActiveTransports.StoreMux(State->Owner, *Domain);
        if (!Stored)
        {
            State->Result.SetupFailure = Stored.error();
            co_return;
        }
        State->Result.SetupSucceeded = true;
        State->Result.SetupStage = "RootRun";
        auto RunOwner = std::move(*Stored);
        const auto RunExecutor = RunOwner->Activity()->Executor();
        auto Run = RunOwner->Run(std::move(Request));
        Net::co_spawn(RunExecutor, std::move(Run),
            [State, RunOwner = std::move(RunOwner)](std::exception_ptr Error, Outcome Result) mutable
            {
                (void)RunOwner;
                State->RootException = std::move(Error);
                State->RootOutcome = std::move(Result);
                State->Result.RootCompleted = true;
                (void)State->RootCompleted.try_send(boost::system::error_code{});
            });

        co_await State->Server->WaitForPendingRead();
        constexpr std::string_view SettingsText{"v=2\nclient=shutdown-test\n"};
        const auto SettingsBytes = std::as_bytes(std::span(SettingsText));
        auto Settings = Preview::Anytls::Encode({Preview::Anytls::Command::Settings, 0U,
            std::vector<std::byte>(SettingsBytes.begin(), SettingsBytes.end())});
        if (!co_await WriteAll(State->Client, Settings))
        {
            const auto Finalized = co_await State->ActiveTransports.Finalize();
            State->Result.ActiveTransportsFinalized = static_cast<bool>(Finalized);
            if (!Finalized) State->Result.ActiveTransportsFailure = Finalized.error();
            co_return;
        }
        State->Result.ServerSettingsReceived =
            co_await ReadCommand(State->Client) ==
            static_cast<std::uint8_t>(Preview::Anytls::Command::ServerSettings);
        if (!State->Result.ServerSettingsReceived)
        {
            const auto Finalized = co_await State->ActiveTransports.Finalize();
            State->Result.ActiveTransportsFinalized = static_cast<bool>(Finalized);
            if (!Finalized) State->Result.ActiveTransportsFailure = Finalized.error();
            co_return;
        }

        co_await State->Server->WaitForPendingRead();
        State->Result.NextFrameReadPending = true;
        if (StopOwner)
        {
            const auto Finalized = co_await State->ActiveTransports.Finalize();
            State->Result.ActiveTransportsFinalized = static_cast<bool>(Finalized);
            if (!Finalized) State->Result.ActiveTransportsFailure = Finalized.error();
        }
        else
        {
            State->Result.CancelAccepted = static_cast<bool>(State->Server->Cancel());
            co_await State->RootCompleted.async_receive(Net::use_awaitable);
            const auto Finalized = co_await State->ActiveTransports.Finalize();
            State->Result.ActiveTransportsFinalized = static_cast<bool>(Finalized);
            if (!Finalized) State->Result.ActiveTransportsFailure = Finalized.error();
        }
        if (StopOwner) co_await State->RootCompleted.async_receive(Net::use_awaitable);

        State->Result.RootSucceeded = static_cast<bool>(State->RootOutcome);
        if (!State->RootOutcome) State->Result.RootFailure = State->RootOutcome.error();
        State->Result.RootRetired = State->Owner->IsRetired();
        State->Result.RootException = State->RootException;
        State->Result.ServerCloseForwarded = State->Server->CloseForwarded();
        const auto ChildActivity = State->Server->ChildActivity();
        ChildActivity->Seal();
        const auto ChildDrain = co_await ChildActivity->Drain();
        State->Result.ChildActivityDrained = static_cast<bool>(ChildDrain);
        State->Result.ChildActivityRetired = ChildActivity->IsRetired();
        if (!ChildDrain) State->Result.ChildActivityFailure = ChildDrain.error();
        const auto ServerActivity = State->Server->Activity();
        ServerActivity->Seal();
        const auto ServerDrain = co_await ServerActivity->Drain();
        State->Result.ServerActivityDrained = static_cast<bool>(ServerDrain);
        State->Result.ServerActivityRetired = ServerActivity->IsRetired();
        if (!ServerDrain) State->Result.ServerActivityFailure = ServerDrain.error();
        State->Activity->Seal();
        const auto ActivityDrain = co_await State->Activity->Drain();
        State->Result.RootActivityDrained = static_cast<bool>(ActivityDrain);
        if (!ActivityDrain) State->Result.RootActivityFailure = ActivityDrain.error();

    }

    /** @brief 运行一次真实 AnyTLS owner 场景并收集根、Activity 与 ActiveTransports 回执。 */
    [[nodiscard]] auto ExecuteShutdownScenario(const bool StopOwner) -> ShutdownResult
    {
        Net::io_context Io;
        auto State = std::make_shared<ShutdownFixture>(Io.get_executor());
        Net::co_spawn(Io, RunShutdownScenario(State, StopOwner),
            [State](std::exception_ptr Error)
            {
                State->Result.ScenarioException = std::move(Error);
            });
        Io.run();
        return State->Result;
    }
}

TEST(AnytlsSessionShutdown, OwnerCloseDrainsCanceledIdleFrameRead)
{
    const auto Result = ExecuteShutdownScenario(true);

    ASSERT_FALSE(Result.RootException);
    ASSERT_FALSE(Result.ScenarioException);
    ASSERT_TRUE(Result.SetupSucceeded) << "stage=" << Result.SetupStage
                                       << " code=" << static_cast<unsigned>(Result.SetupFailure.Code);
    ASSERT_TRUE(Result.ServerSettingsReceived);
    ASSERT_TRUE(Result.NextFrameReadPending);
    ASSERT_TRUE(Result.RootCompleted);
    EXPECT_TRUE(Result.RootSucceeded);
    EXPECT_TRUE(Result.RootFailure.Succeeded());
    EXPECT_TRUE(Result.RootRetired);
    EXPECT_TRUE(Result.RootActivityDrained);
    EXPECT_TRUE(Result.ServerActivityDrained);
    EXPECT_TRUE(Result.ServerActivityRetired);
    EXPECT_TRUE(Result.ServerCloseForwarded);
    EXPECT_TRUE(Result.ChildActivityDrained);
    EXPECT_TRUE(Result.ChildActivityRetired);
    EXPECT_TRUE(Result.ActiveTransportsFinalized);
}

TEST(AnytlsSessionShutdown, ExternalCancelWithoutOwnerStopRemainsFailure)
{
    const auto Result = ExecuteShutdownScenario(false);

    ASSERT_FALSE(Result.RootException);
    ASSERT_FALSE(Result.ScenarioException);
    ASSERT_TRUE(Result.SetupSucceeded) << "stage=" << Result.SetupStage
                                       << " code=" << static_cast<unsigned>(Result.SetupFailure.Code);
    ASSERT_TRUE(Result.ServerSettingsReceived);
    ASSERT_TRUE(Result.NextFrameReadPending);
    ASSERT_TRUE(Result.CancelAccepted);
    ASSERT_TRUE(Result.RootCompleted);
    EXPECT_FALSE(Result.RootSucceeded);
    EXPECT_EQ(Result.RootFailure.Code, Preview::Fault::Code::Canceled);
    EXPECT_TRUE(Result.RootRetired);
    EXPECT_FALSE(Result.RootActivityDrained);
    EXPECT_EQ(Result.RootActivityFailure.Code, Preview::Fault::Code::Canceled);
    EXPECT_FALSE(Result.ActiveTransportsFinalized);
    EXPECT_EQ(Result.ActiveTransportsFailure.Code, Preview::Fault::Code::Canceled);
}
