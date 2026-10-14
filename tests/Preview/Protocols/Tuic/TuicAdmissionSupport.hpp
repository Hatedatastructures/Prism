#pragma once

/**
 * @file TuicAdmissionSupport.hpp
 * @brief TUIC admission 测试共享认证、传输和账户租约 fixture。
 */
#pragma once

#include <Preview/Account/Account.hpp>
#include <Preview/Protocols/Tuic/Admission.hpp>
#include <Preview/Protocols/Common/IoBridge.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include <TestSupport/Preview/QuicStreamProviderActivity.hpp>

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/system/system_error.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/experimental/channel_error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Gate = Net::experimental::channel<void(boost::system::error_code)>;

    constexpr std::array<std::uint8_t, Preview::Tuic::UuidLen> TestUuid{
        0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
        0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    constexpr std::string_view ExporterContext{"exporter-password"};
    constexpr std::string_view StaticPassword{"static-password"};

    class ScriptedTransmission final : public Preview::Transmission
    {
    public:
        ScriptedTransmission(
            Net::any_io_executor Executor,
            std::vector<std::byte> Input = {},
            bool WaitAtEnd = false)
            : Preview::Transmission(Executor),
              Executor_(std::move(Executor)),
              Input_(std::move(Input)),
              WaitAtEnd_(WaitAtEnd),
              ReadCancelled_(Executor_, 1)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Preview::Protocols::StartPartialRead(
                Preview::Protocols::PartialReadInput<ScriptedTransmission>{
                    std::static_pointer_cast<ScriptedTransmission>(
                        Preview::Transmission::shared_from_this()),
                    Buffer, Executor_},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Preview::Protocols::StartPartialWrite(
                Preview::Protocols::PartialWriteInput<ScriptedTransmission>{
                    std::static_pointer_cast<ScriptedTransmission>(
                        Preview::Transmission::shared_from_this()),
                    Buffer, Executor_},
                std::move(Handler));
        }

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际内层转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Preview::Transport::Detail::PostResult(Executor_, std::move(Handler), {});
        }

        /** @brief 测试传输的有界部分读取；字节数与原生失败在同一 IoResult 中返回。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer) -> Net::awaitable<Preview::IoResult>
        {
            ++ReadCalls_;
            if (ReadStarted_)
            {
                auto Callback = std::move(ReadStarted_);
                ReadStarted_ = {};
                Callback();
            }
            if (Closed_)
            {
                co_return Preview::IoResult{0, Preview::Fault::FromNative(
                    std::make_error_code(std::errc::operation_canceled))};
            }
            if (ReadOffset_ < Input_.size())
            {
                const auto Count = (std::min)(Buffer.size(), Input_.size() - ReadOffset_);
                std::copy_n(Input_.begin() + static_cast<std::ptrdiff_t>(ReadOffset_),
                    Count, Buffer.begin());
                ReadOffset_ += Count;
                co_return Preview::IoResult{Count, {}};
            }
            if (!WaitAtEnd_)
            {
                co_return Preview::IoResult{};
            }
            co_await ReadCancelled_.async_receive(Net::use_awaitable);
            co_return Preview::IoResult{0, Preview::Fault::FromNative(
                std::make_error_code(std::errc::operation_canceled))};
        }

        /** @brief 测试传输的有界部分写入；保留实际短写字节数。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Preview::IoResult>
        {
            if (Closed_)
            {
                co_return Preview::IoResult{0, Preview::Fault::FromNative(
                    std::make_error_code(std::errc::broken_pipe))};
            }
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
            co_return Preview::IoResult{Buffer.size(), {}};
        }

        /** @brief 原 Close() 函数体原位保留，控制结果只表达命令已交付。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            ++CloseCalls_;
            Closed_ = true;
            (void)ReadCancelled_.try_send(boost::system::error_code{});
            return {};
        }

        /** @brief 原 Cancel() 函数体原位保留，控制结果只表达命令已交付。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++CancelCalls_;
            Closed_ = true;
            (void)ReadCancelled_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        void SetReadStarted(std::function<void()> Callback)
        {
            ReadStarted_ = std::move(Callback);
        }

        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t
        {
            return ReadCalls_;
        }

        [[nodiscard]] auto CancelCalls() const noexcept -> std::size_t
        {
            return CancelCalls_;
        }

    private:
        Net::any_io_executor Executor_;
        std::vector<std::byte> Input_;
        std::vector<std::byte> Written_{};
        bool WaitAtEnd_{false};
        bool Closed_{false};
        std::size_t ReadOffset_{0};
        std::size_t ReadCalls_{0};
        std::size_t CloseCalls_{0};
        std::size_t CancelCalls_{0};
        std::function<void()> ReadStarted_{};
        Net::experimental::channel<void(boost::system::error_code)> ReadCancelled_;
    };

    /** @brief 把 typed 脚本结果适配到现有 QUIC provider 的原生错误边界。 */
    class ScriptedStreamProvider final : public Preview::Quic::StreamProvider
    {
    public:
        explicit ScriptedStreamProvider(std::shared_ptr<ScriptedTransmission> TransmissionValue)
            : Transmission_(std::move(TransmissionValue)),
              Activity_(std::make_shared<Preview::Testing::Quic::StreamProviderActivity>(
                  Transmission_->Executor(), Transmission_->Activity())),
              StreamId_(NextStreamId_.fetch_add(1, std::memory_order_relaxed))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Transmission_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Read(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                ErrorCode = Preview::Fault::ToNative(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                co_return 0;
            }
            const auto Result = co_await Transmission_->ReadPartial(Buffer);
            ErrorCode = Preview::Fault::ToNative(Result.Failure);
            co_return Result.Bytes;
        }

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                ErrorCode = Preview::Fault::ToNative(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                co_return 0;
            }
            const auto Result = co_await Transmission_->WritePartial(Buffer);
            ErrorCode = Preview::Fault::ToNative(Result.Failure);
            co_return Result.Bytes;
        }

        [[nodiscard]] auto Close() -> Preview::Quic::StreamProvider::ControlResult override
        {
            if (Closed_)
            {
                return {};
            }
            Closed_ = true;
            const auto Cancel = Transmission_->Cancel();
            const auto Closed = Transmission_->Close();
            if (!Closed)
            {
                Activity_->FailClose(Closed.error());
                return std::unexpected(Closed.error());
            }
            Activity_->CompleteClose();
            if (!Cancel)
            {
                return std::unexpected(Cancel.error());
            }
            return {};
        }

        auto ShutdownWrite()
            -> Net::awaitable<Preview::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            WriteShutdown_ = true;
            co_return Preview::Quic::StreamProvider::ShutdownResult{};
        }
        auto WaitForWriteAcknowledgement()
            -> Net::awaitable<Preview::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            if (!WriteShutdown_)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            co_return Preview::Quic::StreamProvider::ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return StreamId_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_ || !Transmission_->IsOpen();
        }

    private:
        inline static std::atomic<std::int64_t> NextStreamId_{1};
        std::shared_ptr<ScriptedTransmission> Transmission_;
        std::shared_ptr<Preview::Testing::Quic::StreamProviderActivity> Activity_;
        std::int64_t StreamId_{0};
        bool Closed_{false};
        bool WriteShutdown_{false};
    };

    /** @brief 同时保留计数传输 owner 与 Admission 所有的 provider owner。 */
    struct ScriptedStream final
    {
        std::shared_ptr<ScriptedTransmission> Transmission;
        std::shared_ptr<ScriptedStreamProvider> Provider;
    };

    /** @brief 创建具有原始 wire 输入与独立传输计数的脚本 QUIC 流。 */
    [[nodiscard]] auto MakeScriptedStream(
        Net::any_io_executor Executor,
        std::vector<std::byte> Input = {},
        bool WaitAtEnd = false) -> ScriptedStream
    {
        auto TransmissionValue = std::make_shared<ScriptedTransmission>(
            std::move(Executor), std::move(Input), WaitAtEnd);
        auto Provider = std::make_shared<ScriptedStreamProvider>(TransmissionValue);
        return {std::move(TransmissionValue), std::move(Provider)};
    }

    class ScriptedDatagramProvider final : public Preview::Quic::DatagramProvider
    {
    public:
        ScriptedDatagramProvider(Net::any_io_executor Executor, std::vector<std::byte> Input)
            : Executor_(std::move(Executor)), Input_(std::move(Input))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Receive(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            ++ReceiveCalls_;
            if (Consumed_ || Closed_)
            {
                ErrorCode = std::make_error_code(std::errc::operation_canceled);
                co_return 0;
            }
            if (Input_.size() > Buffer.size())
            {
                ErrorCode = std::make_error_code(std::errc::message_size);
                co_return 0;
            }
            std::copy(Input_.begin(), Input_.end(), Buffer.begin());
            Consumed_ = true;
            ErrorCode.clear();
            co_return Input_.size();
        }

        [[nodiscard]] auto Send(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            Sent_.assign(Buffer.begin(), Buffer.end());
            ++SendCalls_;
            ErrorCode.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
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

        [[nodiscard]] auto ReceiveCalls() const noexcept -> std::size_t
        {
            return ReceiveCalls_;
        }

        [[nodiscard]] auto SendCalls() const noexcept -> std::size_t
        {
            return SendCalls_;
        }

        [[nodiscard]] auto CancelCalls() const noexcept -> std::size_t
        {
            return CancelCalls_;
        }

        [[nodiscard]] auto Sent() const noexcept -> const std::vector<std::byte> &
        {
            return Sent_;
        }

    private:
        Net::any_io_executor Executor_;
        std::vector<std::byte> Input_;
        std::vector<std::byte> Sent_{};
        std::size_t ReceiveCalls_{0};
        std::size_t SendCalls_{0};
        std::size_t CancelCalls_{0};
        bool Consumed_{false};
        bool Closed_{false};
    };

    class CountingAuthenticator final : public Preview::Authenticator
    {
    public:
        explicit CountingAuthenticator(Preview::Account::CredentialIndexView View)
            : View_(std::move(View))
        {
        }

        [[nodiscard]] auto InspectCredential(
            const Preview::Account::CredentialView &Credential) const noexcept
            -> std::expected<bool, Preview::Fault::Failure> override
        {
            return View_.InspectCredential(Credential);
        }

        [[nodiscard]] auto Authenticate(const Preview::AuthenticationRequest &Request) const noexcept
            -> Preview::AuthenticationResult override
        {
            ++Calls_;
            if (DropLease_)
            {
                // 旧契约用 Accepted 加空 Lease 表示“认证成功却没有交出 lease”；
                // 新契约唯一形状是 expected<AccountLease>，因此返回成功但空的 lease，
                // 让 admission 的 lease 门禁继续拒绝该连接。
                return Preview::Account::AccountLease{};
            }
            return View_.TryAcquire(Request);
        }

        void DropLease() noexcept
        {
            DropLease_ = true;
        }

        [[nodiscard]] auto Calls() const noexcept -> std::size_t
        {
            return Calls_;
        }

    private:
        Preview::Account::CredentialIndexView View_;
        mutable std::size_t Calls_{0};
        bool DropLease_{false};
    };

    [[nodiscard]] auto TestExporter(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) -> bool
    {
        if (Label.empty() || Output.empty())
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Output.size(); ++Index)
        {
            const auto LabelByte = Label[Index % Label.size()];
            Output[Index] = static_cast<std::uint8_t>(LabelByte ^ Context.size() ^ (Index * 17U));
        }
        return true;
    }

    [[nodiscard]] auto ToBytes(const std::vector<std::uint8_t> &Input) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Input.size());
        for (const auto Value : Input)
        {
            Result.push_back(static_cast<std::byte>(Value));
        }
        return Result;
    }

    template <std::size_t Size>
    [[nodiscard]] auto ToBytes(const std::array<std::uint8_t, Size> &Input)
        -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Input.size());
        for (const auto Value : Input)
        {
            Result.push_back(static_cast<std::byte>(Value));
        }
        return Result;
    }

    [[nodiscard]] auto MakeAuthWire(std::string_view Context = ExporterContext)
        -> std::vector<std::byte>
    {
        std::array<std::uint8_t, Preview::Tuic::TokenLen> Token{};
        if (!TestExporter(Token, TestUuid, Context))
        {
            return {};
        }
        return ToBytes(Preview::Tuic::BuildAuthenticate(TestUuid, Token));
    }

    [[nodiscard]] auto MakeConnectWire() -> std::vector<std::byte>
    {
        Preview::Tuic::Message Message;
        Message.Cmd = Preview::Tuic::CmdConnect;
        Message.dst = {Preview::Tuic::AddressType::Domain, "example.com", 443};
        return ToBytes(Preview::Tuic::Build(Message));
    }

    [[nodiscard]] auto MakePacketWire() -> std::vector<std::byte>
    {
        Preview::Tuic::Message Message;
        Message.Cmd = Preview::Tuic::CmdPacket;
        Message.dst = {Preview::Tuic::AddressType::Domain, "example.com", 53};
        Message.payload = "request-payload";
        return ToBytes(Preview::Tuic::Build(Message));
    }

    class AdmissionHarness final
    {
    public:
        explicit AdmissionHarness(Net::io_context &Io) : Io_(Io)
        {
            Accounts_ = Preview::Testing::ProviderAccount(
                Preview::Account::Credential::Password(StaticPassword), Preview::AccountId(42),
                {.MaxConnections = 8, .MaxStreams = 8});
            Record_ = Accounts_->Store->FindById(Preview::AccountId(42));
            EXPECT_TRUE(Record_);
            Authenticator_ = std::make_shared<CountingAuthenticator>(Accounts_->Credentials);
        }

        void Install(
            Preview::Tuic::AdmissionServices Services = {},
            std::size_t MaxPendingBidiStreams = 8U)
        {
            const auto Executor = Io_.get_executor();
            if (!Services.Dial)
            {
                Services.Dial = [Executor](Preview::Tuic::DialRequest)
                    -> Net::awaitable<std::expected<Preview::SharedTransmission,
                        Preview::Fault::Failure>>
                {
                    co_return Preview::SharedTransmission{
                        std::make_shared<ScriptedTransmission>(Executor)};
                };
            }
            if (!Services.Resolve)
            {
                Services.Resolve = [](Preview::Tuic::ResolveRequest Request)
                    -> Net::awaitable<Preview::Tuic::ResolveResult>
                {
                    Request.Target.Type = Preview::Tuic::AddressType::Ipv4;
                    Request.Target.Host = "203.0.113.7";
                    co_return Preview::Tuic::ResolveResult{
                        Preview::Error::None, {std::move(Request.Target)}};
                };
            }
            if (!Services.RelayStream)
            {
                Services.RelayStream = [](Preview::Tuic::StreamRelayRequest)
                    -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
                {
                    co_return std::expected<void, Preview::Fault::Failure>{};
                };
            }
            if (!Services.ExchangeDatagram)
            {
                Services.ExchangeDatagram = [](Preview::Tuic::DatagramRequest Request)
                    -> Net::awaitable<Preview::Tuic::DatagramResult>
                {
                    co_return Preview::Tuic::DatagramResult{
                        Preview::Error::None,
                        std::move(Request.Target),
                        std::move(Request.Payload)};
                };
            }

            auto Options = BaseOptions();
            Options.MaxPendingBidiStreams = MaxPendingBidiStreams;
            auto AdmissionResult = Preview::Tuic::ConnectionAdmission::Create(
                std::move(Options), std::move(Services));
            if (!AdmissionResult)
                throw std::system_error(Preview::Fault::ToNative(AdmissionResult.error()));
            Admission_ = std::move(*AdmissionResult);
        }

        [[nodiscard]] auto BaseOptions() -> Preview::Tuic::AdmissionOptions
        {
            return Preview::Tuic::AdmissionOptions{
                .Executor = Io_.get_executor(),
                .Uuid = TestUuid,
                .ExporterContext = std::string(ExporterContext),
                .Credential = std::make_shared<const Preview::Account::Credential>(
                    Preview::Account::Credential::Password(StaticPassword)),
                .AuthenticatorOwner = Authenticator_,
                .MaxPendingBidiStreams = 8U,
                .CloseOwner = [this] { return CloseOwnerReceipt(); }};
        }

        [[nodiscard]] auto CloseOwnerReceipt()
            -> std::expected<void, Preview::Fault::Failure>
        {
            ++CloseOwnerCalls_;
            if (CloseOwnerObserver_)CloseOwnerObserver_();
            if (CloseOwnerFailuresRemaining_ != 0U)
            {
                --CloseOwnerFailuresRemaining_;
                return std::unexpected(CloseOwnerFailure_);
            }
            return {};
        }

        auto RejectNextCloseOwner(Preview::Fault::Failure Failure) -> void
        {
            RejectCloseOwner(1U, Failure);
        }

        auto RejectCloseOwner(
            const std::size_t Attempts,
            Preview::Fault::Failure Failure) -> void
        {
            CloseOwnerFailure_ = Failure;
            CloseOwnerFailuresRemaining_ = Attempts;
        }

        auto SetExpectedCloseOwnerCalls(const std::size_t Count) noexcept -> void
        {
            ExpectedCloseOwnerCalls_ = Count;
        }

        void SetCloseOwnerObserver(std::function<void()> Observer)
        {
            CloseOwnerObserver_ = std::move(Observer);
        }

        [[nodiscard]] auto Admission() const -> const std::shared_ptr<Preview::Tuic::ConnectionAdmission> &
        {
            return Admission_;
        }

        /** @brief 提交认证流并核对 Admission 同步接管结果。 */
        auto SubmitUnidirectional(Preview::Quic::SharedStreamProvider Provider) -> void
        {
            ExpectInputAccepted(Admission_->OnUnidirectional(std::move(Provider)), "authentication stream");
        }

        /** @brief 提交 TLS exporter 并核对 Admission 同步接管结果。 */
        auto SubmitExporter(Preview::Tuic::KeyingMaterialExporter Exporter) -> void
        {
            ExpectInputAccepted(Admission_->OnExporter(std::move(Exporter)), "TLS exporter");
        }

        /** @brief 提交 bidi stream 并核对 Admission 同步接管结果。 */
        auto SubmitBidirectional(Preview::Quic::SharedStreamProvider Provider) -> void
        {
            ExpectInputAccepted(Admission_->OnBidirectional(std::move(Provider)), "bidi stream");
        }

        /** @brief 提交 datagram provider 并核对 Admission 同步接管结果。 */
        auto SubmitDatagram(Preview::Quic::SharedDatagramProvider Provider) -> void
        {
            ExpectInputAccepted(Admission_->OnDatagram(std::move(Provider)), "datagram provider");
        }

        [[nodiscard]] auto Authenticator() const -> const std::shared_ptr<CountingAuthenticator> &
        {
            return Authenticator_;
        }

        [[nodiscard]] auto Record() const
            -> const std::shared_ptr<const Preview::Account::AccountBinding> &
        {
            return Record_;
        }

        [[nodiscard]] auto CloseOwnerCalls() const noexcept -> std::size_t
        {
            return CloseOwnerCalls_;
        }

        [[nodiscard]] auto TakeAdmission()
            -> std::shared_ptr<Preview::Tuic::ConnectionAdmission>
        {
            return std::exchange(Admission_, {});
        }

        auto CloseAndDrain() -> void
        {
            if (!Admission_)
            {
                return;
            }

            // CloseOwner runs after Closed_ is set; run() also drains cancelled child completions.
            Io_.restart();
            Admission_->OnClosed();
            Io_.run();
            bool DrainCompleted = false;
            bool DrainThrew = false;
            std::optional<Preview::Fault::Failure> DrainFailure;
            Io_.restart();
            Net::co_spawn(Io_, Admission_->Drain(),
                [&DrainCompleted, &DrainThrew, &DrainFailure](std::exception_ptr Error,
                    std::expected<void, Preview::Fault::Failure> Result)
                {
                    DrainThrew = static_cast<bool>(Error);
                    if (!Error && !Result) DrainFailure = Result.error();
                    DrainCompleted = !Error && static_cast<bool>(Result);
                });
            Io_.run();
            EXPECT_FALSE(DrainThrew);
            if (DrainFailure)
            {
                EXPECT_TRUE(DrainCompleted) << "Drain code="
                    << static_cast<int>(DrainFailure->Code)
                    << " native=" << DrainFailure->Native.value()
                    << " category=" << DrainFailure->Native.category().name();
            }
            else
            {
                EXPECT_TRUE(DrainCompleted);
            }
            EXPECT_EQ(CloseOwnerCalls_, ExpectedCloseOwnerCalls_);
            EXPECT_EQ(Record_->Runtime()->ActiveConnections(), 0U);
            EXPECT_EQ(Record_->Runtime()->ActiveStreams(), 0U);

            Admission_.reset();
            Io_.restart();
            Io_.run();
        }

    private:
        /** @brief 失败时打印事件提交边界的领域码与原生 cause。 */
        static auto ExpectInputAccepted(
            std::expected<void, Preview::Fault::Failure> Result,
            std::string_view Operation) -> void
        {
            if (Result) return;
            ADD_FAILURE() << Operation << " rejected: code="
                << static_cast<int>(Result.error().Code)
                << " native=" << Result.error().Native.value()
                << " category=" << Result.error().Native.category().name();
        }

        Net::io_context &Io_;
        std::shared_ptr<const Preview::Account::AccountBinding> Record_{};
        std::shared_ptr<Preview::Testing::ProviderAccounts> Accounts_{};
        std::shared_ptr<CountingAuthenticator> Authenticator_{};
        std::size_t CloseOwnerCalls_{0};
        std::size_t ExpectedCloseOwnerCalls_{1U};
        std::size_t CloseOwnerFailuresRemaining_{0U};
        Preview::Fault::Failure CloseOwnerFailure_{Preview::Fault::Code::Blocked};
        std::function<void()> CloseOwnerObserver_{};
        std::shared_ptr<Preview::Tuic::ConnectionAdmission> Admission_{};
    };
} // namespace
