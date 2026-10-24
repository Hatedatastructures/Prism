#pragma once

/**
 * @file TuicAdmissionSupport.hpp
 * @brief TUIC admission 测试共享认证、传输和账户租约 fixture。
 */
#pragma once

#include <Prism/Account/Account.hpp>
#include <Prism/Protocols/Tuic/Admission.hpp>
#include <Prism/Protocols/Common/IoBridge.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <TestSupport/Prism/QuicStreamProviderActivity.hpp>

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

    constexpr std::array<std::uint8_t, Prism::Tuic::UuidLen> TestUuid{
        0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
        0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    constexpr std::string_view ExporterContext{"exporter-password"};
    constexpr std::string_view StaticPassword{"static-password"};

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(
            Net::any_io_executor Executor,
            std::vector<std::byte> Input = {},
            bool WaitAtEnd = false)
            : Prism::Transmission(Executor),
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
            Prism::Protocols::StartPartialRead(
                Prism::Protocols::PartialReadInput<ScriptedTransmission>{
                    std::static_pointer_cast<ScriptedTransmission>(
                        Prism::Transmission::shared_from_this()),
                    Buffer, Executor_},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::Protocols::StartPartialWrite(
                Prism::Protocols::PartialWriteInput<ScriptedTransmission>{
                    std::static_pointer_cast<ScriptedTransmission>(
                        Prism::Transmission::shared_from_this()),
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
            Prism::Transmission::PostResult(Executor_, std::move(Handler), {});
        }

        /** @brief 测试传输的有界部分读取；字节数与原生失败在同一 IoResult 中返回。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer) -> Net::awaitable<Prism::IoResult>
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
                co_return Prism::IoResult{0, Prism::Fault::FromNative(
                    std::make_error_code(std::errc::operation_canceled))};
            }
            if (ReadOffset_ < Input_.size())
            {
                const auto Count = (std::min)(Buffer.size(), Input_.size() - ReadOffset_);
                std::copy_n(Input_.begin() + static_cast<std::ptrdiff_t>(ReadOffset_),
                    Count, Buffer.begin());
                ReadOffset_ += Count;
                co_return Prism::IoResult{Count, {}};
            }
            if (!WaitAtEnd_)
            {
                co_return Prism::IoResult{};
            }
            co_await ReadCancelled_.async_receive(Net::use_awaitable);
            co_return Prism::IoResult{0, Prism::Fault::FromNative(
                std::make_error_code(std::errc::operation_canceled))};
        }

        /** @brief 测试传输的有界部分写入；保留实际短写字节数。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            if (Closed_)
            {
                co_return Prism::IoResult{0, Prism::Fault::FromNative(
                    std::make_error_code(std::errc::broken_pipe))};
            }
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
            co_return Prism::IoResult{Buffer.size(), {}};
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
    class ScriptedStreamProvider final : public Prism::Quic::StreamProvider
    {
    public:
        explicit ScriptedStreamProvider(std::shared_ptr<ScriptedTransmission> TransmissionValue)
            : Transmission_(std::move(TransmissionValue)),
              Activity_(std::make_shared<Prism::Testing::Quic::StreamProviderActivity>(
                  Transmission_->Executor(), Transmission_->Activity())),
              StreamId_(NextStreamId_.fetch_add(1, std::memory_order_relaxed))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Transmission_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
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
                ErrorCode = Prism::Fault::ToNative(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                co_return 0;
            }
            const auto Result = co_await Transmission_->ReadPartial(Buffer);
            ErrorCode = Prism::Fault::ToNative(Result.Failure);
            co_return Result.Bytes;
        }

        [[nodiscard]] auto Write(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                ErrorCode = Prism::Fault::ToNative(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                co_return 0;
            }
            const auto Result = co_await Transmission_->WritePartial(Buffer);
            ErrorCode = Prism::Fault::ToNative(Result.Failure);
            co_return Result.Bytes;
        }

        [[nodiscard]] auto Close() -> Prism::Quic::StreamProvider::ControlResult override
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
            -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            WriteShutdown_ = true;
            co_return Prism::Quic::StreamProvider::ShutdownResult{};
        }
        auto WaitForWriteAcknowledgement()
            -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult> override
        {
            const auto Operation = Activity_->BeginOperation();
            if (!Operation)
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            }
            if (!WriteShutdown_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            co_return Prism::Quic::StreamProvider::ShutdownResult{};
        }

        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override
        {
            return StreamId_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return Closed_ || !Transmission_->IsOpen();
        }

        /** @brief 模拟对端 FIN 已到达、但流内仍有尚待读取的数据。 */
        auto MarkPeerFin() noexcept -> void
        {
            PeerFin_ = true;
        }

    private:
        inline static std::atomic<std::int64_t> NextStreamId_{1};
        std::shared_ptr<ScriptedTransmission> Transmission_;
        std::shared_ptr<Prism::Testing::Quic::StreamProviderActivity> Activity_;
        std::int64_t StreamId_{0};
        bool Closed_{false};
        bool PeerFin_{false};
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

    class ScriptedDatagramProvider final : public Prism::Quic::DatagramProvider
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

    class CountingAuthenticator final : public Prism::Authenticator
    {
    public:
        explicit CountingAuthenticator(Prism::Account::CredentialIndexView View)
            : View_(std::move(View))
        {
        }

        [[nodiscard]] auto InspectCredential(
            const Prism::Account::CredentialView &Credential) const noexcept
            -> std::expected<bool, Prism::Fault::Failure> override
        {
            return View_.InspectCredential(Credential);
        }

        [[nodiscard]] auto Authenticate(const Prism::AuthenticationRequest &Request) const noexcept
            -> Prism::AuthenticationResult override
        {
            ++Calls_;
            if (DropLease_)
            {
                // 旧契约用 Accepted 加空 Lease 表示“认证成功却没有交出 lease”；
                // 新契约唯一形状是 expected<AccountLease>，因此返回成功但空的 lease，
                // 让 admission 的 lease 门禁继续拒绝该连接。
                return Prism::Account::AccountLease{};
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
        Prism::Account::CredentialIndexView View_;
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
        std::array<std::uint8_t, Prism::Tuic::TokenLen> Token{};
        if (!TestExporter(Token, TestUuid, Context))
        {
            return {};
        }
        return ToBytes(Prism::Tuic::BuildAuthenticate(TestUuid, Token));
    }

    [[nodiscard]] auto MakeConnectWire() -> std::vector<std::byte>
    {
        Prism::Tuic::Message Message;
        Message.Cmd = Prism::Tuic::CmdConnect;
        Message.dst = {Prism::Tuic::AddressType::Domain, "example.com", 443};
        return ToBytes(Prism::Tuic::Build(Message));
    }

    [[nodiscard]] auto MakePacketWire() -> std::vector<std::byte>
    {
        Prism::Tuic::Message Message;
        Message.Cmd = Prism::Tuic::CmdPacket;
        Message.dst = {Prism::Tuic::AddressType::Domain, "example.com", 53};
        Message.payload = "request-payload";
        return ToBytes(Prism::Tuic::Build(Message));
    }

    class AdmissionHarness final
    {
    public:
        explicit AdmissionHarness(Net::io_context &Io) : Io_(Io)
        {
            Accounts_ = Prism::Testing::ProviderAccount(
                Prism::Account::Credential::Password(StaticPassword), Prism::AccountId(42),
                {.MaxConnections = 8, .MaxStreams = 8});
            Record_ = Accounts_->Store->FindById(Prism::AccountId(42));
            EXPECT_TRUE(Record_);
            Authenticator_ = std::make_shared<CountingAuthenticator>(Accounts_->Credentials);
        }

        void Install(
            Prism::Tuic::AdmissionServices Services = {},
            std::size_t MaxPendingBidiStreams = 8U)
        {
            const auto Executor = Io_.get_executor();
            if (!Services.Dial)
            {
                Services.Dial = [Executor](Prism::Tuic::DialRequest)
                    -> Net::awaitable<std::expected<Prism::SharedTransmission,
                        Prism::Fault::Failure>>
                {
                    co_return Prism::SharedTransmission{
                        std::make_shared<ScriptedTransmission>(Executor)};
                };
            }
            if (!Services.Resolve)
            {
                Services.Resolve = [](Prism::Tuic::ResolveRequest Request)
                    -> Net::awaitable<Prism::Tuic::ResolveResult>
                {
                    Request.Target.Type = Prism::Tuic::AddressType::Ipv4;
                    Request.Target.Host = "203.0.113.7";
                    co_return Prism::Tuic::ResolveResult{
                        Prism::Error::None, {std::move(Request.Target)}};
                };
            }
            if (!Services.RelayStream)
            {
                Services.RelayStream = [](Prism::Tuic::StreamRelayRequest)
                    -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                };
            }
            if (!Services.ExchangeDatagram)
            {
                Services.ExchangeDatagram = [](Prism::Tuic::DatagramRequest Request)
                    -> Net::awaitable<Prism::Tuic::DatagramResult>
                {
                    co_return Prism::Tuic::DatagramResult{
                        Prism::Error::None,
                        std::move(Request.Target),
                        std::move(Request.Payload)};
                };
            }

            auto Options = BaseOptions();
            Options.MaxPendingBidiStreams = MaxPendingBidiStreams;
            auto AdmissionResult = Prism::Tuic::ConnectionAdmission::Create(
                std::move(Options), std::move(Services));
            if (!AdmissionResult)
                throw std::system_error(Prism::Fault::ToNative(AdmissionResult.error()));
            Admission_ = std::move(*AdmissionResult);
        }

        [[nodiscard]] auto BaseOptions() -> Prism::Tuic::AdmissionOptions
        {
            return Prism::Tuic::AdmissionOptions{
                .Executor = Io_.get_executor(),
                .Uuid = TestUuid,
                .ExporterContext = std::string(ExporterContext),
                .Credential = std::make_shared<const Prism::Account::Credential>(
                    Prism::Account::Credential::Password(StaticPassword)),
                .AuthenticatorOwner = Authenticator_,
                .MaxPendingBidiStreams = 8U,
                .CloseOwner = [this] { return CloseOwnerReceipt(); }};
        }

        [[nodiscard]] auto CloseOwnerReceipt()
            -> std::expected<void, Prism::Fault::Failure>
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

        auto RejectNextCloseOwner(Prism::Fault::Failure Failure) -> void
        {
            RejectCloseOwner(1U, Failure);
        }

        auto RejectCloseOwner(
            const std::size_t Attempts,
            Prism::Fault::Failure Failure) -> void
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

        [[nodiscard]] auto Admission() const -> const std::shared_ptr<Prism::Tuic::ConnectionAdmission> &
        {
            return Admission_;
        }

        /** @brief 提交认证流并核对 Admission 同步接管结果。 */
        auto SubmitUnidirectional(Prism::Quic::SharedStreamProvider Provider) -> void
        {
            ExpectInputAccepted(Admission_->OnUnidirectional(std::move(Provider)), "authentication stream");
        }

        /** @brief 提交 TLS exporter 并核对 Admission 同步接管结果。 */
        auto SubmitExporter(Prism::Tuic::KeyingMaterialExporter Exporter) -> void
        {
            ExpectInputAccepted(Admission_->OnExporter(std::move(Exporter)), "TLS exporter");
        }

        /** @brief 提交 bidi stream 并核对 Admission 同步接管结果。 */
        auto SubmitBidirectional(Prism::Quic::SharedStreamProvider Provider) -> void
        {
            ExpectInputAccepted(Admission_->OnBidirectional(std::move(Provider)), "bidi stream");
        }

        /** @brief 提交 datagram provider 并核对 Admission 同步接管结果。 */
        auto SubmitDatagram(Prism::Quic::SharedDatagramProvider Provider) -> void
        {
            ExpectInputAccepted(Admission_->OnDatagram(std::move(Provider)), "datagram provider");
        }

        [[nodiscard]] auto Authenticator() const -> const std::shared_ptr<CountingAuthenticator> &
        {
            return Authenticator_;
        }

        [[nodiscard]] auto Record() const
            -> const std::shared_ptr<const Prism::Account::AccountBinding> &
        {
            return Record_;
        }

        [[nodiscard]] auto CloseOwnerCalls() const noexcept -> std::size_t
        {
            return CloseOwnerCalls_;
        }

        [[nodiscard]] auto TakeAdmission()
            -> std::shared_ptr<Prism::Tuic::ConnectionAdmission>
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
            bool DrainCompleted = !Admission_;
            bool DrainThrew = false;
            std::optional<Prism::Fault::Failure> DrainFailure;
            Io_.restart();
            Net::co_spawn(Io_, Admission_->Drain(),
                [&DrainCompleted, &DrainThrew, &DrainFailure](std::exception_ptr Error,
                    std::expected<void, Prism::Fault::Failure> Result)
                {
                    DrainThrew = static_cast<bool>(Error);
                    if (!Error && !Result) DrainFailure = Result.error();
                    DrainCompleted = !Error;
                });
            Io_.run();
            EXPECT_FALSE(DrainThrew);
            EXPECT_TRUE(DrainCompleted);
            ASSERT_FALSE(DrainFailure) << "Drain code="
                << static_cast<int>(DrainFailure->Code)
                << " native=" << DrainFailure->Native.value()
                << " category=" << DrainFailure->Native.category().name();
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
            std::expected<void, Prism::Fault::Failure> Result,
            std::string_view Operation) -> void
        {
            if (Result) return;
            ADD_FAILURE() << Operation << " rejected: code="
                << static_cast<int>(Result.error().Code)
                << " native=" << Result.error().Native.value()
                << " category=" << Result.error().Native.category().name();
        }

        Net::io_context &Io_;
        std::shared_ptr<const Prism::Account::AccountBinding> Record_{};
        std::shared_ptr<Prism::Testing::ProviderAccounts> Accounts_{};
        std::shared_ptr<CountingAuthenticator> Authenticator_{};
        std::size_t CloseOwnerCalls_{0};
        std::size_t ExpectedCloseOwnerCalls_{1U};
        std::size_t CloseOwnerFailuresRemaining_{0U};
        Prism::Fault::Failure CloseOwnerFailure_{Prism::Fault::Code::Blocked};
        std::function<void()> CloseOwnerObserver_{};
        std::shared_ptr<Prism::Tuic::ConnectionAdmission> Admission_{};
    };
} // namespace
