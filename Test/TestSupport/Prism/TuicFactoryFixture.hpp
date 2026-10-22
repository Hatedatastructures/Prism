/**
 * @file TuicFactoryFixture.hpp
 * @brief TUIC factory 测试共用的模拟 provider、认证器与 fixture 声明。
 */

#pragma once

#include <gtest/gtest.h>
#include <Prism/Protocols/Tuic/Admission.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include <TestSupport/Prism/QuicStreamProviderActivity.hpp>
#include <Prism/Foundation/Executor/FatalState.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace Prism::Testing::TuicFactory
{

    namespace Net = boost::asio;

    using Gate = Net::experimental::channel<void(boost::system::error_code)>;

    struct AdmissionFixtureOptions final
    {
        Prism::Tuic::AdmissionOptions Admission;
        Prism::Tuic::AdmissionServices Services;
    };
    struct AdmissionEvents final
    {
        Prism::Quic::ServerOptions::ExporterHandler OnExporter;
        Prism::Quic::ServerOptions::UnidirectionalHandler OnUnidirectional;
        Prism::Quic::ServerOptions::StreamHandler OnStream;
        Prism::Quic::ServerOptions::DatagramHandler OnDatagram;
        std::function<void()> OnClosed;
        std::shared_ptr<Prism::Tuic::ConnectionAdmission> Owner;
    };

    class ScriptedStreamProvider final : public Prism::Quic::StreamProvider
    {
    public:
        ScriptedStreamProvider(Net::any_io_executor Executor, std::vector<std::byte> Input);
        ~ScriptedStreamProvider() override;

        auto SetGate(std::shared_ptr<Gate> GateValue) -> void;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;
        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override;
        [[nodiscard]] auto Read(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override;
        [[nodiscard]] auto Write(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override;
        [[nodiscard]] auto Close() -> Prism::Quic::StreamProvider::ControlResult override;
        auto ShutdownWrite()
            -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult> override;
        auto WaitForWriteAcknowledgement()
            -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult> override;
        [[nodiscard]] auto StreamId() const noexcept -> std::int64_t override;
        [[nodiscard]] auto IsClosed() const noexcept -> bool override;
        [[nodiscard]] auto ReadCalls() const noexcept -> std::size_t;

    private:
        class Impl;
        std::unique_ptr<Impl> Impl_;
    };

    class RecordingDatagramProvider final : public Prism::Quic::DatagramProvider
    {
    public:
        explicit RecordingDatagramProvider(Net::any_io_executor Executor);
        ~RecordingDatagramProvider() override;

        auto Inject(std::vector<std::byte> Data) -> void;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;
        [[nodiscard]] auto Receive(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override;
        [[nodiscard]] auto Send(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override;
        auto Close() -> void override;
        auto Cancel() -> void override;
        [[nodiscard]] auto IsClosed() const noexcept -> bool override;
        [[nodiscard]] auto ReceiveCalls() const noexcept -> std::size_t;
        [[nodiscard]] auto SendCalls() const noexcept -> std::size_t;
        [[nodiscard]] auto CloseCalls() const noexcept -> std::size_t;

    private:
        class Impl;
        std::unique_ptr<Impl> Impl_;
    };

    class RecordingAuthenticator final : public Prism::Authenticator
    {
    public:
        RecordingAuthenticator(
            std::shared_ptr<Prism::Testing::ProviderAccounts> Accounts,
            std::shared_ptr<const Prism::Account::AccountBinding> Record);
        ~RecordingAuthenticator() override;

        [[nodiscard]] auto InspectCredential(
            const Prism::Account::CredentialView &Credential) const noexcept
            -> std::expected<bool, Prism::Fault::Failure> override;
        [[nodiscard]] auto Authenticate(const Prism::AuthenticationRequest &Request) const noexcept
            -> Prism::AuthenticationResult override;
        [[nodiscard]] auto Calls() const noexcept -> std::size_t;
        [[nodiscard]] auto LeaseHeldAtSuccess() const noexcept -> bool;

    private:
        class Impl;
        std::unique_ptr<Impl> Impl_;
    };

    [[nodiscard]] auto TestExporter(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) -> bool;
    [[nodiscard]] auto MakeConnectWire() -> std::vector<std::byte>;
    [[nodiscard]] auto MakePacketWire() -> std::vector<std::byte>;

    class TuicTestHarness final
    {
    public:
        TuicTestHarness();
        ~TuicTestHarness();

        TuicTestHarness(const TuicTestHarness &) = delete;
        auto operator=(const TuicTestHarness &) -> TuicTestHarness & = delete;

        [[nodiscard]] auto Configure() -> AdmissionEvents;
        auto CloseAndDrain(AdmissionEvents &Options) -> void;
        [[nodiscard]] auto ValidAuthWire() const -> std::vector<std::byte>;
        [[nodiscard]] auto InvalidAuthWire() const -> std::vector<std::byte>;
        [[nodiscard]] auto AccountActiveConnections() const noexcept -> std::uint32_t;
        [[nodiscard]] auto AccountActiveStreams() const noexcept -> std::uint32_t;
        [[nodiscard]] auto CompletionCalls() const noexcept -> std::size_t;
        [[nodiscard]] auto Installed() const noexcept -> bool;
        [[nodiscard]] auto Binding() -> AdmissionFixtureOptions &;
        [[nodiscard]] auto Authenticator() const
            -> const std::shared_ptr<RecordingAuthenticator> &;

        Net::io_context Io;

    private:
        class Impl;
        std::unique_ptr<Impl> Impl_;
    };


    namespace
    {
        [[nodiscard]] auto MakeUuid() -> std::array<std::uint8_t, Prism::Tuic::UuidLen>
        {
            return {0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
                    0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        }

        [[nodiscard]] auto ToBytes(const std::vector<std::uint8_t> &Data)
            -> std::vector<std::byte>
        {
            std::vector<std::byte> Result;
            Result.reserve(Data.size());
            for (const auto Byte : Data)
            {
                Result.push_back(static_cast<std::byte>(Byte));
            }
            return Result;
        }

        template <std::size_t Size>
        [[nodiscard]] auto ToBytes(const std::array<std::uint8_t, Size> &Data)
            -> std::vector<std::byte>
        {
            std::vector<std::byte> Result;
            Result.reserve(Data.size());
            for (const auto Byte : Data)
            {
                Result.push_back(static_cast<std::byte>(Byte));
            }
            return Result;
        }

        [[nodiscard]] auto MakeAuthWire(
            const std::array<std::uint8_t, Prism::Tuic::UuidLen> &Uuid,
            const std::array<std::uint8_t, Prism::Tuic::TokenLen> &Token)
            -> std::vector<std::byte>
        {
            return ToBytes(Prism::Tuic::BuildAuthenticate(Uuid, Token));
        }
    } // namespace

    class ScriptedStreamProvider::Impl final
    {
    public:
        Impl(Net::any_io_executor Executor, std::vector<std::byte> Input)
            : Executor_(std::move(Executor)), Input_(std::move(Input)),
              Activity_(std::make_shared<Prism::Testing::Quic::StreamProviderActivity>(Executor_))
        {
        }

        Net::any_io_executor Executor_;
        std::vector<std::byte> Input_;
        std::vector<std::byte> Written_;
        std::shared_ptr<Gate> Gate_;
        std::size_t ReadOffset_{0};
        std::size_t ReadCalls_{0};
        std::int64_t StreamId_{7};
        bool Closed_{false};
        bool WriteShutdown_{false};
        std::shared_ptr<Prism::Testing::Quic::StreamProviderActivity> Activity_;
    };

    inline ScriptedStreamProvider::ScriptedStreamProvider(
        Net::any_io_executor Executor,
        std::vector<std::byte> Input)
        : Impl_(std::make_unique<Impl>(std::move(Executor), std::move(Input)))
    {
    }

    inline ScriptedStreamProvider::~ScriptedStreamProvider() = default;

    inline auto ScriptedStreamProvider::SetGate(std::shared_ptr<Gate> GateValue) -> void
    {
        Impl_->Gate_ = std::move(GateValue);
    }

    inline auto ScriptedStreamProvider::Executor() const -> Net::any_io_executor
    {
        return Impl_->Executor_;
    }

    inline auto ScriptedStreamProvider::Activity() const noexcept
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return Impl_->Activity_;
    }

    inline auto ScriptedStreamProvider::Read(
        std::span<std::byte> Buffer,
        std::error_code &Error) -> Net::awaitable<std::size_t>
    {
        const auto Operation = Impl_->Activity_->BeginOperation();
        Error.clear();
        if (!Operation)
        {
            Error = std::make_error_code(std::errc::operation_canceled);
            co_return 0;
        }
        const auto Call = Impl_->ReadCalls_++;
        if (Impl_->Gate_ && Call == 0U)
        {
            (void)co_await Impl_->Gate_->async_receive(Net::use_awaitable);
        }
        if (Impl_->Closed_ || Impl_->ReadOffset_ == Impl_->Input_.size())
        {
            Error = std::make_error_code(std::errc::io_error);
            co_return 0;
        }
        const auto Count = (std::min)(Buffer.size(), Impl_->Input_.size() - Impl_->ReadOffset_);
        std::copy_n(
            Impl_->Input_.begin() + static_cast<std::ptrdiff_t>(Impl_->ReadOffset_),
            Count,
            Buffer.begin());
        Impl_->ReadOffset_ += Count;
        co_return Count;
    }

    inline auto ScriptedStreamProvider::Write(
        std::span<const std::byte> Buffer,
        std::error_code &Error) -> Net::awaitable<std::size_t>
    {
        Error.clear();
        if (Impl_->Closed_)
        {
            Error = std::make_error_code(std::errc::broken_pipe);
            co_return 0;
        }
        const auto Operation = Impl_->Activity_->BeginOperation();
        if (!Operation)
        {
            Error = std::make_error_code(std::errc::operation_canceled);
            co_return 0;
        }
        Impl_->Written_.insert(Impl_->Written_.end(), Buffer.begin(), Buffer.end());
        co_return Buffer.size();
    }

    inline auto ScriptedStreamProvider::Close() -> Prism::Quic::StreamProvider::ControlResult
    {
        Impl_->Closed_ = true;
        if (Impl_->Gate_)
        {
            (void)Impl_->Gate_->try_send(boost::system::error_code{});
        }
        Impl_->Activity_->CompleteClose();
        return {};
    }

    inline auto ScriptedStreamProvider::ShutdownWrite()
        -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult>
    {
        const auto Operation = Impl_->Activity_->BeginOperation();
        if (!Operation)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        Impl_->WriteShutdown_ = true;
        co_return Prism::Quic::StreamProvider::ShutdownResult{};
    }

    inline auto ScriptedStreamProvider::WaitForWriteAcknowledgement()
        -> Net::awaitable<Prism::Quic::StreamProvider::ShutdownResult>
    {
        const auto Operation = Impl_->Activity_->BeginOperation();
        if (!Operation)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        if (!Impl_->WriteShutdown_)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        co_return Prism::Quic::StreamProvider::ShutdownResult{};
    }

    inline auto ScriptedStreamProvider::StreamId() const noexcept -> std::int64_t
    {
        return Impl_->StreamId_;
    }

    inline auto ScriptedStreamProvider::IsClosed() const noexcept -> bool
    {
        return Impl_->Closed_;
    }

    inline auto ScriptedStreamProvider::ReadCalls() const noexcept -> std::size_t
    {
        return Impl_->ReadCalls_;
    }

    class RecordingDatagramProvider::Impl final
    {
    public:
        explicit Impl(Net::any_io_executor Executor) : Executor_(std::move(Executor))
        {
        }

        Net::any_io_executor Executor_;
        std::deque<std::vector<std::byte>> Queue_;
        std::vector<std::vector<std::byte>> Sent_;
        std::size_t ReceiveCalls_{0};
        std::size_t CloseCalls_{0};
        bool Closed_{false};
        bool Canceled_{false};
    };

    inline RecordingDatagramProvider::RecordingDatagramProvider(Net::any_io_executor Executor)
        : Impl_(std::make_unique<Impl>(std::move(Executor)))
    {
    }

    inline RecordingDatagramProvider::~RecordingDatagramProvider() = default;

    inline auto RecordingDatagramProvider::Inject(std::vector<std::byte> Data) -> void
    {
        Impl_->Queue_.push_back(std::move(Data));
    }

    inline auto RecordingDatagramProvider::Executor() const -> Net::any_io_executor
    {
        return Impl_->Executor_;
    }

    inline auto RecordingDatagramProvider::Receive(
        std::span<std::byte> Buffer,
        std::error_code &Error) -> Net::awaitable<std::size_t>
    {
        Error.clear();
        ++Impl_->ReceiveCalls_;
        if (Impl_->Closed_ || Impl_->Queue_.empty())
        {
            Error = std::make_error_code(std::errc::io_error);
            co_return 0;
        }
        auto Data = std::move(Impl_->Queue_.front());
        Impl_->Queue_.pop_front();
        const auto Count = (std::min)(Buffer.size(), Data.size());
        std::copy_n(Data.begin(), Count, Buffer.begin());
        co_return Count;
    }

    inline auto RecordingDatagramProvider::Send(
        std::span<const std::byte> Buffer,
        std::error_code &Error) -> Net::awaitable<std::size_t>
    {
        Error.clear();
        if (Impl_->Closed_)
        {
            Error = std::make_error_code(std::errc::broken_pipe);
            co_return 0;
        }
        Impl_->Sent_.emplace_back(Buffer.begin(), Buffer.end());
        co_return Buffer.size();
    }

    inline auto RecordingDatagramProvider::Close() -> void
    {
        Impl_->Closed_ = true;
        ++Impl_->CloseCalls_;
    }

    inline auto RecordingDatagramProvider::Cancel() -> void
    {
        Impl_->Canceled_ = true;
    }

    inline auto RecordingDatagramProvider::IsClosed() const noexcept -> bool
    {
        return Impl_->Closed_;
    }

    inline auto RecordingDatagramProvider::ReceiveCalls() const noexcept -> std::size_t
    {
        return Impl_->ReceiveCalls_;
    }

    inline auto RecordingDatagramProvider::SendCalls() const noexcept -> std::size_t
    {
        return Impl_->Sent_.size();
    }

    inline auto RecordingDatagramProvider::CloseCalls() const noexcept -> std::size_t
    {
        return Impl_->CloseCalls_;
    }

    class RecordingAuthenticator::Impl final
    {
    public:
        Impl(
            std::shared_ptr<Prism::Testing::ProviderAccounts> Accounts,
            std::shared_ptr<const Prism::Account::AccountBinding> Record)
            : AccountsOwner_(std::move(Accounts)),
              Delegate_(AccountsOwner_->Credentials),
              Record_(std::move(Record))
        {
        }

        std::shared_ptr<Prism::Testing::ProviderAccounts> AccountsOwner_;
        Prism::DirectoryAuthenticator Delegate_;
        std::shared_ptr<const Prism::Account::AccountBinding> Record_;
        std::size_t Calls_{0};
        bool LeaseHeldAtSuccess_{false};
    };

    inline RecordingAuthenticator::RecordingAuthenticator(
        std::shared_ptr<Prism::Testing::ProviderAccounts> Accounts,
        std::shared_ptr<const Prism::Account::AccountBinding> Record)
        : Impl_(std::make_unique<Impl>(std::move(Accounts), std::move(Record)))
    {
    }

    inline RecordingAuthenticator::~RecordingAuthenticator() = default;

    inline auto RecordingAuthenticator::InspectCredential(
        const Prism::Account::CredentialView &Credential) const noexcept
        -> std::expected<bool, Prism::Fault::Failure>
    {
        return Impl_->Delegate_.InspectCredential(Credential);
    }

    inline auto RecordingAuthenticator::Authenticate(
        const Prism::AuthenticationRequest &Request) const noexcept
        -> Prism::AuthenticationResult
    {
        ++Impl_->Calls_;
        auto Result = Impl_->Delegate_.Authenticate(Request);
        Impl_->LeaseHeldAtSuccess_ =
            static_cast<bool>(Result) && Impl_->Record_->Runtime()->ActiveConnections() == 1U;
        return Result;
    }

    inline auto RecordingAuthenticator::Calls() const noexcept -> std::size_t
    {
        return Impl_->Calls_;
    }

    inline auto RecordingAuthenticator::LeaseHeldAtSuccess() const noexcept -> bool
    {
        return Impl_->LeaseHeldAtSuccess_;
    }

    inline auto TestExporter(
        std::span<std::uint8_t> Output,
        std::span<const std::uint8_t> Label,
        std::string_view Context) -> bool
    {
        std::uint8_t State = 0x5A;
        for (const auto Byte : Label)
        {
            State = static_cast<std::uint8_t>((State * 33U) ^ Byte);
        }
        for (const auto Character : Context)
        {
            State = static_cast<std::uint8_t>(
                (State * 33U) ^ static_cast<std::uint8_t>(Character));
        }
        for (std::size_t Index = 0; Index < Output.size(); ++Index)
        {
            State = static_cast<std::uint8_t>(
                State * 33U + static_cast<std::uint8_t>(Index));
            Output[Index] = State;
        }
        return true;
    }

    inline auto MakeConnectWire() -> std::vector<std::byte>
    {
        Prism::Tuic::Message Message;
        Message.Cmd = Prism::Tuic::CmdConnect;
        Message.dst = {Prism::Tuic::AddressType::Domain, "example.com", 443};
        return ToBytes(Prism::Tuic::Build(Message));
    }

    inline auto MakePacketWire() -> std::vector<std::byte>
    {
        Prism::Tuic::Message Message;
        Message.Cmd = Prism::Tuic::CmdPacket;
        Message.dst = {Prism::Tuic::AddressType::Domain, "example.com", 443};
        Message.payload = "udp-payload";
        return ToBytes(Prism::Tuic::Build(Message));
    }

    class TuicTestHarness::Impl final
    {
    public:
        explicit Impl(Net::io_context &Io) : Io_(Io), Directory_(Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token(Password_), Prism::AccountId{8101},
            {.MaxConnections = 4}))
        {
            Uuid_ = MakeUuid();
            Record_ = Directory_->Store->FindById(Prism::AccountId{8101});
            Installed_ = Record_ != nullptr;
            Authenticator_ = std::make_shared<RecordingAuthenticator>(Directory_, Record_);
            Binding_.Admission = Prism::Tuic::AdmissionOptions{
                .Executor = Io_.get_executor(),
                .Uuid = Uuid_,
                .ExporterContext = Password_,
                .Credential = std::make_shared<const Prism::Account::Credential>(
                    Prism::Account::Credential::Token(Password_)),
                .AuthenticatorOwner = Authenticator_,
                .MaxPendingBidiStreams = 8U};



            Binding_.Services.Dial = [Executor = Io_.get_executor()](Prism::Tuic::DialRequest)
                -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
            {
                auto Provider = std::make_shared<ScriptedStreamProvider>(
                    Executor, std::vector<std::byte>{});
                co_return std::make_shared<Prism::Quic::StreamAdapter>(
                    Executor, std::move(Provider));
            };
            Binding_.Services.Resolve = [](Prism::Tuic::ResolveRequest Request)
                -> Net::awaitable<Prism::Tuic::ResolveResult>
            {
                Request.Target.Type = Prism::Tuic::AddressType::Ipv4;
                Request.Target.Host = "203.0.113.7";
                co_return Prism::Tuic::ResolveResult{
                    Prism::Error::None, {std::move(Request.Target)}};
            };
            Binding_.Services.ExchangeDatagram = ExchangeDatagram;
        }

        [[nodiscard]] auto Configure() -> AdmissionEvents
        {
            auto Config=Binding_.Admission;
            Config.CloseOwner=[this,Close=Config.CloseOwner]()
                ->std::expected<void,Prism::Fault::Failure>
            {
                ++CompletionCalls_;
                if (Close)
                {
                    return Close();
                }
                return std::expected<void,Prism::Fault::Failure>{};
            };
            auto OwnerResult=Prism::Tuic::ConnectionAdmission::Create(std::move(Config),Binding_.Services);
            if(!OwnerResult)
                throw std::system_error(Prism::Fault::ToNative(OwnerResult.error()));
            auto Owner=std::move(*OwnerResult);
            AdmissionEvents Events;
            Events.Owner=Owner;
            Events.OnExporter=[Owner](auto Exporter)
            {return Owner->OnExporter(std::move(Exporter));};
            Events.OnUnidirectional=[Owner](auto Provider)
            {return Owner->OnUnidirectional(std::move(Provider));};
            Events.OnStream=[Owner](auto Provider)
            {return Owner->OnBidirectional(std::move(Provider));};
            Events.OnDatagram=[Owner](auto Provider)
            {return Owner->OnDatagram(std::move(Provider));};
            Events.OnClosed=[Owner]{Owner->OnClosed();};return Events;
        }

        [[nodiscard]] auto ValidAuthWire() const -> std::vector<std::byte>
        {
            std::array<std::uint8_t, Prism::Tuic::TokenLen> Token{};
            (void)TestExporter(
                std::span<std::uint8_t>(Token),
                std::span<const std::uint8_t>(Uuid_),
                Password_);
            return MakeAuthWire(Uuid_, Token);
        }

        [[nodiscard]] auto InvalidAuthWire() const -> std::vector<std::byte>
        {
            auto Wire = ValidAuthWire();
            Wire.back() ^= std::byte{0x01};
            return Wire;
        }

        [[nodiscard]] auto AccountActiveConnections() const noexcept -> std::uint32_t
        {
            return Record_->Runtime()->ActiveConnections();
        }

        [[nodiscard]] auto AccountActiveStreams() const noexcept -> std::uint32_t
        {
            return Record_->Runtime()->ActiveStreams();
        }

        [[nodiscard]] auto CompletionCalls() const noexcept -> std::size_t
        {
            return CompletionCalls_;
        }

        [[nodiscard]] auto Installed() const noexcept -> bool
        {
            return Installed_;
        }

        [[nodiscard]] auto Binding() -> AdmissionFixtureOptions &
        {
            return Binding_;
        }

        [[nodiscard]] auto Authenticator() const
            -> const std::shared_ptr<RecordingAuthenticator> &
        {
            return Authenticator_;
        }

    private:
        [[nodiscard]] static auto ExchangeDatagram(Prism::Tuic::DatagramRequest Request)
            -> Net::awaitable<Prism::Tuic::DatagramResult>
        {
            const auto PayloadBytes = static_cast<std::uint64_t>(Request.Payload.size());
            co_return Prism::Tuic::DatagramResult{
                Prism::Error::None, std::move(Request.Target),
                std::move(Request.Payload), PayloadBytes, PayloadBytes};
        }

        Net::io_context &Io_;
        const std::string Password_{"tuic-password"};
        std::array<std::uint8_t, Prism::Tuic::UuidLen> Uuid_{};
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory_;
        std::shared_ptr<const Prism::Account::AccountBinding> Record_;
        std::shared_ptr<RecordingAuthenticator> Authenticator_;
        AdmissionFixtureOptions Binding_;
        std::size_t CompletionCalls_{0};
        bool Installed_{false};
    };

    inline TuicTestHarness::TuicTestHarness() : Io(), Impl_(std::make_unique<Impl>(Io))
    {
    }

    inline TuicTestHarness::~TuicTestHarness() = default;

    inline auto TuicTestHarness::Configure() -> AdmissionEvents
    {
        return Impl_->Configure();
    }

    /** @brief 保留并输出真实执行域异常首因，供失败关闭链定位。 */
    inline auto VerifyFatalState(Net::io_context &Context) -> void
    {
        const auto Fatal = Prism::Executor::FatalState::For(Context.get_executor());
        const auto Error = Fatal->Error();
        if (!Error) return;
        try { std::rethrow_exception(Error); }
        catch (const boost::system::system_error &Exception)
        {
            ADD_FAILURE() << "FatalNativeCategory=" << Exception.code().category().name()
                << " FatalNativeValue=" << Exception.code().value()
                << " FatalWhat=" << Exception.what();
        }
        catch (const std::exception &Exception)
        { ADD_FAILURE() << "FatalWhat=" << Exception.what(); }
        catch (...) { ADD_FAILURE() << "FatalUnknownException"; }
    }

    inline auto TuicTestHarness::CloseAndDrain(AdmissionEvents &Options) -> void
    {
        if (Options.OnClosed)
        {
            Options.OnClosed();
        }
        Io.restart();
        bool Drained=!Options.Owner;
        std::exception_ptr DrainException;
        Prism::Fault::Failure DrainFailure;
        if(Options.Owner)
        {
            auto Owner=Options.Owner;
            Net::co_spawn(Io,Owner->Drain(),[Owner,&Drained,&DrainException,&DrainFailure](std::exception_ptr Error,
                std::expected<void,Prism::Fault::Failure> Result)
            {
                DrainException=std::move(Error);
                Drained=!DrainException && static_cast<bool>(Result);
                if(!Result)DrainFailure=Result.error();
            });
        }
        Io.run();
        EXPECT_FALSE(DrainException);
        VerifyFatalState(Io);
        EXPECT_TRUE(Drained);
        if (!Drained)
            ADD_FAILURE() << "Code=" << static_cast<int>(DrainFailure.Code)
                << " NativeCategory=" << DrainFailure.Native.category().name()
                << " NativeValue=" << DrainFailure.Native.value();
        Options = AdmissionEvents{};
        Impl_->Binding().Services = {};
        Impl_->Binding().Admission.CloseOwner = {};
        Io.restart();
        Io.run();
    }

    inline auto TuicTestHarness::ValidAuthWire() const -> std::vector<std::byte>
    {
        return Impl_->ValidAuthWire();
    }

    inline auto TuicTestHarness::InvalidAuthWire() const -> std::vector<std::byte>
    {
        return Impl_->InvalidAuthWire();
    }

    inline auto TuicTestHarness::AccountActiveConnections() const noexcept -> std::uint32_t
    {
        return Impl_->AccountActiveConnections();
    }

    inline auto TuicTestHarness::AccountActiveStreams() const noexcept -> std::uint32_t
    {
        return Impl_->AccountActiveStreams();
    }

    inline auto TuicTestHarness::CompletionCalls() const noexcept -> std::size_t
    {
        return Impl_->CompletionCalls();
    }

    inline auto TuicTestHarness::Installed() const noexcept -> bool
    {
        return Impl_->Installed();
    }

    inline auto TuicTestHarness::Binding() -> AdmissionFixtureOptions &
    {
        return Impl_->Binding();
    }

    inline auto TuicTestHarness::Authenticator() const
        -> const std::shared_ptr<RecordingAuthenticator> &
    {
        return Impl_->Authenticator();
    }
} // namespace Prism::Testing::TuicFactory

