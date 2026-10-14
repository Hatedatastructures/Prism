/**
 * @file IngressFactory.hpp
 * @brief TrustTunnel wire-proof 与 typed protocol Accept owner。
 * @details HTTP/2 carrier 先由 Http2Accept 完成 TLS、settings、CONNECT 和
 *          Basic wire proof，再由本 owner 进行账户 Authenticate、目标解析、
 *          lease 移交和唯一 ProtocolDataPlane 发布。raw Http2Transport 即使
 *          可以公开构造，也不能绕过私有 wire-proof handoff。
 */

#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/AcceptedCarrierActivity.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/CarrierOwner.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <charconv>
#include <atomic>
#include <cstdint>
#include <expected>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Trusttunnel
{

    namespace Net = boost::asio;

    class AuthenticatedTransport;

    namespace Detail
    {
        class Http2Accept;
        struct Http2DriverParameters;
    }

    /**
     * @struct WireAuthBinding
     * @brief 同一 cold generation 的 TrustTunnel wire 与账户认证材料。
     * @details Detail::Http2Accept 使用 Configuration 做 wire Basic proof，IngressFactory
     *          使用同一对象中的 Credential/Authenticator 取得 lease；对象发布后
     *          不可变，避免 A 配置的 wire proof 被 B factory 领取 B lease。
     */
    struct WireAuthBinding final
    {
        const ServerConfig Configuration;
        const std::string Credential;
        const Preview::SharedAuthenticator Authenticator;

    private:
        friend auto MakeWireAuthBinding(ServerConfig Configuration,
                                        Preview::SharedAuthenticator Authenticator)
            -> std::shared_ptr<const WireAuthBinding>;

        WireAuthBinding(ServerConfig ConfigurationValue,
                        Preview::SharedAuthenticator AuthenticatorValue)
            : Configuration(std::move(ConfigurationValue)),
              Credential(Configuration.username + ":" + Configuration.password),
              Authenticator(std::move(AuthenticatorValue))
        {
        }
    };

    [[nodiscard]] inline auto MakeWireAuthBinding(
        ServerConfig Configuration,
        Preview::SharedAuthenticator Authenticator)
        -> std::shared_ptr<const WireAuthBinding>
    {
        return std::shared_ptr<const WireAuthBinding>(
            new WireAuthBinding(std::move(Configuration), std::move(Authenticator)));
    }

    using SharedWireAuthBinding = std::shared_ptr<const WireAuthBinding>;

    /**
     * @class AuthenticatedTransport
     * @brief Http2Accept 完成 wire 认证后发布的不可伪造 carrier handoff。
     * @details 构造函数和发布入口只对 Detail::Http2Accept 开放；普通调用方可以构造
     *          raw Http2Transport，但不能把它包装成已认证 transport。该对象
     *          只保存 carrier owner 与 authority，不保存账户身份或 lease。不可变
     *          binding pin 由 carrier owner 保留至完整物理退休后释放。
     */
    class AuthenticatedTransport final : public Preview::Transmission
    {
    public:
        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        /** @brief 部分读取；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (Owner_->IsRetired() || !Owner_->Transport)
            {
                Preview::Transport::Detail::PostResult(
                    Executor_, std::move(Handler), {0, {Preview::Fault::Code::Canceled}});
                return;
            }
            Owner_->Transport->ReadSome(Buffer, std::move(Handler));
        }

        /** @brief 部分写入；保留 carrier 侧短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (Owner_->IsRetired() || !Owner_->Transport)
            {
                Preview::Transport::Detail::PostResult(
                    Executor_, std::move(Handler), {0, {Preview::Fault::Code::Canceled}});
                return;
            }
            Owner_->Transport->WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭：只提交 END_STREAM，保留反向读取能力。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Owner_->WriteShutdown(std::move(Handler));
        }

        /** @brief 交付 carrier 关闭；实际退出由 carrier driver 生命周期另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Owner_->Close();
        }

        /** @brief 可重复取消 carrier 挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Owner_->Cancel();
        }

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (Owner_->Transport) Owner_->Transport->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Owner_->IsRetired() && Owner_->Transport && Owner_->Transport->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Owner_->Transport.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Preview::Transmission * override
        {
            return Owner_->Transport.get();
        }

        [[nodiscard]] auto Authority() const noexcept -> std::string_view
        {
            return Authority_;
        }

        /** @brief 返回 carrier driver 生命周期观察句柄，不转移关闭责任。 */
        [[nodiscard]] auto Lifecycle() const noexcept -> std::shared_ptr<Detail::CarrierLifecycle>
        {
            return Owner_->Lifecycle;
        }

    private:
        friend class Detail::Http2Accept;
        friend class IngressFactory;

        AuthenticatedTransport(std::shared_ptr<Detail::CarrierOwner> Owner,
                               std::string Authority)
            : Preview::Transmission(
                  Owner->Executor()),
              Executor_(Owner->Executor()), Owner_(std::move(Owner)),
              Authority_(std::move(Authority)),
              Activity_(std::make_shared<Detail::AcceptedCarrierActivity<Detail::CarrierOwner>>(
                  Preview::Transmission::Activity(), Owner_, CloseReceipt()))
        {
        }

        [[nodiscard]] static auto CreateForHandshake(
            std::shared_ptr<Detail::CarrierOwner> Owner,
            std::string Authority)
            -> std::shared_ptr<AuthenticatedTransport>
        {
            if (!Owner || !Owner->Transport || Authority.empty() || !Owner->Binding)
            {
                return {};
            }
            return std::shared_ptr<AuthenticatedTransport>(
                new AuthenticatedTransport(std::move(Owner), std::move(Authority)));
        }

        /** @brief 读取当前 owner 的 generation pin；物理退休后返回空绑定。 */
        [[nodiscard]] auto Binding() const noexcept
            -> const SharedWireAuthBinding &
        {
            return Owner_->Binding;
        }

        ExecutorType Executor_;
        std::shared_ptr<Detail::CarrierOwner> Owner_;
        std::string Authority_;
        std::shared_ptr<Detail::AcceptedCarrierActivity<Detail::CarrierOwner>> Activity_;
    };

    /**
     * @struct IngressOptions
     * @brief TrustTunnel 的 wire 配置与 typed 账户认证器。
     * @details ServerConfig 只用于核对 carrier 已完成的 wire 认证材料；账户
     *          AccountId/AccountLease 必须由 Authenticator 在本 owner 中取得。
     */
    struct IngressOptions final
    {
        SharedWireAuthBinding Binding{};
    };

    /**
     * @class IngressFactory
     * @brief TrustTunnel 的唯一 protocol Accept owner。
     * @details Accept 只接受 AuthenticatedTransport。成功时将 authority、typed
     *          identity、AccountId、AccountLease 和 stream carrier 一起交给 Admit；
     *          失败或异常由 InboundAdmission 负责取消与关闭，支持 carrier EOF、
     *          half-close 和最终 close 的既有 Transport 合同。
     */
    class IngressFactory final : public Preview::Contract::StreamFactory
    {
        using Failure = Preview::Fault::Failure;

    public:
        explicit IngressFactory(IngressOptions Options)
            : Options_(std::move(Options))
        {
        }

        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<std::expected<
                Preview::Contract::ProtocolDataPlane, Preview::Fault::Failure>> override
        {
            auto Inbound = std::move(Input.Inbound);
            auto Bytes = std::move(Input.Bytes);
            if (!Inbound)
            {
                co_return std::unexpected(ToAdmissionFailure(Preview::Error::Unsupported));
            }
            auto Prepared = co_await Preview::Contract::InboundAdmission::Prepare(Inbound);
            if (!Prepared) co_return std::unexpected(Prepared.error());
            auto Admission = std::move(*Prepared);
            std::exception_ptr Fatal;
            try
            {
                if (!Bytes)
                {
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::IoError));
                }
                const auto Proof = std::dynamic_pointer_cast<AuthenticatedTransport>(Inbound);
                if (!Proof)
                {
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::Unsupported));
                }
                if (!Options_.Binding || Proof->Binding().get() != Options_.Binding.get())
                {
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::Unsupported));
                }

                const auto &Binding = *Options_.Binding;
                if (!Binding.Authenticator)
                {
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::BadAuth));
                }

                const auto Target = ParseAuthority(Proof->Authority());
                if (!Target)
                {
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::BadAddress));
                }

                auto Authentication = Binding.Authenticator->Authenticate(
                    Preview::AuthenticationRequest{
                        .AccountId = {},
                        .Identity = Binding.Configuration.username,
                        .Credential = Preview::Account::CredentialView::Password(Binding.Credential),
                        .Rate = {}});
                if (!Authentication || !Authentication->AccountId())
                {
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::BadAuth));
                }

                Preview::Contract::ProtocolDataPlane Plane;
                Plane.Protocol = Preview::Contract::ProtocolType::TrustTunnel;
                auto Host = Preview::Network::ParseHost(Target->Host);
                if (!Host)
                    co_return co_await Admission.Reject(ToAdmissionFailure(Preview::Error::BadAddress));
                Plane.Target = {std::move(*Host), Target->Port, Preview::Network::RouteKind::Forward};
                Plane.ProtocolAuthenticated = true;
                Plane.AccountId = Authentication->AccountId();
                Plane.Identity = std::string(Authentication->Identity());
                Plane.DisplayIdentity = std::string(Authentication->DisplayIdentity());
                Plane.AccountLease = std::move(*Authentication);
                Plane.Root = Preview::Contract::StreamDataPlane{std::move(Inbound)};

                co_return co_await Admission.Admit(std::move(Plane));
            }
            catch (const std::bad_alloc &)
            {
                Fatal = std::current_exception();
            }
            co_return co_await Admission.Reject(
                Preview::Contract::InboundAdmission::ExceptionFailure(std::move(Fatal)));
        }

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "trusttunnel";
        }

    private:
        /** @brief 在旧 TrustTunnel wire 错误边界映射正式 typed Failure 分类。 */
        [[nodiscard]] static auto ToAdmissionFailure(const Preview::Error Error) noexcept -> Failure
        {
            return {Preview::Fault::ToCode(Preview::make_error_code(Error))};
        }

        struct Authority final
        {
            std::string Host;
            std::uint16_t Port{0};
        };

        [[nodiscard]] static auto ParseAuthority(const std::string_view Value)
            -> std::optional<Authority>
        {
            if (Value.empty())
            {
                return std::nullopt;
            }
            std::string_view Host;
            std::string_view PortText;
            if (Value.front() == '[')
            {
                const auto Close = Value.find(']');
                if (Close == std::string_view::npos || Close + 2U > Value.size() ||
                    Value[Close + 1U] != ':')
                {
                    return std::nullopt;
                }
                Host = Value.substr(1U, Close - 1U);
                PortText = Value.substr(Close + 2U);
            }
            else
            {
                const auto Colon = Value.rfind(':');
                if (Colon == std::string_view::npos || Value.find(':') != Colon)
                {
                    return std::nullopt;
                }
                Host = Value.substr(0, Colon);
                PortText = Value.substr(Colon + 1U);
            }

            std::uint32_t Port = 0;
            const auto [End, Error] = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port);
            if (Host.empty() || Port == 0U || Port > 65535U || Error != std::errc{} ||
                End != PortText.data() + PortText.size())
            {
                return std::nullopt;
            }
            return Authority{std::string(Host), static_cast<std::uint16_t>(Port)};
        }

        IngressOptions Options_;
    };

} // namespace Preview::Trusttunnel
