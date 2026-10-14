/** @file IngressFactory.hpp @brief AnyTLS 密码验证、真实账户 lease 与正式 Session 的唯一 producer。 */
#pragma once

#include <Preview/Protocols/Anytls/Detail/Session/Session.hpp>
#include <Preview/Protocols/Anytls/Detail/Session/Retirement.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Contract/Ingress/AdmissionTransportRetirement.hpp>
#include <Preview/Account/Authenticator.hpp>

#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <boost/asio/this_coro.hpp>

namespace Preview::Anytls
{
    namespace Detail
    {
        /** @brief ticket 分配失败时用 carrier 预建控制 owner 真实关闭入站实物。 */
        inline auto RetireUnreservedWithFailure(
            const Preview::SharedTransmission &Inbound,
            Preview::Fault::Failure Primary)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            bool CancelAttempted = false;
            bool CloseAttempted = false;
            const auto Cleanup = co_await Preview::Contract::RetireAdmissionTransport(
                Inbound, CancelAttempted, CloseAttempted);
            if (!Primary.Failed() && Cleanup.Error.Failed()) Primary = Cleanup.Error;
            co_return Primary;
        }

        /** @brief 清理决定 owner 是否保留；不把清理错误并入协议首因。 */
        inline auto RetireWithFailure(
            const std::shared_ptr<Detail::TransportRetirement> &Retirement,
            Preview::Fault::Failure Primary)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            Retirement->RetainForRetry();
            try
            {
                const auto Retired = co_await Retirement->RetireAndDrain();
                if (!Retired && !Primary.Failed()) Primary = Retired.error();
            }
            catch (...)
            {
                Retirement->RequestRetirement();
                const auto Cleanup = Detail::FailureFromRetirementException(
                    std::current_exception());
                if (!Primary.Failed()) Primary = Cleanup;
            }
            co_return Primary;
        }
    }

    struct IngressOptions final
    {
        ServerConfig Configuration;
        Preview::Contract::StreamServices Streams;
        Preview::SharedAuthenticator Authenticator;
    };

    class IngressFactory final : public Preview::Contract::StreamFactory
    {
    public:
        explicit IngressFactory(IngressOptions Options) : Options_(std::move(Options)) {}

        /** @brief AnyTLS expected handshake 成功后申请一次账户 lease，并移交唯一正式 data plane。 */
        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome> override
        {
            auto Inbound = std::move(Input.Inbound);
            [[maybe_unused]] auto Metadata = std::move(Input.Metadata);
            auto Bytes = std::move(Input.Bytes);
            auto GenerationUseState = std::move(Input.GenerationUseState);
            if (!Inbound || !Bytes)
            {
                if (Inbound)
                {
                    auto Prepared = Detail::TransportRetirement::Prepare();
                    if (!Prepared)
                    {
                        const auto Failure = co_await Detail::RetireUnreservedWithFailure(
                            Inbound, Preview::Fault::Failure{
                                Preview::Fault::Code::InvalidArgument});
                        co_return std::unexpected(Failure);
                    }
                    auto Retirement = std::move(*Prepared);
                    auto Attached = Retirement->Attach(
                        std::move(Inbound), Preview::Account::StreamLease{});
                    if (!Attached) co_return std::unexpected(Attached.error());
                    Retirement->RetainForRetry();
                    const auto Failure = co_await Detail::RetireWithFailure(
                        Retirement,
                        Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                    co_return std::unexpected(Failure);
                }
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }

            auto Prepared = Detail::TransportRetirement::Prepare();
            if (!Prepared)
            {
                const auto Failure = co_await Detail::RetireUnreservedWithFailure(
                    Inbound, Prepared.error());
                co_return std::unexpected(Failure);
            }
            auto Retirement = std::move(*Prepared);
            auto Handshake = co_await Detail::AcceptWithRetirement(
                std::move(Inbound), Options_.Configuration, Retirement);
            if (!Handshake) co_return std::unexpected(Handshake.error());
            auto Connection = std::move(*Handshake);

            if (!Options_.Streams.Egress)
            {
                Retirement->RetainForRetry();
                const auto Failure = co_await Detail::RetireWithFailure(
                    Retirement,
                    Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
                co_return std::unexpected(Failure);
            }

            Preview::Contract::ProtocolDataPlane Plane;
            if (Options_.Authenticator)
            {
                const auto Credential =
                    Preview::Account::Credential::Password(Options_.Configuration.Password);
                auto Auth = Options_.Authenticator->Authenticate(
                    Preview::AuthenticationRequest{.Credential = Credential.View()});
                if (!Auth)
                {
                    Retirement->RetainForRetry();
                    const auto Failure = co_await Detail::RetireWithFailure(
                        Retirement,
                        Preview::Fault::Failure{Preview::Fault::Code::AuthFailed});
                    co_return std::unexpected(Failure);
                }
                Plane.AccountId = Auth->AccountId();
                Plane.Identity = std::string(Auth->Identity());
                Plane.DisplayIdentity = std::string(Auth->DisplayIdentity());
                Plane.AccountLease = std::move(*Auth);
            }

            Plane.Protocol = Preview::Contract::ProtocolType::AnyTls;
            Plane.ProtocolAuthenticated = true;
            Plane.Root = Preview::Contract::MuxRootDataPlane{Connection, {}};
            if (!GenerationUseState)
            {
                Retirement->AttachMuxRootPlane(std::move(Plane));
                Retirement->RetainForRetry();
                const auto Failure = co_await Detail::RetireWithFailure(Retirement,
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
                co_return std::unexpected(Failure);
            }

            auto CreateRequest = Preview::Contract::MuxRootCreateRequest::Prepare(
                Retirement, std::move(GenerationUseState), std::move(Plane));
            if (!CreateRequest)
            {
                if (Plane.HasTransport())
                {
                    Retirement->AttachMuxRootPlane(std::move(Plane));
                    Retirement->RetainForRetry();
                    const auto Failure = co_await Detail::RetireWithFailure(
                        Retirement, CreateRequest.error());
                    co_return std::unexpected(Failure);
                }
                co_return std::unexpected(CreateRequest.error());
            }

            auto Created = Detail::Session::Create(*CreateRequest, Options_.Streams);
            if (!Created) co_return std::unexpected(Created.error());
            auto AcceptedPlane = CreateRequest->TakePlane();
            CreateRequest->Transfer();
            Plane = std::move(AcceptedPlane);
            co_return Preview::Contract::AcceptOutcome{std::move(Plane)};
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "anytls"; }

    private:
        IngressOptions Options_;
    };
}
