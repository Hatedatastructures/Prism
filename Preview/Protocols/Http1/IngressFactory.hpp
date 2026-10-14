/**
 * @file IngressFactory.hpp
 * @brief HTTP/1.1 入站代理协议的唯一 typed Accept owner。
 * @details 该 owner 负责 HTTP 请求读取、Basic 认证、目标解析、首个响应、
 *          正向请求 framing 和成功后的 half-close/最终 close 交接。
 *          Recognition 只检查 wire 结构，不在 prepare 阶段取得 lease。
 */

#pragma once

#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Foundation/Utility/Crypto/Base64.hpp>
#include <Preview/Protocols/Http1/Conn.hpp>
#include <Preview/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Preview/Protocols/Http1/ForwardResponseTransport.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Http11
{

    namespace Net = boost::asio;

    /**
     * @struct IngressOptions
     * @brief HTTP/1.1 入站认证的 typed 配置。
     * @details Authenticator 由冷装配提供并由 factory 共享持有；认证成功后
     *          AccountLease 只移动到唯一 ProtocolDataPlane，失败不发布 plane。
     */
    struct IngressOptions final
    {
        bool RequireAuth{false};
        Preview::SharedAuthenticator Authenticator{};
    };

    namespace detail
    {

        /**
         * @brief 将 Proxy-Authorization Basic 头转换为唯一 typed Authenticate 请求。
         * @details Base64 解码产生的 user/password view 只在同步 Authenticate 调用期间
         *          有效；Authenticator 不得保存这些 view。
         */
        [[nodiscard]] inline auto AuthenticateBasic(
            const std::string_view Authorization,
            const Preview::Authenticator &Authenticator) -> Preview::AuthenticationResult
        {
            constexpr std::string_view BasicPrefix = "Basic ";
            if (Authorization.size() <= BasicPrefix.size() ||
                !Preview::Http11::detail::Iequals(
                    Authorization.substr(0, BasicPrefix.size()), BasicPrefix))
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::AuthFailed});
            }

            const auto Decoded = Preview::Crypto::Base64Decode(
                Authorization.substr(BasicPrefix.size()));
            const auto Colon = Decoded.find(':');
            if (Colon == std::string_view::npos || Colon + 1U >= Decoded.size())
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::AuthFailed});
            }

            const auto User = std::string_view(Decoded).substr(0, Colon);
            const auto Password = std::string_view(Decoded).substr(Colon + 1U);
            return Authenticator.Authenticate(Preview::AuthenticationRequest{
                .AccountId = {},
                .Identity = User,
                .Credential = Preview::Account::CredentialView::Password(Password),
                .Rate = {}});
        }

    } // namespace detail

    /**
     * @class IngressFactory
     * @brief HTTP/1.1 CONNECT 和普通正向代理的唯一接入工厂。
     * @details Accept 按值接收输入并由 InboundAdmission 守卫到结果发布；失败或
     *          异常由守卫取消并关闭，成功后由 DataPlane 接管。transport、lease、
     *          PostDial 和 response decorator 一起移入唯一 DataPlane，relay 负责
     *          后续 half-close 和最终 close。
     */
    class IngressFactory final : public Preview::Contract::StreamFactory
    {
    public:
        explicit IngressFactory(IngressOptions Options)
            : Options_(std::move(Options))
        {
        }

        /**
         * @brief 读取并认证一个 HTTP/1.1 入站请求。
         * @param Inbound 由调用方按值移交的根传输；guard 持有到结果发布。
         * @param Metadata listener 提供的请求元数据；当前 HTTP wire 不改写它。
         * @return 成功时返回唯一 typed DataPlane；失败时无可转发 plane。
         * @note 网络 I/O 在调用 executor；取消由输入 transport 的 Cancel/Close
         *       传播，最终关闭由 DataPlane/relay owner 完成。
         */
        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome> override
        {
            Preview::Contract::ProtocolDataPlane Result;
            Result.Protocol = Preview::Contract::ProtocolType::Http;
            auto Inbound = std::move(Input.Inbound);
            auto Bytes = std::move(Input.Bytes);
            if (!Inbound)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            auto PreparedAdmission = co_await Preview::Contract::InboundAdmission::Prepare(Inbound);
            if (!PreparedAdmission)
            {
                co_return std::unexpected(PreparedAdmission.error());
            }
            auto Admission = std::move(*PreparedAdmission);
            if (!Bytes)
            {
                co_return co_await Admission.Reject(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            Preview::Http11::ServerConn Server(std::move(Inbound), std::move(Bytes));
            Preview::Http11::HttpRequest Request;
            const auto ReadError = co_await Server.ReadRequest(Request);
            if (ReadError.Failed())
            {
                co_return co_await RejectWithResponse(Http1Rejection{
                    Server, Admission, Preview::Http11::Status::BadRequest,
                    ReadError});
            }

            const auto Target = Preview::Http11::ResolveTarget(Request);
            if (!Target)
            {
                co_return co_await RejectWithResponse(Http1Rejection{
                    Server, Admission, Preview::Http11::Status::BadRequest,
                    Preview::Fault::Failure{Preview::Fault::Code::BadMessage}});
            }

            Preview::Account::AccountLease Lease;
            if (Options_.RequireAuth)
            {
                if (!Options_.Authenticator)
                {
                    co_return co_await RejectWithResponse(Http1Rejection{
                        Server, Admission, Preview::Http11::Status::ProxyAuthRequired,
                        Preview::Fault::Failure{Preview::Fault::Code::AuthFailed}});
                }

                auto AuthResult = detail::AuthenticateBasic(
                    Request.authorization, *Options_.Authenticator);
                if (!AuthResult)
                {
                    co_return co_await RejectWithResponse(Http1Rejection{
                        Server, Admission, Preview::Http11::Status::ProxyAuthRequired,
                        AuthResult.error()});
                }
                Lease = std::move(*AuthResult);
            }

            const bool IsConnect = Target->Form == Preview::Http11::RequestForm::Connect;
            const bool IsHead = Request.Method == "HEAD";
            const bool UpgradeRequested = Request.Headers.HasUpgrade &&
                                          Request.Headers.ConnectionContains("upgrade");
            auto Host = Preview::Network::ParseHost(Target->Host);
            if (!Host) co_return co_await Admission.Reject(Host.error());
            Result.Target = {std::move(*Host), Target->Port, Preview::Network::RouteKind::Forward};
            if (Options_.RequireAuth)
            {
                Result.AccountId = Lease.AccountId();
                Result.Identity = std::string(Lease.Identity());
                Result.DisplayIdentity = std::string(Lease.DisplayIdentity());
            }
            Result.ProtocolAuthenticated = Options_.RequireAuth;
            Result.AccountLease = std::move(Lease);

            Preview::SharedTransmission Transport = IsConnect
                ? Server.Release()
                : Server.ReleaseForward();
            if (!Transport)
            {
                co_return co_await Admission.Reject(
                    Preview::Fault::Failure{Preview::Fault::Code::IoError});
            }

            Result.Root = Preview::Contract::StreamDataPlane{Transport};
            ConfigureResponse(Result, ResponsePlan{IsConnect, IsHead, UpgradeRequested});
            const auto Tracked = Admission.Track(Transport);
            if (!Tracked)
            {
                co_return co_await Admission.Reject(std::move(Result), Tracked.error());
            }
            co_return co_await Admission.Admit(std::move(Result));
        }

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "http";
        }

    private:
        struct Http1Rejection final
        {
            Preview::Http11::ServerConn& Server;
            Preview::Contract::InboundAdmission& Admission;
            std::string_view Response;
            Preview::Fault::Failure Failure;
        };

        [[nodiscard]] static auto RejectWithResponse(Http1Rejection Request)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            const auto Sent = co_await Request.Server.SendResponse(Request.Response);
            if (Sent.Failed())
            {
                Request.Failure = Sent;
            }
            co_return co_await Request.Admission.Reject(Request.Failure);
        }

        struct ResponsePlan final
        {
            bool Tunnel{false};
            bool Head{false};
            bool Upgrade{false};
        };

        /** @brief 装配单个拨号后响应和普通请求出站 framing callback；消费次数
         *         由 Runtime DataPlane contract 约束，不在 factory 内重复调度。 */
        static auto ConfigureResponse(Preview::Contract::ProtocolDataPlane &Plane,
                                      const ResponsePlan Plan) -> void
        {
            Plane.PostDial = [Client = Plane.Transport(), Plan](
                                 Preview::Fault::Failure Failure)
                -> Net::awaitable<Preview::Fault::Failure>
            { return SendDeferredReply(Client, Plan.Tunnel, std::move(Failure)); };
            if (!Plan.Tunnel)
            {
                Plane.Stream()->OutboundDecorator = [Plan](Preview::SharedTransmission Outbound)
                    -> Preview::SharedTransmission
                { return DecorateResponse(std::move(Outbound), Plan); };
            }
        }

        [[nodiscard]] static auto SendDeferredReply(
            Preview::SharedTransmission Client,
            const bool IsTunnel,
            Preview::Fault::Failure Failure)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            if (!IsTunnel && Failure.Code == Preview::Fault::Code::Success)
            {
                co_return Preview::Fault::Failure{Preview::Fault::Code::Success};
            }
            auto Status = Preview::Http11::Status::Ok;
            if (Failure.Code != Preview::Fault::Code::Success)
                Status = Preview::Http11::Status::BadGateway;
            co_return co_await Preview::Http11::SendResponse(Client, Status);
        }

        [[nodiscard]] static auto DecorateResponse(
            Preview::SharedTransmission Outbound,
            const ResponsePlan Plan) -> Preview::SharedTransmission
        {
            Preview::Http11::ForwardResponseTransportOptions Options;
            Options.Inner = std::move(Outbound);
            Options.Framing.RequestMethod = Preview::Http11::ForwardResponseMethod::Other;
            if (Plan.Head)
                Options.Framing.RequestMethod = Preview::Http11::ForwardResponseMethod::Head;
            Options.Framing.AllowUpgrade = Plan.Upgrade;
            return Preview::Http11::MakeForwardResponseTransport(std::move(Options));
        }

        IngressOptions Options_;
    };

} // namespace Preview::Http11
