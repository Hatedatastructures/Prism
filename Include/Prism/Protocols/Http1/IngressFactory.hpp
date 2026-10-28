/**
 * @file IngressFactory.hpp
 * @brief HTTP/1.1 入站代理协议的唯一 typed Accept owner。
 * @details 该 owner 负责 HTTP 请求读取、Basic 认证、目标解析、首个响应、
 *          正向请求 framing 和成功后的 half-close/最终 close 交接。
 *          Recognition 只检查 wire 结构，不在 prepare 阶段取得 lease。
 */

#pragma once

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Http1/Conn.hpp>
#include <Prism/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Prism/Protocols/Http1/Forward/Response/Transport.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace Prism::Http11
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
        Prism::SharedAuthenticator Authenticator{};
    };

    /**
     * @class IngressFactory
     * @brief HTTP/1.1 CONNECT 和普通正向代理的唯一接入工厂。
     * @details Accept 按值接收输入并由 InboundAdmission 守卫到结果发布；失败或
     *          异常由守卫取消并关闭，成功后由 DataPlane 接管。transport、lease、
     *          PostDial 和 response decorator 一起移入唯一 DataPlane，relay 负责
     *          后续 half-close 和最终 close。
     */
    class IngressFactory final : public Prism::Contract::StreamFactory
    {
    public:
        explicit IngressFactory(IngressOptions Options);

        /**
         * @brief 读取并认证一个 HTTP/1.1 入站请求。
         * @param Inbound 由调用方按值移交的根传输；guard 持有到结果发布。
         * @param Metadata listener 提供的请求元数据；当前 HTTP wire 不改写它。
         * @return 成功时返回唯一 typed DataPlane；失败时无可转发 plane。
         * @note 网络 I/O 在调用 executor；取消由输入 transport 的 Cancel/Close
         *       传播，最终关闭由 DataPlane/relay owner 完成。
         */
        auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override;

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "http";
        }

    private:
        struct Http1Rejection final
        {
            Prism::Http11::ServerConn& Server;
            Prism::Contract::InboundAdmission& Admission;
            std::string_view Response;
            Prism::Fault::Failure Failure;
        };

        [[nodiscard]] static auto RejectWithResponse(Http1Rejection Request)
            -> Net::awaitable<Prism::Contract::AcceptOutcome>;

        struct ResponsePlan final
        {
            bool Tunnel{false};
            bool Head{false};
            bool Upgrade{false};
        };

        /** @brief 装配单个拨号后响应和普通请求出站 framing callback；消费次数
         *         由 Runtime DataPlane contract 约束，不在 factory 内重复调度。 */
        static auto ConfigureResponse(Prism::Contract::ProtocolDataPlane &Plane,
                                      const ResponsePlan Plan) -> void;

        [[nodiscard]] static auto SendDeferredReply(
            Prism::SharedTransmission Client,
            const bool IsTunnel,
            Prism::Fault::Failure Failure)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto DecorateResponse(
            Prism::SharedTransmission Outbound,
            const ResponsePlan Plan) -> Prism::SharedTransmission;

        IngressOptions Options_;
    };

} // namespace Prism::Http11
