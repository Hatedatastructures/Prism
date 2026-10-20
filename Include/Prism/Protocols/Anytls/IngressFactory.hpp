/** @file IngressFactory.hpp @brief AnyTLS 入站工厂公开接口。 */
#pragma once

#include <Prism/Protocols/Anytls/Anytls.hpp>
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Account/Authenticator.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace Prism::Anytls
{

    namespace Net = boost::asio;

    struct IngressOptions final
    {
        ServerConfig Configuration;
        Prism::Contract::StreamServices Streams;
        Prism::SharedAuthenticator Authenticator;
    };

    /**
     * @brief AnyTLS expected handshake、认证租约与 mux root 的唯一 producer。
     * @details 构造时按值接管配置和服务句柄。Accept 在入站 executor 运行；拒绝时由 admission
     *          与 retirement owner 取消、关闭并等待真实 Activity 退栈，成功时把最终关闭责任
     *          移交给唯一发布的 root plane。该对象不提供跨调用并发协调。
     */
    class IngressFactory final : public Prism::Contract::StreamFactory
    {
    public:
        explicit IngressFactory(IngressOptions Options);

        [[nodiscard]] auto Accept(Prism::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Prism::Contract::AcceptOutcome> override;

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return "anytls";
        }

    private:
        IngressOptions Options_;
    };

} // namespace Prism::Anytls
