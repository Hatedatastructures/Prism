/** @file Binding.hpp @brief TrustTunnel wire proof 与账户认证的冷绑定材料。 */
#pragma once

#include <boost/asio/ssl/context.hpp>

#include <Prism/Account/Credential.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>

#include <atomic>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace Prism::Trusttunnel
{
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> Prism::Account::Credential;

    struct PreparedBinding final
    {
        std::string Instance;
        std::shared_ptr<boost::asio::ssl::context> NativeTls;
        SharedWireAuthBinding Wire;
    };

    struct Binding final
    {
        explicit Binding(PreparedBinding Prepared);

        /** @brief 关闭该无独立异步活动的协议配置 owner。 */
        auto Close() const noexcept -> void;

        /** @brief 返回配置 owner 的真实关闭回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        std::string Instance;
        std::shared_ptr<boost::asio::ssl::context> NativeTls;
        SharedWireAuthBinding Wire;

    private:
        mutable std::atomic<bool> Closed_{false};
    };

    [[nodiscard]] auto ParseServerCredential(std::string_view Credential)
        -> std::expected<ServerConfig, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto PrepareProviderBinding(
        std::string Instance,
        Prism::Contract::AuthenticationServices Authentication,
        std::shared_ptr<boost::asio::ssl::context> NativeTls)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>;

    [[nodiscard]] auto BindProvider(PreparedBinding Prepared)
        -> std::shared_ptr<const Binding>;
}
