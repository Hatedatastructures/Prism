/** @file Prepared.hpp @brief SOCKS5 配置实例的实际材料及关联服务准备。 */
#pragma once
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <expected>
namespace Prism::Socks5
{
    struct Preparation final
    {
        std::string Instance;
        Prism::Foundation::GenerationPin Generation;
        ServerConfig Config;
    };
    struct BindingServices final
    {
        boost::asio::any_io_executor Executor;
        Prism::Contract::AuthenticationServices Authentication;
        Prism::Contract::DatagramServices Datagrams;
    };
    /** @brief 拥有已校验配置和实际服务；没有活动 socket，不可复制或重复 Bind。 */
    struct Prepared final
    {
        Preparation Input;
        BindingServices Services;
        Prepared(Preparation InputValue, BindingServices ServiceValue)
            : Input(std::move(InputValue)), Services(std::move(ServiceValue)) {}
        Prepared(Prepared&&) = default;
        auto operator=(Prepared&&) -> Prepared& = default;
        Prepared(const Prepared&) = delete;
    };
    /** @brief 冷路径接管实例材料；错误含非敏感配置路径。无 I/O、取消、半关闭或活动 closer。 */
    [[nodiscard]] inline auto Prepare(Preparation Input, BindingServices Services)
        -> std::expected<Prepared, Prism::Contract::ProviderFailure>
    {
        using Error = Prism::Contract::ProviderError;
        auto Fail = [&Input](Error Code, std::string Path)
        { return std::unexpected(Prism::Contract::ProviderFailure{Code, Input.Instance, std::move(Path)}); };
        if (Input.Instance.empty() || !Services.Executor || (!Input.Config.EnableTcp && !Input.Config.EnableUdp))
            return Fail(Error::InvalidConfiguration, "Options");
        if (!Services.Authentication.Matches(Input.Generation))
            return Fail(Error::GenerationMismatch, "Generation");
        if (Input.Config.EnableAuth && (!Services.Authentication.Authenticator || !Services.Authentication.Credentials))
            return Fail(Error::MissingAuthentication, "Authentication");
        if (Input.Config.EnableUdp && !Services.Datagrams.Resolve)
            return Fail(Error::MissingResolver, "Datagrams.Resolve");
        Input.Config.Authenticator = Services.Authentication.Authenticator;
        Input.Config.DeferConnectReply = true;
        return Prepared(std::move(Input), std::move(Services));
    }
}
