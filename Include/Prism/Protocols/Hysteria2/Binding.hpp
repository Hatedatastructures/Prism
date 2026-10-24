/**
 * @file Binding.hpp
 * @brief Hysteria2 配置准备结果与 QUIC provider 绑定接口。
 */
#pragma once

#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Contract/Services/Quic.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/QuicPreparation.hpp>
#include <Prism/Protocols/Common/QuicBindingState.hpp>
#include <Prism/Protocols/Http3/Server.hpp>

#include <atomic>
#include <expected>
#include <memory>
#include <stop_token>
#include <utility>

#include <boost/asio/awaitable.hpp>

namespace Prism::Hysteria2
{

    /** @brief Hysteria2 provider 绑定所需的 owning 服务。 */
    struct BindingServices final
    {
        Prism::Contract::QuicBindingServices Network;
        Prism::Contract::AuthenticationServices Authentication;
        std::shared_ptr<Prism::Http3::ServerFactory> Http3;
    };

    /** @brief 已校验的 Hysteria2 配置、凭据和服务材料。 */
    struct Prepared final
    {
        Prism::Protocols::QuicPreparation Input;
        BindingServices Services;
        Prism::Protocols::ScopedMaterial Credential;

        Prepared(
            Prism::Protocols::QuicPreparation Value,
            BindingServices Ports,
            Prism::Protocols::ScopedMaterial Record)
            : Input(std::move(Value)), Services(std::move(Ports)), Credential(std::move(Record))
        {
        }

        Prepared(Prepared&&) = default;
        Prepared(const Prepared&) = delete;
        auto operator=(Prepared&&) -> Prepared& = default;
        auto operator=(const Prepared&) -> Prepared& = delete;
    };

    /** @brief 校验 QUIC 端口、HTTP/3 factory 与认证材料，不启动监听。 */
    [[nodiscard]] auto Prepare(
        Prism::Protocols::QuicPreparation Input,
        BindingServices Services)
        -> std::expected<Prepared, Prism::Contract::ProviderFailure>;

    /** @brief 持有 generation 材料并创建 Hysteria2 QUIC connection lease。 */
    class Binding final : public Prism::Contract::QuicConnectionFactory
    {
    public:
        explicit Binding(Prepared Value);
        ~Binding() override;

        [[nodiscard]] auto Create(Prism::Contract::QuicAcceptRequest Request)
            -> std::expected<Prism::Contract::QuicConnectionLease,
                Prism::Contract::ProviderFailure> override;

        auto Close() noexcept -> void;
        [[nodiscard]] auto IsRetired() const noexcept -> bool override;
        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        std::atomic<std::shared_ptr<const Prepared>> Prepared_;
        std::shared_ptr<Prism::Protocols::QuicBindingState> Lifetime_;
    };

    /** @brief 将校验结果绑定为可监听的 QUIC provider。 */
    [[nodiscard]] auto Bind(Prepared Value, std::stop_token Stop)
        -> std::expected<std::shared_ptr<Binding>, Prism::Contract::ProviderFailure>;

} // namespace Prism::Hysteria2
