/** @file Binding.hpp @brief VLESS 冷 UUID、认证、generation 与接入退休 owner。 */
#pragma once

#include <Prism/Account/Credential.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/ProviderLifecycle/ProviderBindingLifecycle.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Vless
{
    class IngressFactory;
    struct IngressRoute final
    {
        std::shared_ptr<Prism::Mux::RootBinding> Mux;
        bool EnableUdp{true};
    };

    /** @brief 将账户 UUID 文本严格解析为固定 16 字节值。 */
    [[nodiscard]] auto ParseAccountUuid(std::string_view Value) -> std::optional<std::array<std::uint8_t, 16>>;

    /** @brief 将标准账户 UUID 封装为正式 UUID 凭据。 */
    [[nodiscard]] auto PrepareAccountCredential(std::string_view Value)
        -> std::expected<Prism::Account::Credential, Prism::Contract::ProviderFailure>;

    struct ProviderRequest final
    {
        std::string Instance;
        Prism::Contract::AuthenticationServices Authentication;
        Prism::Contract::DatagramServices Datagrams;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        boost::asio::any_io_executor Executor;
        bool EnableUdp;
    };

    struct PreparedBinding final
    {
        std::string Instance;
        ServerConfig Configuration;
        Prism::Contract::DatagramServices Datagrams;
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState;
        boost::asio::any_io_executor Executor;
    };

    class Binding final : public std::enable_shared_from_this<Binding>
    {
        using Lifetime = Prism::Protocols::ProviderBindingLifecycle<PreparedBinding>;

    public:
        using AcceptAttempt = Lifetime::AcceptAttempt;

        ~Binding();
        Binding(const Binding&) = delete;
        auto operator=(const Binding&) -> Binding& = delete;

        /** @brief 派生同一 prepared owner 的 route view；不会复制凭据或 generation state。 */
        [[nodiscard]] auto WithIngress(IngressRoute Route) const
            -> std::shared_ptr<IngressFactory>;

        [[nodiscard]] auto Begin(Prism::SharedTransmission Inbound) const
            -> std::expected<AcceptAttempt, Prism::Fault::Failure>;

        [[nodiscard]] auto Material() const noexcept -> std::shared_ptr<const PreparedBinding>
        {
            return Lifetime_->Material();
        }

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>
        {
            return Lifetime_->UseState();
        }

        auto Close() const noexcept -> void;
        [[nodiscard]] auto Drain() const -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
        [[nodiscard]] auto IsRetired() const noexcept -> bool { return Lifetime_->IsRetired(); }
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        { return Lifetime_->DrainFailure(); }

    private:
        friend auto BindProvider(PreparedBinding) -> std::shared_ptr<const Binding>;
        friend class IngressFactory;

        explicit Binding(PreparedBinding Value);

        [[nodiscard]] static auto MakeLifetime(PreparedBinding Value)
            -> std::shared_ptr<Lifetime>;

        std::shared_ptr<Lifetime> Lifetime_;
    };

    /** @brief 为已校验 provider 材料创建唯一共享 binding owner。 */
    [[nodiscard]] auto BindProvider(PreparedBinding Prepared) -> std::shared_ptr<const Binding>;

    /** @brief 校验认证/generation 服务并选择唯一 UUID 凭据。 */
    [[nodiscard]] auto PrepareProviderBinding(ProviderRequest Request)
        -> std::expected<PreparedBinding, Prism::Contract::ProviderFailure>;
}
