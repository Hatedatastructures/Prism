/** @file Prepared.hpp @brief SS2022 实例材料准备；全部 PSK 必须属于原 generation 的账户记录。 */
#pragma once
#include <Prism/Contract/Services/Authentication.hpp>
#include <Prism/Contract/Services/Datagram/Egress.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Protocols/Common/Authentication/ScopedMaterial.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Prism::Shadowsocks2022
{
    struct BindingConfig final
    {
        bool EnableTcp{true};
        bool RawUdp{false};
        std::uint64_t TimeWindow{90};
        std::chrono::milliseconds RelayTimeout{2000};
        std::chrono::milliseconds PeerIdleTimeout{60000};
        std::size_t MaxPeers{1024};
    };
    struct Preparation final
    {
        std::string Instance;
        Prism::Foundation::GenerationPin Generation;
        BindingConfig Config;
    };
    struct BindingServices final
    {
        Net::any_io_executor Executor;
        Prism::Contract::AuthenticationServices Authentication;
        std::shared_ptr<Prism::Contract::DatagramEgress> Egress;
        std::shared_ptr<Prism::Contract::DatagramSender> Sender;
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic;
    };
    /** @brief 无活动 socket 的单次拥有值；记录拥有 SecureBytes，不保存 borrowed key span。 */
    struct Prepared final
    {
        Preparation Input;
        BindingServices Services;
        std::vector<Prism::Protocols::ScopedMaterial> Credentials;
        Prepared(Preparation InputValue, BindingServices ServicesValue)
            : Input(std::move(InputValue)), Services(std::move(ServicesValue)) {}
        Prepared(Prepared&&) = default;
        auto operator=(Prepared&&) -> Prepared& = default;
        Prepared(const Prepared&) = delete;
    };
    /** @brief 接管实际配置/材料/服务并验证；无 I/O，错误路径不含秘密，不产生租约。 */
    [[nodiscard]] auto Prepare(Preparation Input, BindingServices Services)
        -> std::expected<Prepared, Prism::Contract::ProviderFailure>;
    /** @brief 仅在协议 wire 边界复制固定长度工作 key；记录和秘密寿命继续由 owning credential 持有。 */
    [[nodiscard]] auto WireKey(const Prism::Protocols::ScopedMaterial& Record)
        -> std::array<std::uint8_t,16>;
}
