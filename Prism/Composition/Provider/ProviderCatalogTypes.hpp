/** @file ProviderCatalogTypes.hpp @brief 已实施代理协议的 typed Prepare/Bind owning 变体。 */
#pragma once

#include <Prism/Protocols/Anytls/Binding.hpp>
#include <Prism/Protocols/Hysteria2/Binding.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Binding.hpp>
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Protocols/Trojan/Binding.hpp>
#include <Prism/Protocols/Trusttunnel/Binding.hpp>
#include <Prism/Protocols/Tuic/Binding.hpp>
#include <Prism/Protocols/Vless/Binding.hpp>
#include <Prism/Protocols/Vmess/Binding.hpp>

#include <memory>
#include <variant>

namespace Prism::Composition::Provider
{
    /** @brief 冷 Prepare 阶段唯一支持的协议 owner 值；carrier 和 Mux 各有独立槽位。 */
    using PreparedInstance = std::variant<Prism::Socks5::Prepared,
        Prism::Shadowsocks2022::Prepared, Prism::Hysteria2::Prepared, Prism::Tuic::Prepared,
        Prism::Http11::PreparedBinding, Prism::Vless::PreparedBinding,
        Prism::Trojan::PreparedBinding, Prism::Vmess::PreparedBinding,
        Prism::Anytls::PreparedBinding, Prism::Trusttunnel::PreparedBinding>;

    /** @brief 发布阶段具体协议的 owning shared pointer；关闭和排空归实际 protocol owner。 */
    using ActiveBinding = std::variant<std::shared_ptr<Prism::Socks5::Binding>,
        std::shared_ptr<Prism::Shadowsocks2022::Binding>, std::shared_ptr<Prism::Hysteria2::Binding>,
        std::shared_ptr<Prism::Tuic::Binding>, std::shared_ptr<Prism::Http11::Binding>,
        std::shared_ptr<const Prism::Vless::Binding>, std::shared_ptr<const Prism::Trojan::Binding>,
        std::shared_ptr<const Prism::Vmess::Binding>, std::shared_ptr<const Prism::Anytls::Binding>,
        std::shared_ptr<const Prism::Trusttunnel::Binding>>;
}
