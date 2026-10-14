/** @file ProviderCatalogTypes.hpp @brief 已实施代理协议的 typed Prepare/Bind owning 变体。 */
#pragma once

#include <Preview/Protocols/Anytls/Binding.hpp>
#include <Preview/Protocols/Hysteria2/Binding.hpp>
#include <Preview/Protocols/Http1/Binding.hpp>
#include <Preview/Protocols/Shadowsocks2022/Binding.hpp>
#include <Preview/Protocols/Socks5/Binding.hpp>
#include <Preview/Protocols/Trojan/Binding.hpp>
#include <Preview/Protocols/Trusttunnel/Binding.hpp>
#include <Preview/Protocols/Tuic/Binding.hpp>
#include <Preview/Protocols/Vless/Binding.hpp>
#include <Preview/Protocols/Vmess/Binding.hpp>

#include <memory>
#include <variant>

namespace Preview::Composition::Provider
{
    /** @brief 冷 Prepare 阶段唯一支持的协议 owner 值；carrier 和 Mux 各有独立槽位。 */
    using PreparedInstance = std::variant<Preview::Socks5::Prepared,
        Preview::Shadowsocks2022::Prepared, Preview::Hysteria2::Prepared, Preview::Tuic::Prepared,
        Preview::Http11::PreparedBinding, Preview::Vless::PreparedBinding,
        Preview::Trojan::PreparedBinding, Preview::Vmess::PreparedBinding,
        Preview::Anytls::PreparedBinding, Preview::Trusttunnel::PreparedBinding>;

    /** @brief 发布阶段具体协议的 owning shared pointer；关闭和排空归实际 protocol owner。 */
    using ActiveBinding = std::variant<std::shared_ptr<Preview::Socks5::Binding>,
        std::shared_ptr<Preview::Shadowsocks2022::Binding>, std::shared_ptr<Preview::Hysteria2::Binding>,
        std::shared_ptr<Preview::Tuic::Binding>, std::shared_ptr<Preview::Http11::Binding>,
        std::shared_ptr<const Preview::Vless::Binding>, std::shared_ptr<const Preview::Trojan::Binding>,
        std::shared_ptr<const Preview::Vmess::Binding>, std::shared_ptr<const Preview::Anytls::Binding>,
        std::shared_ptr<const Preview::Trusttunnel::Binding>>;
}
