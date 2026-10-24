/**
 * @file CandidateFactory.hpp
 * @brief Composition 层协议候选与 handler resolver 工厂
 * @details CandidateSpec 只保存 Runtime 可理解的结构检查、认证准备和
 *          replay 提交回调；具体 ProtocolHandler 由返回的 Accept 回调持有，
 *          只有 Session 在 winner 确定后才会调用它。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Composition/Recognition/CandidateModel.hpp>
#include <Prism/Composition/Recognition/TrusttunnelCandidate.hpp>
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <Prism/Composition/Provider/MuxProvider.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Runtime/Recognition/Candidate.hpp>
#include <Prism/Protocols/Http1/IngressFactory.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Prism/Protocols/Shadowsocks2022/Binding.hpp>
#include <Prism/Protocols/Socks5/Binding.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <Prism/Protocols/Trojan/RequestCodec.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    /**
     * @brief 已绑定 provider 的候选构造材料；共享唯一协议 owner，不复制认证材料。
     * @details 仅用于监听前的冷构造；Muxes 是 ProviderCatalog 已绑定的 owning roots。
     *          候选发布后，协议 binding 和 BoundCatalog 负责实际取消、排空与最终关闭。
     */
    struct ProviderCandidateInputs final
    {
        Prism::Composition::Provider::BoundInstance Owner;
        std::vector<Prism::Composition::Provider::BoundMux> Muxes;
    };

    namespace configured_detail
    {
        [[nodiscard]] auto MuxForBinding(
            const std::string_view BindingId,
            const std::vector<Prism::Composition::Provider::BoundMux> &Muxes)
            -> std::optional<Prism::Composition::Provider::BoundMux>;
    }

    /**
     * @class CandidateFactory
     * @brief 创建标准协议候选及 winner-only handler resolver
     */
    class CandidateFactory
    {
        /** @brief 同步将具体 provider owner、候选元数据和可选 mux root 投影为 owning binding。 */
        template<typename T>
        [[nodiscard]] static auto ProjectProvider(CandidateOptions Options, const T &Owner,
            const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>;

        static auto PrepareBoundSs(const std::shared_ptr<Prism::Shadowsocks2022::Binding>& Binding,
            Core::PrepareContext Context) -> Core::PrepareResult;

        static auto PrepareHttp(Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>;

    public:
        [[nodiscard]] static auto MakeHttp(
            CandidateOptions Options,
            std::shared_ptr<Prism::Http11::Binding> Factory)
            -> CandidateBinding;

        /** @brief 冷路径接收真实绑定；候选仅检查 wire，winner 消费同一 factory。 */
        [[nodiscard]] static auto MakeSocks5(CandidateOptions Options,
            std::shared_ptr<Prism::Socks5::Binding> Binding) -> CandidateBinding;
        /** @brief 只使用实际绑定中的多账户 key；检查不调用认证器或取得任何 lease。 */
        [[nodiscard]] static auto MakeSs2022(CandidateOptions Options,
            std::shared_ptr<Prism::Shadowsocks2022::Binding> Binding) -> CandidateBinding;

        /** @brief 从已经冻结的 VLESS binding 构造 recognition owner。 */
        [[nodiscard]] static auto MakeVless(CandidateOptions Options,
            std::shared_ptr<const Prism::Vless::Binding> Owner,
            std::optional<Prism::Composition::Provider::BoundMux> Mux)
            -> std::optional<CandidateBinding>;

        /** @brief 从已经冻结的 Trojan binding 构造 recognition owner。 */
        [[nodiscard]] static auto MakeTrojan(CandidateOptions Options,
            std::shared_ptr<const Prism::Trojan::Binding> Owner,
            std::optional<Prism::Composition::Provider::BoundMux> Mux)
            -> std::optional<CandidateBinding>;

        /** @brief 从已经冻结的 VMess binding 构造 recognition owner。 */
        [[nodiscard]] static auto MakeVmess(CandidateOptions Options,
            std::shared_ptr<const Prism::Vmess::Binding> Owner,
            std::optional<Prism::Composition::Provider::BoundMux> Mux)
            -> std::optional<CandidateBinding>;
        [[nodiscard]] static auto MakeAnytls(CandidateOptions Options,
            Prism::Anytls::IngressOptions Config = {}) -> CandidateBinding;

        /**
         * @brief 同步借用 typed 配置和服务，构造拥有完整 VLESS 接入状态的候选。
         * @param Options 按值接管的候选元数据；Inputs 只借用到本次同步返回。
         * @return 拥有 ingress 的 binding；分配异常直接传播，没有异步取消或半关闭。
         * @note 后续 Accept 在入站 executor 运行，协议/root owner 负责取消、半关闭和最终关闭。
         */
    private:
        /** @brief VLESS recognition 只借用同一个 Binding 的冷 UUID 和认证器。 */
        [[nodiscard]] static auto ProjectVless(CandidateOptions Options,
            const std::shared_ptr<const Prism::Vless::Binding>& Owner,
            const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>;

        /** @brief Trojan handler 持有原 Binding；认证轨迹不另行复制 password。 */
        [[nodiscard]] static auto ProjectTrojan(CandidateOptions Options,
            const std::shared_ptr<const Prism::Trojan::Binding>& Owner,
            const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>;

        /** @brief VMess recognition 复用原 credential scope 和 session owner。 */
        [[nodiscard]] static auto ProjectVmess(CandidateOptions Options,
            const std::shared_ptr<const Prism::Vmess::Binding>& Owner,
            const std::optional<Prism::Composition::Provider::BoundMux>& Mux)
            -> std::optional<CandidateBinding>;

        /**
         * @brief 从唯一 provider material 派生候选，具体协议投影由 Composition 完成。
         * @param Options 按值接管元数据；Inputs 只在同步冷构造期间借用。
         * @return 支持的 TCP provider 返回 owning binding；空 owner 或非 TCP family 返回空值。
         * @note 不复制 secret/lease，不执行网络 I/O；分配异常直接传播。后续接入在载体
         *       executor 运行，取消、半关闭与最终 Close/Drain 由协议 binding/root owner 执行。
         */
    public:
        [[nodiscard]] static auto MakeConfiguredProvider(
            CandidateOptions Options, const ProviderCandidateInputs &Inputs)
            -> std::optional<CandidateBinding>;

    };

} // namespace Prism::Composition::Recognition
