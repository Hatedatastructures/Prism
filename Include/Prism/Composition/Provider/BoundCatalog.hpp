/** @file BoundCatalog.hpp @brief 已发布 provider binding 与 carrier owner 的物理退休目录。 */
#pragma once

#include <Prism/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Prism/Composition/Provider/ProviderBindingVariants.hpp>
#include <Prism/Composition/Provider/MuxProvider.hpp>
#include <Prism/Contract/Ingress/CarrierCatalogOwner.hpp>
#include <Prism/Contract/Ingress/Protocol.hpp>
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Contract/Ingress/ProviderFailure.hpp>
#include <Prism/Contract/Ingress/Datagram/Raw.hpp>
#include <Prism/Contract/Ingress/StreamFactory.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Composition::Provider
{
    class FrozenCatalog;
    struct PhysicalRetirementEntry final
    {
        std::string Owner;
        PhysicalRetirementState State{PhysicalRetirementState::Unknown};
    };

    /** @brief 一次 BoundCatalog owner 物理退休快照；与公开 Drain 历史 Failure 相互独立。 */
    struct PhysicalRetirementReceipt final
    {
        std::vector<PhysicalRetirementEntry> Owners;

        /** @brief 只有所有 owner 都明确报告 Retired 才能安全归还代次资源。 */
        [[nodiscard]] auto Complete() const noexcept -> bool;
    };

    /**
     * @brief 一个已发布 protocol binding 的冷 typed view。
     * @details Owner 保留唯一 binding；返回的 Stream/Mux/Quic/Raw 句柄只是 owning shared
     *          view 或空值，不复制 prepared secret、认证 lease，也不参与 packet/frame 查找。
     *          所有方法都属于冷路径，调用者负责在 binding 所属 executor 上驱动后续关闭。
     */
    struct BoundInstance final
    {
        std::string Id;
        Prism::Contract::ProtocolType Protocol;
        ActiveBinding Owner;
        /** @brief 读取实际 typed owner 物理回执；缺少 getter 时保持 Unknown。 */
        [[nodiscard]] auto PhysicalRetirement() const noexcept -> PhysicalRetirementState;
        /** @brief 返回具体 provider 已记录的持久 drain 首因；不把 attempt cancellation 当历史错误。 */
        [[nodiscard]] auto DrainFailure() const noexcept
            -> std::optional<Prism::Fault::Failure>;
        [[nodiscard]] auto HasDrainFailureSource() const noexcept -> bool;
        /**
         * @brief 返回已有 owner 的 typed stream view。
         * @return 具体 Owner 实现 StreamFactory 时返回 shared view；协议 recipe 在候选 binding 阶段生成 factory；
         *         不支持该接口的 variant 返回空值。
         * @note 只在冷装配调用；返回 shared pointer 延长 owner 生命周期，不转移或复制 lease。
         */
        [[nodiscard]] auto Stream() const -> std::shared_ptr<Prism::Contract::StreamFactory>;
        /**
         * @brief 监听前从唯一 provider material 派生正式 wire factory。
         * @param Mux 按值接收的 cold RootBinding view；WithMux 注册后由共享 binding state 关闭。
         * @return S5/SS2022 返回共享 material 的 typed stream view；其他协议或注册失败返回空。
         * @note 这是监听前的冷派生 view；每次调用都可登记一个 factory，共享同一 material，
         *       不消费 Prepared/lease 的唯一机会。它不查运行期字符串模式、不复制认证/lease，
         *       也不把空槽当作 fallback；分配异常不在此处转成 typed failure。
         */
        [[nodiscard]] auto MuxStream(std::shared_ptr<Prism::Mux::RootBinding> Mux) const
            -> std::shared_ptr<Prism::Contract::StreamFactory>;
        /**
         * @brief 返回 QUIC owner 的 typed view；TCP binding 返回空值。
         * @return shared view 不复制 prepared；后续 Close/Drain 仍归具体 QUIC binding。
         * @note 冷路径查询，不执行网络操作或 half-close。
         */
        [[nodiscard]] auto Quic() const -> std::shared_ptr<Prism::Contract::QuicConnectionFactory>;
        /**
         * @brief 返回 SS2022 raw datagram ingress 的 shared view。
         * @return RawUdp 未配置或非 SS2022 时为空；不转移 gateway/socket 关闭权。
         * @note datagram 没有 stream half-close，实际关闭由 binding/gateway owner 完成。
         */
        [[nodiscard]] auto Raw() const -> std::shared_ptr<Prism::Contract::RawDatagramIngress>;
    };
    /**
     * @brief 已发布 binding 的唯一 catalog owner。
     * @details Move assignment 会先请求旧 owner 关闭；析构只 Close，不等待异步排空。Find/Entries
     *          只服务冷装配，返回的 pointer/span 在本 catalog 未移动、销毁或改变前有效。
     *          本类不承诺多个 caller 并发访问、Close 或 Drain 的顺序。
     */
    class BoundCatalog final
    {
    public:
        BoundCatalog()=default;
        BoundCatalog(const BoundCatalog&)=delete;
        auto operator=(const BoundCatalog&) -> BoundCatalog& = delete;
        /** @brief 移动唯一 entries owner；源对象不再提供此前 pointer/span 的有效期。 */
        BoundCatalog(BoundCatalog&& Other) noexcept;
        /** @brief 先请求当前 owner 关闭，再接管 Other 的 entries 与首个 Drain 失败；不等待 drain。 */
        auto operator=(BoundCatalog&& Other) noexcept -> BoundCatalog&;
        /** @brief 析构只提交 Close；不会隐式等待 executor 或真实 owner 退栈。 */
        ~BoundCatalog();
        /**
         * @brief 冷路径按配置实例 ID 查询。
         * @return 指向本 catalog 内 BoundInstance 的借用指针，未找到返回空；不会进入 packet/frame 热路径。
         * @note 指针只在本 catalog 未移动、销毁或修改 entries 期间有效，调用者负责串行冷访问。
         */
        [[nodiscard]] auto Find(std::string_view Id) const -> const BoundInstance*;
        /**
         * @brief 借用当前已发布 entries 的只读 span。
         * @return span 指向本 catalog 的存储；catalog 移动、销毁或 entries 变化后失效。
         * @note 仅供冷装配，不提供跨线程/多 caller 并发保证。
         */
        [[nodiscard]] auto Entries() const -> std::span<const BoundInstance> {return Entries_;}

        /** @brief 冷路径读取唯一已编译 QUIC listener factory；不进入 CID 热路径。 */
        [[nodiscard]] auto QuicIngressBinding() const
            -> std::expected<std::optional<Prism::Contract::QuicIngressBindingSnapshot::Binding>,
                Prism::Contract::ProviderFailure>;

        /** @brief 返回本 generation provider catalog 使用的唯一活动计数。 */
        [[nodiscard]] auto UseState() const noexcept
            -> std::shared_ptr<Prism::Foundation::GenerationUseState>
        {
            return UseState_;
        }
        /** @brief 按名称接管一个 generation-owned carrier callback catalog。 */
        [[nodiscard]] auto AdoptCarrierOwner(std::string Name,
            std::shared_ptr<Prism::Contract::CarrierCatalogOwner> Owner)
            -> std::expected<void, Prism::Contract::ProviderFailure>;
        /** @brief 返回该协议 binding 预先绑定的 mux root；仅供监听前候选组装。 */
        [[nodiscard]] auto MuxesForProtocol(const std::string_view ProtocolId) const
            -> std::vector<BoundMux>;
        /** @brief 按值快照所有 protocol/QUIC/Mux owner 的独立物理退休状态。 */
        [[nodiscard]] auto PhysicalRetirement() const -> PhysicalRetirementReceipt;
        /** @brief 已保存的持久 drain 首因；本轮可重试取消单独返回且不写入此值。 */
        [[nodiscard]] auto DrainFailure() const noexcept
            -> std::optional<Prism::Fault::Failure>
        {
            return FirstFailure_;
        }
        /**
         * @brief 请求所有具体 binding 关闭。
         * @note noexcept 且不等待；真正 cancellation、half-close 和最终 close 仍由各 protocol
         *       owner 在其 executor 完成。失败不会在此同步接口中伪造为 drain 成功。
         */
        auto Close() noexcept -> void;
        /**
         * @brief 请求关闭并排空全部具体 binding owner。
         * @return expected<void, Fault::Failure>；失败保留首个 owner 的完整类型化原因。
         * @details caller 必须驱动相关 binding executor；首个 typed failure 会被保存，
         *          本函数仍尝试其余 owner。只有独立 getter 明确报告 Retired 才释放该 owner；
         *          Drain 历史错误原样返回，Unknown owner 保留且其回执不能归还代次资源。
         *          没有多 waiter 顺序保证。
         */
        auto Drain()
            -> boost::asio::awaitable<std::expected<void,Prism::Fault::Failure>>;
    private:
        friend class FrozenCatalog;
        explicit BoundCatalog(std::vector<BoundInstance> Values, std::vector<BoundMux> Muxes,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);
        template<typename T>
        static auto CloseOwner(const T& Owner) noexcept -> void;
        std::vector<BoundInstance> Entries_;
        std::vector<BoundMux> Muxes_;
        std::vector<std::pair<std::string,
            std::shared_ptr<Prism::Contract::CarrierCatalogOwner>>> CarrierOwners_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        std::optional<Prism::Fault::Failure> FirstFailure_;
    };
}
