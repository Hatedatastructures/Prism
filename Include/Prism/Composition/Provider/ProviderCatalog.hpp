/** @file ProviderCatalog.hpp @brief 配置实例的唯一 Prepared/Frozen/Bound 事务；真实 owner 拥有资源。 */
#pragma once
#include <Prism/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Prism/Composition/Provider/ProviderBindingVariants.hpp>
#include <Prism/Composition/Provider/MuxProvider.hpp>
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <stop_token>
#include <unordered_map>
#include <vector>
namespace Prism::Composition::Provider
{
    /**
     * @brief Prepared 值冻结后的唯一绑定事务。
     * @details Bind 只允许一次，按顺序消费 prepared；失败或 stop 会关闭已发布前的全部
     *          partial owner。它是冷控制路径，不承担网络 I/O、stream half-close 或运行期取消。
     */
    class FrozenCatalog final
    {
    public:
        FrozenCatalog(FrozenCatalog&& Other) noexcept;
        FrozenCatalog(const FrozenCatalog&)=delete;
        /**
         * @brief 消耗唯一绑定机会，并在发布前后检查 stop。
         * @param Stop 按值读取的冷构造取消请求；不取消已发布运行期 I/O。
         * @return BoundCatalog 成功拥有所有 binding；AlreadyBound/Cancelled 或具体
         *         ProviderFailure 表示 typed 失败。失败按逆序 Close 已创建但未发布的 owner，
         *         不承诺可重试；分配/owner 异常不在这里伪造为成功。
         * @note 没有 stream half-close；成功后的 Close/Drain 归 BoundCatalog 和具体 protocol owner。
         */
        [[nodiscard]] auto Bind(std::stop_token Stop)
            -> std::expected<BoundCatalog, Prism::Contract::ProviderFailure>;
    private:
        friend class PreparedCatalog;
        explicit FrozenCatalog(std::vector<PreparedInstance> Values,
            std::vector<PreparedMux> MuxValues,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);
        template<typename T>
        static auto InstanceId(const T& Value) -> std::string;
        template<typename T>
        static auto BindInstance(T Value, std::stop_token Stop)
            -> std::expected<BoundInstance, Prism::Contract::ProviderFailure>;
        static auto CloseEntries(std::vector<BoundInstance>& Values) -> void;
        static auto CloseMuxes(std::vector<BoundMux>& Values) noexcept -> void;
        std::vector<PreparedInstance> Entries_;
        std::vector<PreparedMux> MuxValues_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        bool Bound_{false};
    };
    /**
     * @brief Prepare 产生的唯一 prepared catalog。
     * @details Entries 只读借用到 Freeze 或对象移动前；Freeze 移动全部值并封止第二次消费，
     *          不建立第二份可变 registry。
     */
    class PreparedCatalog final
    {
    public:
        PreparedCatalog(PreparedCatalog&& Other) noexcept;
        PreparedCatalog(const PreparedCatalog&)=delete;
        /**
         * @brief 借用当前 prepared 值的只读 span。
         * @return span 只在本 catalog 未 Freeze、移动或销毁期间有效；不会进入热路径。
         */
        [[nodiscard]] auto Entries() const->std::span<const PreparedInstance>{return Entries_;}
        /**
         * @brief 移动所有 prepared 值并冻结唯一绑定机会。
         * @return FrozenCatalog 成功；重复调用返回 ProviderError::AlreadyFrozen，异常不吞掉。
         * @note 冷同步操作，无 cancellation、executor 或 stream half-close；调用者负责串行访问。
         */
        [[nodiscard]] auto Freeze()
            -> std::expected<FrozenCatalog, Prism::Contract::ProviderFailure>;
    private:
        friend class ProviderCatalog;
        explicit PreparedCatalog(std::vector<PreparedInstance> Values,
            std::vector<PreparedMux> MuxValues,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState);
        std::vector<PreparedInstance> Entries_;
        std::vector<PreparedMux> MuxValues_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        bool Frozen_{false};
    };
    /**
     * @brief 从静态协议描述构造唯一 typed Prepared/Frozen/Bound 事务的入口。
     * @details Handles/Prepare 都是冷路径；不把未实现协议映射为空槽成功，不拥有运行期
     *          packet/frame 循环。Prepare 的 typed error/异常边界向调用者传播，真正关闭者
     *          是返回的协议 binding、root、gateway 和 catalog owner。
     */
    class ProviderCatalog final
    {
    public:
        /**
         * @brief 查询 ProtocolCatalog 中是否有本入口的已实施真实槽位。
         * @param Name 借用到同步返回的 builtin 名称。
         * @return Descriptor 存在且有正式 TCP proxy 或 QUIC proxy slot 时为 true；TLS carrier 由独立槽登记。
         * @note 无状态、无 executor、无取消和半关闭；不会创建 fallback 或运行期对象。
         */
        [[nodiscard]] static auto Handles(std::string_view Name) -> bool;

        /**
         * @brief 按值接管 configured instances，为每个实例建立 typed Prepared。
         * @param Input 移动 Generation 与 configured instances；调用者不再拥有这些冷值。
         * @param Services 按值接管 service shared handles，Executor 只用于后续 owner 的运行上下文。
         * @return PreparedCatalog 成功；重复 ID、未知 builtin、缺失 QUIC/歧义 listener 或协议
          *         Prepare 失败返回对应 ProviderFailure，未在此处伪造 fallback；配置了 mux 的代次
          *         必须提供唯一 GenerationUseState，否则返回 GenerationMismatch；分配/构造异常传播。
         * @note 同步冷路径，无网络 I/O、cancellation token 或 stream half-close；后续关闭归真实
         *       binding/catalog/protocol owner，不能捕获本次参数中的裸地址到运行期。
         */
        [[nodiscard]] static auto Prepare(Preparation Input, BindingServices Services)
            -> std::expected<PreparedCatalog, Prism::Contract::ProviderFailure>;

    };

    struct ConfigurationInput final
    {
        Prism::Foundation::GenerationPin Generation;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
        std::span<const Prism::Contract::ProtocolConfiguration> Protocols;
        std::span<const Prism::Contract::ProtocolBindingConfiguration> Bindings;
        std::unordered_map<std::string, Prism::Contract::AuthenticationServices> Authentication;
    };

    /** @brief 将配置协议实例编译为唯一 typed provider 准备事务。 */
    [[nodiscard]] auto Compile(ConfigurationInput Input, BindingServices Services)
        -> std::expected<PreparedCatalog, Prism::Contract::ProviderFailure>;

}
