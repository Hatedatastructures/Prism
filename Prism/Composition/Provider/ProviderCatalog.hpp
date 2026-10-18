/** @file ProviderCatalog.hpp @brief 配置实例的唯一 Prepared/Frozen/Bound 事务；真实 owner 拥有资源。 */
#pragma once
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>
#include <Prism/Composition/Provider/ProviderCatalogInputs.hpp>
#include <Prism/Composition/Provider/ProviderCatalogTypes.hpp>
#include <Prism/Composition/Provider/ProviderInstancePreparation.hpp>
#include <Prism/Composition/Provider/MuxProvider.hpp>
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <stop_token>
#include <unordered_set>
#include <exception>
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
        FrozenCatalog(FrozenCatalog&& Other) noexcept
            : Entries_(std::move(Other.Entries_)), MuxValues_(std::move(Other.MuxValues_)),
              UseState_(std::move(Other.UseState_)),
              Bound_(std::exchange(Other.Bound_, true))
        {
        }
        FrozenCatalog(const FrozenCatalog&)=delete;
        /**
         * @brief 消耗唯一绑定机会，并在发布前后检查 stop。
         * @param Stop 按值读取的冷构造取消请求；不取消已发布运行期 I/O。
         * @return BoundCatalog 成功拥有所有 binding；AlreadyBound/Cancelled 或具体
         *         ProviderFailure 表示 typed 失败。失败按逆序 Close 已创建但未发布的 owner，
         *         不承诺可重试；分配/owner 异常不在这里伪造为成功。
         * @note 没有 stream half-close；成功后的 Close/Drain 归 BoundCatalog 和具体 protocol owner。
         */
        [[nodiscard]] auto Bind(std::stop_token Stop) -> std::expected<BoundCatalog,Prism::Contract::ProviderFailure>
        {
            using Error=Prism::Contract::ProviderError;
            if(Bound_)return std::unexpected(Prism::Contract::ProviderFailure{Error::AlreadyBound,{},"Bind"});
            Bound_=true;
            std::vector<BoundInstance> Result;
            auto MuxValues = std::move(MuxValues_);
            for(auto& Value:Entries_)
            {
                auto Entry=std::visit([Stop](auto& Prepared)->std::expected<BoundInstance,Prism::Contract::ProviderFailure>
                { return BindInstance(std::move(Prepared),Stop); },Value);
                if (!Entry)
                {
                    CloseEntries(Result);
                    return std::unexpected(Entry.error());
                }
                Result.push_back(std::move(*Entry));
                if (Stop.stop_requested())
                {
                    CloseEntries(Result);
                    return std::unexpected(Prism::Contract::ProviderFailure{Error::Cancelled, {}, "Bind"});
                }
            }
            Entries_.clear();
            std::vector<BoundMux> BoundMuxes;
            for (auto& Value : MuxValues)
            {
                auto Bound = Prism::Composition::Provider::BindMux(std::move(Value), Stop.stop_requested());
                if (!Bound)
                {
                    CloseEntries(Result);
                    CloseMuxes(BoundMuxes);
                    return std::unexpected(Bound.error());
                }
                BoundMuxes.push_back(std::move(*Bound));
                if (Stop.stop_requested())
                {
                    CloseEntries(Result);
                    CloseMuxes(BoundMuxes);
                    return std::unexpected(Prism::Contract::ProviderFailure{Error::Cancelled, {}, "Bind"});
                }
            }
            MuxValues.clear();
            if (Stop.stop_requested())
            {
                CloseEntries(Result);
                CloseMuxes(BoundMuxes);
                return std::unexpected(Prism::Contract::ProviderFailure{Error::Cancelled, {}, "Publish"});
            }
            return BoundCatalog(std::move(Result), std::move(BoundMuxes),
                std::move(UseState_));
        }
    private:
        friend class PreparedCatalog;
        explicit FrozenCatalog(std::vector<PreparedInstance> Values,
            std::vector<PreparedMux> MuxValues,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
            : Entries_(std::move(Values)), MuxValues_(std::move(MuxValues)),
              UseState_(std::move(UseState))
        {
        }
        template<typename T>
        static auto InstanceId(const T& Value) -> std::string
        {
            if constexpr(requires{Value.Input.Instance;})return Value.Input.Instance;
            else return Value.Instance;
        }
        template<typename T>static auto BindInstance(T Value,std::stop_token Stop)
            -> std::expected<BoundInstance,Prism::Contract::ProviderFailure>
        {
            const auto Id=InstanceId(Value);
            if constexpr(std::is_same_v<T,Prism::Socks5::Prepared>)
            {
                auto Bound=Prism::Socks5::Bind(std::move(Value),Stop);
                if(!Bound)return std::unexpected(Bound.error());
                return BoundInstance{Id,Prism::Contract::ProtocolType::Socks5,std::move(*Bound)};
            }
            else if constexpr(std::is_same_v<T,Prism::Shadowsocks2022::Prepared>)
            {
                auto Bound=Prism::Shadowsocks2022::Bind(std::move(Value),Stop);
                if(!Bound)return std::unexpected(Bound.error());
                return BoundInstance{Id,Prism::Contract::ProtocolType::Shadowsocks,std::move(*Bound)};
            }
            else if constexpr(std::is_same_v<T,Prism::Hysteria2::Prepared>)
            {
                auto Bound=Prism::Hysteria2::Bind(std::move(Value),Stop);
                if(!Bound)return std::unexpected(Bound.error());
                return BoundInstance{Id,Prism::Contract::ProtocolType::Hysteria2,std::move(*Bound)};
            }
            else if constexpr(std::is_same_v<T,Prism::Tuic::Prepared>)
            {
                auto Bound=Prism::Tuic::Bind(std::move(Value),Stop);
                if(!Bound)return std::unexpected(Bound.error());
                return BoundInstance{Id,Prism::Contract::ProtocolType::Tuic,std::move(*Bound)};
            }
            else if constexpr(std::is_same_v<T,Prism::Http11::PreparedBinding>)
            {
                if(Stop.stop_requested())return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::Cancelled,Id,"Bind"});
                return BoundInstance{Id,Prism::Contract::ProtocolType::Http,
                    Prism::Http11::BindProvider(std::move(Value))};
            }
            else if constexpr(std::is_same_v<T,Prism::Vless::PreparedBinding>)
            {
                if(Stop.stop_requested())return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::Cancelled,Id,"Bind"});
                return BoundInstance{Id,Prism::Contract::ProtocolType::Vless,
                    Prism::Vless::BindProvider(std::move(Value))};
            }
            else if constexpr(std::is_same_v<T,Prism::Trojan::PreparedBinding>)
            {
                if(Stop.stop_requested())return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::Cancelled,Id,"Bind"});
                return BoundInstance{Id,Prism::Contract::ProtocolType::Trojan,
                    Prism::Trojan::BindProvider(std::move(Value))};
            }
            else if constexpr(std::is_same_v<T,Prism::Vmess::PreparedBinding>)
            {
                if(Stop.stop_requested())return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::Cancelled,Id,"Bind"});
                return BoundInstance{Id,Prism::Contract::ProtocolType::Vmess,
                    Prism::Vmess::BindProvider(std::move(Value))};
            }
            else if constexpr(std::is_same_v<T,Prism::Anytls::PreparedBinding>)
            {
                if(Stop.stop_requested())return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::Cancelled,Id,"Bind"});
                return BoundInstance{Id,Prism::Contract::ProtocolType::AnyTls,
                    Prism::Anytls::BindProvider(std::move(Value))};
            }
            else
            {
                if(Stop.stop_requested())return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::Cancelled,Id,"Bind"});
                return BoundInstance{Id,Prism::Contract::ProtocolType::TrustTunnel,
                    Prism::Trusttunnel::BindProvider(std::move(Value))};
            }
        }
        static auto CloseEntries(std::vector<BoundInstance>& Values)->void
        {
            for(auto It=Values.rbegin();It!=Values.rend();++It)
                std::visit([](const auto& Owner){BoundCatalog::CloseOwner(Owner);},It->Owner);
        }
        static auto CloseMuxes(std::vector<BoundMux>& Values) noexcept -> void
        {
            for (auto It = Values.rbegin(); It != Values.rend(); ++It)
            {
                It->Close();
            }
        }
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
        PreparedCatalog(PreparedCatalog&& Other) noexcept
            : Entries_(std::move(Other.Entries_)), MuxValues_(std::move(Other.MuxValues_)),
              UseState_(std::move(Other.UseState_)),
              Frozen_(std::exchange(Other.Frozen_, true))
        {
        }
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
        [[nodiscard]] auto Freeze()->std::expected<FrozenCatalog,Prism::Contract::ProviderFailure>
        {
            if(Frozen_)return std::unexpected(Prism::Contract::ProviderFailure{
                Prism::Contract::ProviderError::AlreadyFrozen,{},"Freeze"});
            Frozen_ = true;
            return FrozenCatalog(std::move(Entries_), std::move(MuxValues_),
                std::move(UseState_));
        }
    private:
        friend class ProviderCatalog;
        explicit PreparedCatalog(std::vector<PreparedInstance> Values,
            std::vector<PreparedMux> MuxValues,
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState)
            : Entries_(std::move(Values)), MuxValues_(std::move(MuxValues)),
              UseState_(std::move(UseState))
        {
        }
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
        [[nodiscard]] static auto Handles(std::string_view Name)->bool
        {
            return ProtocolProviderPreparation::Handles(Name);
        }

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
        [[nodiscard]] static auto Prepare(Preparation Input,BindingServices Services)
            ->std::expected<PreparedCatalog,Prism::Contract::ProviderFailure>
        {
            auto MuxValues = Prism::Composition::Provider::PrepareMuxes(
                MuxCatalogPreparation{Input.Bindings, Input.Instances, Services.Streams,
                    Input.Generation, Input.UseState});
            if (!MuxValues)
            {
                return std::unexpected(MuxValues.error());
            }
            ProtocolProviderPreparation::State State;
            std::vector<PreparedInstance> Values;
            Values.reserve(Input.Instances.size());
            for(auto& Instance:Input.Instances)
            {
                auto Prepared = ProtocolProviderPreparation::Prepare(
                    ProtocolProviderPreparation::Input{
                    std::move(Instance), Input.Generation, Input.UseState, Services}, State);
                if (!Prepared) return std::unexpected(Prepared.error());
                Values.push_back(std::move(*Prepared));
            }
            return PreparedCatalog(std::move(Values), std::move(*MuxValues),
                std::move(Input.UseState));
        }

    };
}
