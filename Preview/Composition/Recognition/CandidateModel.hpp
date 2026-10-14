/**
 * @file CandidateModel.hpp
 * @brief Composition 候选的稳定数据模型。
 * @details 这里只声明 Runtime 可消费的候选元数据，以及 winner-only
 *          接入回调的所有权容器；probe、prepare 和协议 handler 工厂位于
 *          其他 Recognition 头文件中。
 */

#pragma once
#include <Preview/Contract/Ingress/StreamFactory.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <Preview/Runtime/Recognition/Profile.hpp>

namespace Preview::Composition::Recognition
{

    namespace Core = Preview::Recognition;

    /**
     * @struct CandidateOptions
     * @brief 候选的稳定元数据。
     */
    struct CandidateOptions
    {
        Core::CandidateId Id{Core::InvalidCandidate};
        std::string Name;
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
        bool Fallback{false};
        /// 冷路径正式 binding 身份；运行期 callback 不从名称反推。
        std::string BindingId;
        /// 当前 binding 的 UDP admission 能力；未绑定候选保持 false。
        bool UdpEnabled{false};
    };

    /**
     * @struct CandidateDefinition
     * @brief 监听前 cold recognition candidate 的纯值定义。
     * @details 保存配置实例、carrier 和路由匹配材料；不拥有协议 handler、认证器或 I/O。
     *          ProfileBuilder 编译后只向 Runtime 发布 CandidateSpec。
     */
    struct CandidateDefinition final
    {
        Core::CandidateId Id{Core::InvalidCandidate};
        std::string Name;
        std::string Protocol;
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
        bool Fallback{false};
        std::string Scheme;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        std::string CarrierId;
        std::string ProtocolId;
        /// 配置 binding 的稳定冷身份，不能由 Name 后缀替代。
        std::string BindingId;
        /// 该 binding 的 UDP admission 能力。
        bool UdpEnabled{false};
    };

    /**
     * @struct RecognitionDefinition
     * @brief ProfileBuilder 使用的唯一 cold recognition 配置值。
     * @details 只在 Composition 冷装配阶段消费；Routes 与 Candidates 不跨 await，
     *          编译完成后由 Runtime Profile 接管不可变值。
     */
    struct RecognitionDefinition final
    {
        bool Explicit{false};
        Core::RecognitionMode Mode{Core::RecognitionMode::Configured};
        Core::CandidateId ConfiguredCandidate{Core::InvalidCandidate};
        Core::CandidateId DefaultCandidate{Core::InvalidCandidate};
        Core::RecognitionBudget Budget{};
        std::vector<CandidateDefinition> Candidates;
        std::vector<Core::RouteBinding> Routes;
    };

    struct CandidateInnerBinding;

    /**
     * @struct CandidateBinding
     * @brief Runtime 候选与其 winner-only 接入器。
     * @details Accept 按值持有协议 handler 及其依赖；Inner 只在 TLS
     *          carrier 完成后用于回放内层协议的纯 probe 和接入器。
     */
    struct CandidateBinding
    {
        Core::CandidateSpec Spec;
        std::shared_ptr<Preview::Contract::StreamFactory> Accept;
        std::shared_ptr<const CandidateInnerBinding> Inner;
    };

    using CandidateBuilder = std::function<std::optional<CandidateBinding>(
        const CandidateDefinition &)>;

    /**
     * @struct CandidateInnerBinding
     * @brief TLS 外层解密后的内层协议候选。
     * @details 外层 carrier 相同而内层协议不同的候选在 TLS 握手前无法区分，
     *          由 LayeredCandidateFactory 保存此元数据，供解密后回放试探。
     */
    struct CandidateInnerBinding final
    {
        Core::CandidateSpec Spec;
        std::shared_ptr<Preview::Contract::StreamFactory> Accept;
    };

} // namespace Preview::Composition::Recognition
