/**
 * @file TlsCandidateModel.hpp
 * @brief TLS carrier 候选的稳定类型与接入回调契约。
 * @details 这里拥有 carrier 选择元数据、SNI/ALPN policy 和 binding Inspect；
 *          ClientHello 解析、prepare 与实际 carrier 接入位于对应 helper 头文件。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Composition/Protocol/ProtocolCatalog.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    /// 具体 carrier 的服务端接入回调。
    using CarrierAcceptFn = std::function<Net::awaitable<Core::CarrierAcceptResult>(
        Core::CarrierAcceptInput)>;
    using CarrierAcceptPreparedFn = std::function<Net::awaitable<Core::CarrierAcceptResult>(
        Core::CarrierAcceptPreparedInput)>;

    /**
     * @enum TlsCarrier
     * @brief 已有 Prism TLS carrier 方案名。
     */
    using TlsCarrier = Prism::Composition::Protocol::CarrierKind;

    /**
     * @struct TlsCandidateOptions
     * @brief TLS carrier 候选筛选与提交参数。
     */
    struct TlsCandidateOptions
    {
        Core::CandidateId Id{Core::InvalidCandidate};
        std::string Name;
        std::string Scheme;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        bool Fallback{false};
        TlsCarrier Carrier{TlsCarrier::Native};
        /** @brief 此绑定的真实 Native SSL_CTX 在 carrier 调用期间保活。 */
        bool HasNativeTlsContext{false};
    };

    /**
     * @struct TlsMatchPolicy
     * @brief ClientHello 的纯 TLS 匹配规则。
     * @details 规则值由冷路径按值拥有；发布后通过 const shared state 供
     *          CandidateBinding 与 Spec.Inspect 共同读取，热路径不复制字符串。
     */
    struct TlsMatchPolicy final
    {
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        bool Fallback{false};
        /** @brief 只表示 ECH 扩展语法交给实际 TLS/wire owner 判断。 */
        bool PassesEchExtension{false};
        /** @brief 实际使用 Native SSL_CTX；SNI/ALPN 延至握手结果核验。 */
        bool HasNativeTlsContext{false};
    };

    /**
     * @struct TlsCandidateBinding
     * @brief TLS carrier Runtime 候选。
     */
    struct TlsCandidateBinding
    {
        Core::CandidateSpec Spec;
        std::string Scheme;

        [[nodiscard]] auto Inspect(const Core::ClientHelloFeatures &Features) const -> Core::MatchState;

    private:
        friend class TlsCandidateFactory;
        std::shared_ptr<const TlsMatchPolicy> MatchPolicy_;
    };

    namespace detail
    {

        [[nodiscard]] auto Normalize(std::string_view Value) -> std::string;

        [[nodiscard]] auto MatchesServerName(
            std::string_view ServerName,
            const std::vector<std::string> &Patterns) -> bool;

        [[nodiscard]] auto MatchesAlpn(
            const std::vector<std::string> &Offered,
            const std::vector<std::string> &Expected) -> bool;

        [[nodiscard]] auto InspectFeatures(
            const Core::ClientHelloFeatures &Features,
            const TlsMatchPolicy &Policy) -> Core::MatchState;

    } // namespace detail

} // namespace Prism::Composition::Recognition
