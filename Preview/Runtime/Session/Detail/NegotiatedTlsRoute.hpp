/**
 * @file NegotiatedTlsRoute.hpp
 * @brief 已完成 Native TLS 握手后的 SNI 路由校验。
 * @details ClientHello 扩展只影响冷识别筛选；实际 ECH 接受时 BoringSSL 返回 inner SNI，
 *          GREASE 或未协商时返回外层 SNI。目标候选必须仍属于已完成的 carrier。
 */
#pragma once

#include <expected>
#include <optional>
#include <utility>

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Runtime/Recognition/Candidate.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>

namespace Preview::Runtime::Detail
{
    namespace Core = Preview::Recognition;

    /**
     * @brief 按真实 Native TLS 协商结果解析 SNI 路由目标。
     * @param Profile 已冻结识别 Profile；空值表示没有可用的路由表。
     * @param Carrier BoringSSL 完成握手后拥有的 carrier 元数据。
     * @return 未完成 Native TLS 握手或无路由表时为空值；有效路由返回 owning CandidateHandle。
     * @note 已接受 ECH 时 SNI 是真实 inner 值；路由必须保持同一 TLS carrier。
     */
    [[nodiscard]] inline auto ResolveNegotiatedTlsRoute(
        const Core::Profile* Profile,
        const Core::CarrierMetadata& Carrier)
        -> std::expected<std::optional<Core::CandidateHandle>, Preview::Fault::Failure>
    {
        if (Carrier.EchAccepted && !Carrier.NativeTlsEstablished)
        {
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
        }
        if (!Carrier.NativeTlsEstablished || !Profile || !Profile->HasRoutes() ||
            (Carrier.Sni.empty() && !Carrier.EchAccepted))
        {
            return std::optional<Core::CandidateHandle>{};
        }
        const auto Route = Profile->LookupRoute(Carrier.Sni);
        if (!Route)
        {
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
        }
        auto Candidate = Profile->FindCandidate(*Route);
        if (!Candidate.IsValid() || Candidate.Kind() != Core::CandidateKind::TlsCarrier ||
            Candidate.Scheme() != Carrier.Carrier)
        {
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
        }
        return std::optional<Core::CandidateHandle>{std::move(Candidate)};
    }
}
