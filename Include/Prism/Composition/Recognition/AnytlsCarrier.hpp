/**
 * @file AnytlsCarrier.hpp
 * @brief Native TLS 外层到 AnyTLS 内层候选的 Composition 接入。
 * @details Native TLS 只负责 carrier commit；TLS 解密后的传输所有权继续交给
 *          现有 AnyTLS winner-only handler，避免把 AnyTLS 误当成通用 TLS carrier。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/NativeTls.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    struct NativeTlsCarrier final
    {
        std::shared_ptr<Net::ssl::context> Context;
        std::chrono::steady_clock::duration Timeout;

        struct Request final
        {
            Prism::SharedTransmission Inbound;
            std::shared_ptr<Net::ssl::context> Context;
            std::chrono::steady_clock::duration Timeout;
            std::shared_ptr<Prism::Memory::BytePool> Bytes;
        };

        [[nodiscard]] static auto Run(Request Value) -> Net::awaitable<Core::CarrierAcceptResult>;

        [[nodiscard]] auto operator()(Core::CarrierAcceptInput Input) const
            -> Net::awaitable<Core::CarrierAcceptResult>;
    };

    /**
     * @struct AnytlsCarrierOptions
     * @brief Native TLS 外层与 AnyTLS 内层候选的稳定构造参数。
     */
    struct AnytlsCarrierOptions final
    {
        CandidateOptions Candidate;
        std::vector<std::string> ServerNames;
        std::vector<std::string> Alpn;
        std::shared_ptr<Net::ssl::context> NativeTls;
        Prism::Anytls::IngressOptions Config;
        std::chrono::steady_clock::duration Timeout{
            Prism::Transport::Encrypted::DefaultHandshakeTimeout};
    };

    /**
     * @brief 创建 Native TLS 服务端 carrier 接入回调。
     * @param Context 服务端 TLS 上下文，由长期存活的 Composition owner 持有。
     * @param Timeout 本次 Native TLS 握手预算。
     * @return 可由 TLS candidate 在 commit 阶段调用的 carrier 回调。
     * @details 成功结果只携带解密后的传输；非 TLS 输入不会被静默报告为
     *          Native TLS 成功，避免绕过外层候选的 TLS 语义。
     */
    [[nodiscard]] auto MakeNativeTlsCarrier(
        std::shared_ptr<Net::ssl::context> Context,
        const std::chrono::steady_clock::duration Timeout =
            Prism::Transport::Encrypted::DefaultHandshakeTimeout) -> CarrierAcceptFn;

    /**
     * @brief 构造 Native TLS + AnyTLS 的分层候选。
     * @param Options 外层 TLS、内层 AnyTLS 以及候选元数据。
     * @return 外层 commit 完成后由 resolver 调用 AnyTLS handler 的候选。
     */
    [[nodiscard]] auto MakeNativeTlsAnytlsCandidate(AnytlsCarrierOptions Options)
        -> CandidateBinding;

} // namespace Prism::Composition::Recognition
