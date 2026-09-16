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
#include <utility>
#include <vector>

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Preview/Transport/NativeTls.hpp>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

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
        Preview::Anytls::ServerConfig Config;
        std::chrono::steady_clock::duration Timeout{
            Preview::Transport::Encrypted::DefaultHandshakeTimeout};
    };

    /**
     * @brief 创建 Native TLS 服务端 carrier 接入回调。
     * @param Context 服务端 TLS 上下文，由长期存活的 Composition owner 持有。
     * @param Timeout 本次 Native TLS 握手预算。
     * @return 可由 TLS candidate 在 commit 阶段调用的 carrier 回调。
     * @details 成功结果只携带解密后的传输；非 TLS 输入不会被静默报告为
     *          Native TLS 成功，避免绕过外层候选的 TLS 语义。
     */
    [[nodiscard]] inline auto MakeNativeTlsCarrier(
        std::shared_ptr<Net::ssl::context> Context,
        const std::chrono::steady_clock::duration Timeout =
            Preview::Transport::Encrypted::DefaultHandshakeTimeout) -> CarrierAcceptFn
    {
        return [Context = std::move(Context), Timeout](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = "native";
            if (!Context)
            {
                Result.Code = Preview::Fault::Code::NotSupported;
                Result.Transport = std::move(Inbound);
                co_return Result;
            }

            const auto TlsResult = co_await Preview::Transport::UpgradeNativeTls(
                Preview::Transport::NativeTlsRequest{std::move(Inbound), Context, Timeout});
            Result.Code = TlsResult.Code;
            Result.Transport = std::move(TlsResult.Transport);
            Result.NativeError = TlsResult.NativeError;
            if (Result.Code == Preview::Fault::Code::Success && !TlsResult.Attempted)
            {
                Result.Code = Preview::Fault::Code::TlsHsfail;
            }
            co_return Result;
        };
    }

    /**
     * @brief 构造 Native TLS + AnyTLS 的分层候选。
     * @param Options 外层 TLS、内层 AnyTLS 以及候选元数据。
     * @return 外层 commit 完成后由 resolver 调用 AnyTLS handler 的候选。
     */
    [[nodiscard]] inline auto MakeNativeTlsAnytlsCandidate(AnytlsCarrierOptions Options)
        -> CandidateBinding
    {
        TlsCandidateOptions Outer;
        Outer.Id = Options.Candidate.Id;
        Outer.Name = Options.Candidate.Name;
        Outer.Scheme = "native";
        Outer.ServerNames = std::move(Options.ServerNames);
        Outer.Alpn = std::move(Options.Alpn);
        Outer.Fallback = Options.Candidate.Fallback;
        Outer.Carrier = TlsCarrier::Native;

        auto Inner = CandidateFactory::MakeAnytls(
            std::move(Options.Candidate), std::move(Options.Config));
        auto Result = LayeredCandidateFactory::Make(
            std::move(Outer),
            MakeNativeTlsCarrier(std::move(Options.NativeTls), Options.Timeout),
            std::move(Inner));
        Result.Spec.RequiresAuthentication = true;
        return Result;
    }

} // namespace Preview::Composition::Recognition
