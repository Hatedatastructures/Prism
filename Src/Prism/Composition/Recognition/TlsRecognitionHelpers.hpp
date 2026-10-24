/**
 * @file TlsRecognitionHelpers.hpp
 * @brief TLS ClientHello 解析、prepare 与 carrier commit 辅助函数。
 * @details policy 与 binding Inspect 由 TlsCandidateModel 拥有；本头只处理
 *          probe 解析、prepared state 和 commit 阶段，并保留原始 inbound
 *          以便错误合同向 Runtime 传递。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <string>
#include <string_view>
#include <system_error>

#include <Prism/Composition/Recognition/TlsCandidateModel.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    namespace detail
    {

        [[nodiscard]] auto SchemeName(TlsCarrier Carrier) noexcept -> std::string_view;

        [[nodiscard]] auto ParseFeatures(const Core::ProbeSnapshot &Snapshot,
            Core::ClientHelloFeatures &Features) -> Core::MatchState;

        [[nodiscard]] auto PrepareClientHello(Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>;

        /**
         * @brief TLS commit 的 owning request。
         * @details CommitScheme 按值接收整个 request；typed callback、prepared state
         *          和原始 Inbound 因而都由 coroutine frame 保持。这里不借用
         *          SchemeExecutor、registry 或外层 configuration；取消、half-close
         *          与最终关闭由 carrier callback 的协议 owner 承担。
         */
        struct CommitSchemeRequest
        {
            Core::CommitContext Context;
            CarrierAcceptFn Accept;
            CarrierAcceptPreparedFn AcceptPrepared;
            std::string Scheme;
        };

        [[nodiscard]] auto MetadataFor(const CommitSchemeRequest &RequestData)
            -> Core::CarrierMetadata;

        [[nodiscard]] auto ExecuteCarrier(CommitSchemeRequest &RequestData,
            Prism::SharedTransmission Inbound) -> Net::awaitable<Core::CarrierAcceptResult>;

        [[nodiscard]] auto CarrierRecognitionStatus(Prism::Fault::Code Code) noexcept
            -> Core::RecognitionStatus;

        [[nodiscard]] auto CarrierRecognitionError(Prism::Fault::Code Code) noexcept
            -> std::error_code;

        [[nodiscard]] auto CommitScheme(CommitSchemeRequest RequestData)
            -> Net::awaitable<Core::CommitResult>;

    } // namespace detail

} // namespace Prism::Composition::Recognition
