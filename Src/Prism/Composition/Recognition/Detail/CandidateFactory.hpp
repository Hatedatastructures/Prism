/**
 * @file CandidateFactory.hpp
 * @brief cleartext/opaque 候选的 probe、认证准备和 replay 提交辅助函数。
 * @details 所有函数只操作 ProbeSnapshot 或按值捕获的配置。CommitReplay
 *          只在 winner 确认后转移 inbound，避免失败试探污染连接状态。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <Prism/Composition/Recognition/CandidateModel.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    namespace detail
    {

        [[nodiscard]] auto SnapshotBytes(const Core::ProbeSnapshot &Snapshot)
            -> std::span<const std::uint8_t>;

        [[nodiscard]] auto SnapshotText(const Core::ProbeSnapshot &Snapshot) -> std::string_view;

        [[nodiscard]] auto IsNeedMore(std::error_code Error) noexcept -> bool;

        [[nodiscard]] auto Accepted(Core::CandidateId Id) -> Core::PrepareResult;

        [[nodiscard]] auto NoMatch(Core::CandidateId Id) -> Core::PrepareResult;

        [[nodiscard]] auto NeedMore(Core::CandidateId Id) -> Core::PrepareResult;

        [[nodiscard]] auto CommitReplay(Core::CommitContext Context)
            -> Net::awaitable<Core::CommitResult>;

        [[nodiscard]] auto InspectHttp(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState;

        [[nodiscard]] auto InspectSocks5(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState;

        [[nodiscard]] auto InspectVless(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState;

        [[nodiscard]] auto InspectTrojan(const Core::ProbeSnapshot &Snapshot) -> Core::MatchState;

        [[nodiscard]] auto InspectOpaqueLength(const Core::ProbeSnapshot &Snapshot,
            std::size_t MinimumBytes) -> Core::MatchState;

        struct VlessPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, Prism::Vless::UuidLen> Uuid{};
            Prism::SharedAuthenticator AuthenticatorOwner{};
            Core::ProbeSnapshot Snapshot{};
            bool UdpEnabled{true};
        };

        struct TrojanPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::string Password;
            bool EnableTcp{true};
            bool EnableUdp{false};
            Prism::SharedAuthenticator AuthenticatorOwner{};
            Core::ProbeSnapshot Snapshot{};
        };

        struct Ss2022PrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, 16> Psk{};
            std::uint64_t TimeWindow{90};
            Core::ProbeSnapshot Snapshot{};
        };

        struct AnytlsPrepareRequest
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::string Password;
            Core::ProbeSnapshot Snapshot{};
        };

        [[nodiscard]] auto PrepareVless(VlessPrepareRequest RequestData) -> Core::PrepareResult;

        [[nodiscard]] auto PrepareTrojan(TrojanPrepareRequest RequestData) -> Core::PrepareResult;

        struct VmessRequestInspection final
        {
            Core::MatchState State{Core::MatchState::Rejected};
            std::optional<Prism::Vmess::Command> Command;
        };

        [[nodiscard]] auto InspectVmessUuid(
            const std::array<std::uint8_t, 16> &Uuid,
            const Core::ProbeSnapshot &Snapshot) -> VmessRequestInspection;

        struct VmessPrepareRequest final
        {
            Core::CandidateId Id{Core::InvalidCandidate};
            std::array<std::uint8_t, 16> Uuid{};
            Prism::Account::CredentialIndexView Credentials;
            Core::ProbeSnapshot Snapshot{};
            bool UdpEnabled{true};
        };

        auto UpdateVmessTrial(
            VmessRequestInspection &State,
            const VmessRequestInspection &Trial) -> void;

        /** @brief 同步借用本次 probe 状态和快照；ForEachCredential 返回后不保存任何材料引用。 */
        struct VmessCredentialTrial final
        {
            VmessRequestInspection &State;
            const Core::ProbeSnapshot &Snapshot;

            auto operator()(const std::shared_ptr<const Prism::Account::AccountBinding> &,
                const Prism::Account::CredentialMaterial &Material) const -> void;
        };

        [[nodiscard]] auto PrepareVmess(VmessPrepareRequest RequestData)
            -> Core::PrepareResult;

        [[nodiscard]] auto PrepareSs2022(Ss2022PrepareRequest RequestData) -> Core::PrepareResult;

        [[nodiscard]] auto InspectAnytls(const Core::ProbeSnapshot &Snapshot,
            std::string_view Password) -> Core::MatchState;

        [[nodiscard]] auto PrepareAnytls(AnytlsPrepareRequest RequestData) -> Core::PrepareResult;

        [[nodiscard]] auto CommitFor() -> Core::CommitFn;

        [[nodiscard]] auto NormalizeOptions(CandidateOptions Options, std::string_view Name)
            -> CandidateOptions;

        [[nodiscard]] auto BaseSpec(CandidateOptions Options, std::string_view Name,
            Prism::Contract::ProtocolType Protocol) -> Core::CandidateSpec;

    } // namespace detail

} // namespace Prism::Composition::Recognition
