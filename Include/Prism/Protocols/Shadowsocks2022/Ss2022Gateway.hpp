/** @file Ss2022Gateway.hpp @brief SS2022 raw UDP peer、账户租约、在途 I/O 及真实 drain owner。 */
#pragma once
#include <Prism/Contract/Ingress/RawDatagramIngress.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Protocols/Shadowsocks2022/GatewayState.hpp>
#include <Prism/Protocols/Shadowsocks2022/Prepared.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace Prism::Shadowsocks2022
{
    [[nodiscard]] auto MakeTrafficObservation(
        const std::shared_ptr<Prism::Foundation::TrafficSink>& Traffic, Prism::GenerationId Generation,
        Prism::AccountId Account) -> Prism::Foundation::TrafficObservation;

    class Ss2022Gateway final : public Prism::Contract::RawDatagramIngress,
                                public std::enable_shared_from_this<Ss2022Gateway>
    {
    public:
        /** @brief 接管同一 prepared credential 和服务；协议不拥有公共 socket。 */
        explicit Ss2022Gateway(std::shared_ptr<const Prepared> Value);
        ~Ss2022Gateway() override;
        /** @brief 严格借用密文，仅验证实际 wire，不保存输入或申请 quota/rate 租约。 */
        [[nodiscard]] auto Matches(Prism::Contract::DatagramView Packet) const -> bool override;

        /** @brief 只匹配已持有同一 peer/session/account/代次租约的 raw 关联。 */
        [[nodiscard]] auto MatchesExistingAssociation(
            Prism::Contract::DatagramView Packet) const -> bool override;
        /** @brief 接管包并在本 strand 注册在途任务；close 后直接拒绝，bad auth/replay 不触发 egress。 */
        auto Consume(Prism::Contract::DatagramPacket Packet) -> void override;
        /** @brief 任意线程封止，取消全部在途 DNS/egress/sender，最终清 peer 和账户租约。 */
        auto Close() noexcept -> void override;
        /** @brief 暴露 GatewayState 的 closed+barrier 物理退休事实，不读取公开 Drain 错误。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

        /** @brief 从 PeerRoute 原子快照读取仍持 account 与 generation lease 的关联。 */
        [[nodiscard]] auto HasActiveAssociations() const noexcept -> bool override;
        /** @brief 在协议 strand 等待取消后的实际 coroutine completion；无 half-close。 */
        auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override;

    private:
        struct Parsed final
        {
            Prism::Protocols::ScopedMaterial Credential;
            Address Target;
            std::vector<std::uint8_t> Payload;
            boost::asio::ip::udp::endpoint Peer;
            std::array<std::uint8_t, SessionIdLen> Session{};
            std::uint64_t PacketId{0};
        };
        using PeerState = GatewayState::PeerState;
        using Operation = GatewayState::Operation;
        [[nodiscard]] auto Parse(std::span<const std::byte> Payload) const -> std::optional<Parsed>;
        [[nodiscard]] static auto PeerKey(const Prism::Contract::DatagramPacket& Packet) -> std::string;
        [[nodiscard]] static auto AcceptId(PeerState& Peer, std::uint64_t Id) -> bool;
        [[nodiscard]] auto Admit(const std::string& Name, const Parsed& Packet,
            Prism::Foundation::GenerationUseLease &GenerationUse) -> bool;
        auto Start(GatewayState::PacketAdmission Admission) -> void;
        auto Process(std::shared_ptr<Operation> Work) -> Net::awaitable<void>;
        [[nodiscard]] auto Reap() -> bool;
        static auto DrainOnStrand(std::shared_ptr<Ss2022Gateway> Self)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        std::shared_ptr<GatewayState> State_;
    };
} // namespace Prism::Shadowsocks2022
