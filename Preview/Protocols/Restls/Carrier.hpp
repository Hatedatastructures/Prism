/**
 * @file Carrier.hpp
 * @brief Restls 的 Preview carrier 边界。
 * @details 配置完成的 carrier 负责首个加密帧保护、Restls Conn 构造和
 *          raw transport 的所有权交接；无配置入口仍然显式拒绝。
 */
#pragma once

#include <Preview/Composition/Carrier/FacadeCarrier.hpp>
#include <Preview/Protocols/Restls/Codec.hpp>
#include <Preview/Protocols/Restls/Conn.hpp>
#include <Preview/Protocols/Restls/Types.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Restls
{

    namespace Net = boost::asio;
    namespace Carrier = Preview::Composition::Carrier;

    inline constexpr std::string_view WireBlocker =
        "Restls carrier requires an explicit completed handover";

    /**
     * @struct CarrierOptions
     * @brief Restls carrier 的认证与 wire handover 配置
     */
    struct CarrierOptions final
    {
        std::string Password;
        Restls::Handover Handover;
    };

    namespace Detail
    {

        [[nodiscard]] inline auto WriteAll(
            const Preview::SharedTransmission &Transport,
            std::span<const std::uint8_t> Data,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto Written = co_await Transport->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Data.data() + Offset),
                        Data.size() - Offset),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return false;
                }
                if (Written == 0 || Written > Data.size() - Offset)
                {
                    ErrorCode = std::make_error_code(std::errc::io_error);
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

    } // namespace Detail

    [[nodiscard]] inline auto MakeFacadeCarrier()
        -> Preview::Composition::Carrier::FacadeCarrier
    {
        return Preview::Composition::Carrier::FacadeCarrier::Unavailable(
            Preview::Composition::Carrier::CarrierKind::Restls, std::string(WireBlocker));
    }

    /**
     * @brief 创建配置完成的 Restls carrier
     * @param Options 已完成的 Restls 握手 handover
     * @return 可执行真实 wire 接管的 carrier facade
     * @details 首先向客户端写出经 ServerMask 保护的首个加密记录，
     * 随后将同一 raw transport 交给 Conn，保留 Facade 的 replay 和 owner 语义。
     */
    [[nodiscard]] inline auto MakeFacadeCarrier(CarrierOptions Options)
        -> Carrier::FacadeCarrier
    {
        auto SharedOptions = std::make_shared<CarrierOptions>(std::move(Options));
        return Carrier::FacadeCarrier::Ready(
            Carrier::CarrierKind::Restls,
            [SharedOptions](Carrier::CarrierAcceptRequest Request)
                -> Net::awaitable<Carrier::CarrierAcceptResult>
            {
                auto Original = Request.Transport;
                auto Replay = Request.Replay;
                auto State = Request.State;
                if (!Original)
                {
                    co_return Carrier::CarrierAcceptResult::Rejected(
                        Carrier::MapError(Preview::Error::NotOpen,
                                          Carrier::HandshakeStage::Preparing,
                                          "Restls carrier received no transport"),
                        {}, std::move(Replay), std::move(State));
                }
                if (SharedOptions->Password.empty() ||
                    SharedOptions->Handover.ClientFinished.empty() ||
                    SharedOptions->Handover.FirstEncrypted.empty())
                {
                    co_return Carrier::CarrierAcceptResult::Rejected(
                        Carrier::MapError(Preview::Error::BadLength,
                                          Carrier::HandshakeStage::Preparing,
                                          "Restls handover is incomplete"),
                        std::move(Original), std::move(Replay), std::move(State));
                }

                auto Connection = std::make_shared<Conn<>>(Original, SharedOptions->Password);
                const auto HandshakeError = co_await Connection->ReadHandshake(
                    SharedOptions->Handover.ServerRandom,
                    SharedOptions->Handover.ClientFinished);
                if (HandshakeError != Preview::Error::None)
                {
                    co_return Carrier::CarrierAcceptResult::Rejected(
                        Carrier::MapError(HandshakeError,
                                          Carrier::HandshakeStage::Preparing,
                                          "Restls handover initialization failed"),
                        std::move(Original), std::move(Replay), std::move(State));
                }

                const auto Secret = Connection->Secret();
                const auto [ProtectError, ProtectedFirst] = ProtectFirstEncrypted(
                    SharedOptions->Handover.FirstEncrypted,
                    Secret,
                    SharedOptions->Handover.ServerRandom);
                if (ProtectError != Preview::Error::None)
                {
                    co_return Carrier::CarrierAcceptResult::Rejected(
                        Carrier::MapError(ProtectError,
                                          Carrier::HandshakeStage::Committing,
                                          "Restls first encrypted frame is invalid"),
                        std::move(Original), std::move(Replay), std::move(State));
                }

                std::error_code WriteError;
                if (!co_await Detail::WriteAll(Original, ProtectedFirst, WriteError))
                {
                    co_return Carrier::CarrierAcceptResult::Rejected(
                        Carrier::MapError(WriteError,
                                          Carrier::HandshakeStage::Committing,
                                          "Restls first encrypted frame write failed"),
                        std::move(Original), std::move(Replay), std::move(State));
                }

                auto Metadata = Carrier::CarrierMetadata{
                    .Kind = Carrier::CarrierKind::Restls,
                    .WireComplete = true,
                    .ReplayBytes = Replay.Size(),
                    .Detail = "Restls first encrypted frame and transport handoff completed"};
                co_return Carrier::CarrierAcceptResult::Accepted(
                    std::move(Connection), std::move(Replay), std::move(Metadata), std::move(State));
            });
    }

} // namespace Preview::Restls
