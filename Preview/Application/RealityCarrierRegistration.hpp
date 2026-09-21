/**
 * @file RealityCarrierRegistration.hpp
 * @brief 将配置中的 Reality carrier 转换为 Preview prepared 接入回调。
 */

#pragma once

#include <Preview/Application/Application.hpp>
#include <Preview/Application/Configuration/ConfigurationGeneration.hpp>
#include <Preview/Application/Configuration/PreviewConfiguration.hpp>
#include <Preview/Composition/Recognition/CandidateRegistry.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Protocols/Reality/Codec.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Preview::Application::RealityCarrier
{

    namespace Configuration = Preview::Application::Configuration;
    namespace Recognition = Preview::Composition::Recognition;

    [[nodiscard]] inline auto MakeError(
        const StartupErrorCode Code,
        const std::string &CarrierId,
        const std::string_view Suffix) -> StartupError
    {
        return StartupError{
            Code,
            "Carriers." + CarrierId,
            "Reality carrier " + std::string(Suffix)};
    }

    [[nodiscard]] inline auto Register(
        Recognition::CandidateRegistry &Registry,
        const Configuration::CarrierConfiguration &Carrier,
        const Configuration::ConfigurationGeneration &Generation)
        -> std::expected<void, StartupError>
    {
        const auto *Options = std::get_if<Configuration::RealityOptions>(&Carrier.Options);
        if (Options == nullptr)
        {
            return std::unexpected(MakeError(
                StartupErrorCode::UnsupportedService, Carrier.Id, "has no typed options"));
        }

        const auto Secret = Generation.LookupSecret(Options->PrivateKeyRef);
        const auto EncodedPrivateKey = std::string_view(
            reinterpret_cast<const char *>(Secret.data()), Secret.size());
        std::array<std::uint8_t, Preview::Reality::KeyLen> PrivateKey{};
        if (Secret.empty() || Preview::Reality::ParsePrivateKey(EncodedPrivateKey, PrivateKey))
        {
            return std::unexpected(MakeError(
                StartupErrorCode::Generation, Carrier.Id, "private key secret is invalid"));
        }

        std::vector<std::array<std::uint8_t, Preview::Reality::MaxShortIdLen>> ShortIds;
        ShortIds.reserve(Options->ShortIds.size());
        for (const auto &EncodedShortId : Options->ShortIds)
        {
            std::array<std::uint8_t, Preview::Reality::MaxShortIdLen> ShortId{};
            if (Preview::Reality::ParseShortId(EncodedShortId, ShortId))
            {
                return std::unexpected(MakeError(
                    StartupErrorCode::InvalidConfiguration, Carrier.Id, "ShortId is invalid"));
            }
            ShortIds.push_back(ShortId);
        }

        if (!Registry.RegisterPreparedCarrier(
                Carrier.Id, "reality",
                Recognition::MakeRealityServerAccept(PrivateKey, std::move(ShortIds))))
        {
            return std::unexpected(MakeError(
                StartupErrorCode::Runtime, Carrier.Id, "prepared registration failed"));
        }
        return {};
    }

} // namespace Preview::Application::RealityCarrier
