/**
 * @file RealityPreparation.cpp
 * @brief Reality 公钥与 ShortId 材料准备实现。
 */
#include <Prism/Protocols/Reality/CarrierPreparation.hpp>

#include <Prism/Protocols/Reality/Detail/KeyMaterial.hpp>
#include <Prism/Protocols/Reality/Detail/SessionId.hpp>

namespace Prism::Reality
{
    auto PrepareCarrier(CarrierPreparationRequest Request)
        -> std::expected<PreparedConfig, CarrierPreparationError>
    {
        if (Request.PrivateKey.empty())
        {
            return std::unexpected(CarrierPreparationError::MissingPrivateKey);
        }
        PreparedConfig Result;
        if (Detail::ParsePrivateKey(Request.PrivateKey, Result.PrivateKey))
        {
            return std::unexpected(CarrierPreparationError::InvalidPrivateKey);
        }
        if (Request.ShortIds.empty())
        {
            return std::unexpected(CarrierPreparationError::MissingShortIds);
        }
        Result.ShortIds.reserve(Request.ShortIds.size());
        for (const auto &Text : Request.ShortIds)
        {
            std::array<std::uint8_t, MaxShortIdLen> Value{};
            if (Detail::ParseShortId(Text, Value))
            {
                return std::unexpected(CarrierPreparationError::InvalidShortId);
            }
            Result.ShortIds.push_back(Value);
        }
        Result.ServerNames.assign(Request.ServerNames.begin(), Request.ServerNames.end());
        return Result;
    }
}
