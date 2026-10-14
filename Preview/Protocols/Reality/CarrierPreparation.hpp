/** @file CarrierPreparation.hpp @brief Reality 服务端 carrier secret 的协议内准备。 */
#pragma once

#include <Preview/Protocols/Reality/Detail/Key.hpp>
#include <Preview/Protocols/Reality/Types.hpp>
#include <Preview/Protocols/Reality/Detail/Authentication.hpp>

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Preview::Reality
{
    enum class CarrierPreparationError : std::uint8_t
    {
        MissingPrivateKey,
        InvalidPrivateKey,
        MissingShortIds,
        InvalidShortId
    };

    /** @brief Reality 自己解释私钥编码和 ShortId wire 材料，不接受 Application 配置对象。 */
    struct CarrierPreparationRequest final
    {
        std::string_view PrivateKey;
        std::span<const std::string> ShortIds;
        std::span<const std::string> ServerNames;
    };

    /** @brief 产生唯一协议-owned 静态材料；返回值不包含 socket、executor 或运行期回调。 */
    [[nodiscard]] inline auto PrepareCarrier(CarrierPreparationRequest Request)
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
        for (const auto& Text : Request.ShortIds)
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
