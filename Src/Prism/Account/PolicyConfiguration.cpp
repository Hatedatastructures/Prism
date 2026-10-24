/** @file PolicyConfiguration.cpp
 * @brief 账户策略字段校验与继承编译实现。
 */
#include <Prism/Account/PolicyConfiguration.hpp>

#include <cstdint>
#include <expected>
#include <limits>
#include <optional>

namespace Prism::Account
{
    auto ResolveLimit(const LimitConfiguration& Account,
        const LimitConfiguration& Group) noexcept -> std::optional<std::uint64_t>
    {
        const auto& Selected = Account.Mode == LimitMode::Inherit ? Group : Account;
        if (Selected.Mode == LimitMode::Finite) return Selected.Value;
        return std::nullopt;
    }

    auto ValidatePolicyConfiguration(const PolicyConfiguration& Value) noexcept
        -> std::expected<void, Fault::Failure>
    {
        const LimitConfiguration* Limits[]{&Value.Connections, &Value.Streams, &Value.TrafficBytes,
            &Value.UploadBytesPerSecond, &Value.DownloadBytesPerSecond, &Value.AdmissionsPerSecond};
        for (const auto* Limit : Limits)
            if (Limit->Mode > LimitMode::Finite ||
                (Limit->Mode != LimitMode::Finite && Limit->Value != 0U))
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        const auto MaxCount = static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max());
        if (Value.Connections.Value > MaxCount || Value.Streams.Value > MaxCount)
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        if (Value.Cycle && (Value.Cycle->Kind > CycleKind::None ||
            Value.Cycle->OffsetMinutes < -840 || Value.Cycle->OffsetMinutes > 840))
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        return {};
    }

    auto CompilePolicy(const PolicyConfiguration& Account,
        const PolicyConfiguration& Group) -> std::expected<EffectivePolicy, Fault::Failure>
    {
        const auto AccountValid = ValidatePolicyConfiguration(Account);
        if (!AccountValid) return std::unexpected(AccountValid.error());
        const auto GroupValid = ValidatePolicyConfiguration(Group);
        if (!GroupValid) return std::unexpected(GroupValid.error());
        EffectivePolicy Result;
        if (const auto Value = ResolveLimit(Account.Connections, Group.Connections))
            Result.Connections = static_cast<std::uint32_t>(*Value);
        if (const auto Value = ResolveLimit(Account.Streams, Group.Streams))
            Result.Streams = static_cast<std::uint32_t>(*Value);
        Result.TrafficBytes = ResolveLimit(Account.TrafficBytes, Group.TrafficBytes);
        Result.UploadBytesPerSecond = ResolveLimit(Account.UploadBytesPerSecond, Group.UploadBytesPerSecond);
        Result.DownloadBytesPerSecond = ResolveLimit(Account.DownloadBytesPerSecond, Group.DownloadBytesPerSecond);
        Result.AdmissionsPerSecond = ResolveLimit(Account.AdmissionsPerSecond, Group.AdmissionsPerSecond);
        Result.Cycle = Account.Cycle.value_or(Group.Cycle.value_or(CycleConfiguration{}));
        return Result;
    }
}
