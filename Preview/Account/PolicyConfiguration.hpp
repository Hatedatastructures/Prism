/** @file PolicyConfiguration.hpp
 * @brief 账户和用户组共用的逐项继承配置与唯一有效策略编译。
 */
#pragma once
#include <Preview/Account/Failure.hpp>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <string>

namespace Preview::Account
{
    /** @brief Inherit 取组默认，Unlimited 显式不限，Finite 的零值仍是有效限制。 */
    enum class LimitMode : std::uint8_t { Inherit, Unlimited, Finite };
    enum class CycleKind : std::uint8_t { Day, Week, Month, None };

    struct LimitConfiguration final
    {
        LimitMode Mode{LimitMode::Inherit};
        std::uint64_t Value{0};
    };

    struct CycleConfiguration final
    {
        CycleKind Kind{CycleKind::Month};
        std::int32_t OffsetMinutes{480};
        friend auto operator==(const CycleConfiguration&, const CycleConfiguration&) -> bool = default;
    };

    /** @brief 每项只有一个正式配置；周期未指定继承组，否则采用自然月 UTC+08:00。 */
    struct PolicyConfiguration final
    {
        LimitConfiguration Connections;
        LimitConfiguration Streams;
        LimitConfiguration TrafficBytes;
        LimitConfiguration UploadBytesPerSecond;
        LimitConfiguration DownloadBytesPerSecond;
        LimitConfiguration AdmissionsPerSecond;
        std::optional<CycleConfiguration> Cycle;
    };

    /** @brief 已解析的生效策略；nullopt 表示不限，不用零值承担第二种意义。 */
    struct EffectivePolicy final
    {
        std::optional<std::uint32_t> Connections;
        std::optional<std::uint32_t> Streams;
        std::optional<std::uint64_t> TrafficBytes;
        std::optional<std::uint64_t> UploadBytesPerSecond;
        std::optional<std::uint64_t> DownloadBytesPerSecond;
        std::optional<std::uint64_t> AdmissionsPerSecond;
        CycleConfiguration Cycle;
    };

    /** @brief 数据面流量与带宽策略；并发仍仅由 QuotaPolicy 持有，准入仅由 RatePolicy 持有。 */
    struct TransferPolicy final
    {
        std::optional<std::uint64_t> TrafficBytes;
        std::optional<std::uint64_t> UploadBytesPerSecond;
        std::optional<std::uint64_t> DownloadBytesPerSecond;
        CycleConfiguration Cycle;
    };

    [[nodiscard]] inline auto ResolveLimit(const LimitConfiguration& Account,
        const LimitConfiguration& Group) noexcept -> std::optional<std::uint64_t>
    {
        const auto& Selected = Account.Mode == LimitMode::Inherit ? Group : Account;
        if (Selected.Mode == LimitMode::Finite) return Selected.Value;
        return std::nullopt;
    }

    /** @brief 冷路径严格校验所有字段，包括被账户覆盖的组配置也应独立校验。 */
    [[nodiscard]] inline auto ValidatePolicyConfiguration(const PolicyConfiguration& Value) noexcept
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

    [[nodiscard]] inline auto CompilePolicy(const PolicyConfiguration& Account,
        const PolicyConfiguration& Group = {}) -> std::expected<EffectivePolicy, Fault::Failure>
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
