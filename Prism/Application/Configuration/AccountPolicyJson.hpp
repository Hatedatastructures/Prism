/** @file AccountPolicyJson.hpp @brief 账户资源策略的严格 JSON 配置边界。 */
#pragma once
#include <Prism/Account/PolicyConfiguration.hpp>
#include <glaze/glaze.hpp>

template <> struct glz::meta<Prism::Account::LimitMode>
{
    using T = Prism::Account::LimitMode;
    static constexpr auto value = glz::enumerate("Inherit", T::Inherit, "Unlimited", T::Unlimited,
        "Finite", T::Finite);
};
template <> struct glz::meta<Prism::Account::CycleKind>
{
    using T = Prism::Account::CycleKind;
    static constexpr auto value = glz::enumerate("Day", T::Day, "Week", T::Week,
        "Month", T::Month, "None", T::None);
};
template <> struct glz::meta<Prism::Account::LimitConfiguration>
{
    using T = Prism::Account::LimitConfiguration;
    static constexpr auto value = glz::object("Mode", &T::Mode, "Value", &T::Value);
};
template <> struct glz::meta<Prism::Account::CycleConfiguration>
{
    using T = Prism::Account::CycleConfiguration;
    static constexpr auto value = glz::object("Kind", &T::Kind, "OffsetMinutes", &T::OffsetMinutes);
};
template <> struct glz::meta<Prism::Account::PolicyConfiguration>
{
    using T = Prism::Account::PolicyConfiguration;
    static constexpr auto value = glz::object("Connections", &T::Connections, "Streams", &T::Streams,
        "TrafficBytes", &T::TrafficBytes, "UploadBytesPerSecond", &T::UploadBytesPerSecond,
        "DownloadBytesPerSecond", &T::DownloadBytesPerSecond,
        "AdmissionsPerSecond", &T::AdmissionsPerSecond, "Cycle", &T::Cycle);
};
