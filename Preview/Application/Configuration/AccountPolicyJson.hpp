/** @file AccountPolicyJson.hpp @brief 账户资源策略的严格 JSON 配置边界。 */
#pragma once
#include <Preview/Account/PolicyConfiguration.hpp>
#include <glaze/glaze.hpp>

template <> struct glz::meta<Preview::Account::LimitMode>
{
    using T = Preview::Account::LimitMode;
    static constexpr auto value = glz::enumerate("Inherit", T::Inherit, "Unlimited", T::Unlimited,
        "Finite", T::Finite);
};
template <> struct glz::meta<Preview::Account::CycleKind>
{
    using T = Preview::Account::CycleKind;
    static constexpr auto value = glz::enumerate("Day", T::Day, "Week", T::Week,
        "Month", T::Month, "None", T::None);
};
template <> struct glz::meta<Preview::Account::LimitConfiguration>
{
    using T = Preview::Account::LimitConfiguration;
    static constexpr auto value = glz::object("Mode", &T::Mode, "Value", &T::Value);
};
template <> struct glz::meta<Preview::Account::CycleConfiguration>
{
    using T = Preview::Account::CycleConfiguration;
    static constexpr auto value = glz::object("Kind", &T::Kind, "OffsetMinutes", &T::OffsetMinutes);
};
template <> struct glz::meta<Preview::Account::PolicyConfiguration>
{
    using T = Preview::Account::PolicyConfiguration;
    static constexpr auto value = glz::object("Connections", &T::Connections, "Streams", &T::Streams,
        "TrafficBytes", &T::TrafficBytes, "UploadBytesPerSecond", &T::UploadBytesPerSecond,
        "DownloadBytesPerSecond", &T::DownloadBytesPerSecond,
        "AdmissionsPerSecond", &T::AdmissionsPerSecond, "Cycle", &T::Cycle);
};
