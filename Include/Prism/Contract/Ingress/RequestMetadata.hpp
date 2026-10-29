/** @file RequestMetadata.hpp @brief 接入与正式根运行共用的唯一请求观察快照。 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Lifecycle/Task/State.hpp>
#include <string>

namespace Prism::Contract
{
    /** @brief 立即按值拥有身份、来源和 trace；无服务查找、认证事实或 Runtime 引用。 */
    struct RequestMetadata final
    {
        Prism::Lifecycle::TaskIdentity TaskIdentity{};
        std::string SourceIp;
        Prism::Diagnose::ContextState Trace{Prism::Diagnose::ContextState::Empty()};
    };
}
