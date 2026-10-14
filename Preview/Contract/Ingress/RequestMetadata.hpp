/** @file RequestMetadata.hpp @brief 接入与正式根运行共用的唯一请求观察快照。 */
#pragma once
#include <Preview/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Preview/Lifecycle/TaskState.hpp>
#include <string>

namespace Preview::Contract
{
    /** @brief 立即按值拥有身份、来源和 trace；无服务查找、认证事实或 Runtime 引用。 */
    struct RequestMetadata final
    {
        Preview::Lifecycle::TaskIdentity TaskIdentity{};
        std::string SourceIp;
        Preview::Diagnose::ContextState Trace{Preview::Diagnose::ContextState::Empty()};
    };
}
