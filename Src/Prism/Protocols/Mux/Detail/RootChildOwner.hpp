/** @file RootChildOwner.hpp @brief Mux 子流重置 owner 的模块内构造入口。 */
#pragma once

#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/TaskState.hpp>

#include <memory>

namespace Prism::Mux::Detail
{
    /** @brief 创建保有任务句柄、控制失败和子流作用域的真实重置 owner。 */
    [[nodiscard]] auto CreateStreamResetTaskOwner(
        Prism::Lifecycle::TaskHandle Task,
        std::shared_ptr<Prism::Fault::FailureState> ControlFailure,
        Prism::Contract::Ingress::StreamResetRequest Scope)
        -> std::shared_ptr<Prism::Contract::Ingress::StreamResetOwner>;
}
