/** @file BackendBridge.hpp
 * @brief facade 请求到唯一有界快照队列的窄边界。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp>

#include <utility>
namespace Prism::Diagnose::Detail
{
    class BackendBridge final
    {
    public:
        /** @brief 过滤后同步捕获输入；不格式化、不分配、不执行 sink fallback。 */
        [[nodiscard]] static auto Submit(const SubmissionRequest& Request, AsyncBackendState* State) noexcept
            -> SubmissionReceipt;
    };
}
