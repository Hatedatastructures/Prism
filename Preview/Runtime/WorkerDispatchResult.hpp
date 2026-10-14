/** @file WorkerDispatchResult.hpp @brief worker 命令交付的唯一公开结果。 */
#pragma once

#include <cstdint>
#include <functional>

namespace Preview::Runtime
{
    /** @brief worker command 的提交结果，不暴露内部 mailbox 类型。
     * @details Accepted 只表示命令已排队；worker 所属执行器会执行仍在队列中的命令，Stop 可释放尚未执行的闭包。
     * 拒绝结果表示命令未入队。提交本身不取消 I/O、不做半关闭；传输和最终关闭仍归闭包所捕获的真实 owner。
     */
    enum class WorkerDispatchResult : std::uint8_t
    {
        Accepted,           ///< 命令已进入队列，执行仍由目标 worker executor 决定。
        Full,               ///< 固定容量队列没有可用槽位。
        Closed,             ///< 队列已关闭，命令未接管。
        WorkerUnavailable,  ///< worker 已停止接收或不存在。
        GenerationRejected, ///< 命令代次未被该 worker 的 publication 接受。
    };

    /** @brief 被 worker 调度的拥有型命令闭包；拒绝时不执行，执行期异常由 worker 记录并隔离。 */
    using WorkerDispatchCommand = std::function<void()>;
}
