/** @file WorkerTestSupport.hpp @brief Runtime worker 生命周期测试的内部 owner 观察。 */
#pragma once

#include <Preview/Runtime/Worker.hpp>

namespace Preview::Runtime
{
    /** @brief 仅供同模块多个测试 CPP 观察 worker 私有 mailbox 生命周期。 */
    class WorkerTestAccess final
    {
    public:
        static auto CloseMailbox(Worker &Value) noexcept -> void
        {
            Value.Mailbox_.Close();
        }

        [[nodiscard]] static auto IsMailboxClosed(const Worker &Value) noexcept -> bool
        {
            return Value.Mailbox_.IsClosed();
        }
    };
}
