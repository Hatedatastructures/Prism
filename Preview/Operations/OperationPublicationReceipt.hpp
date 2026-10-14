/** @file OperationPublicationReceipt.hpp @brief 操作终态已提交后的独立通知回执。 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>

namespace Preview::Operations
{
    /**
     * @brief 本回执只在 Router 已存储唯一终态后返回。
     * @details WaiterSignalFailure 保存唤醒其它操作等待者时的原始失败；它不撤销已提交终态。
     *          调用者据此记录观察失败，仍可发布对应终态事件，禁止重新执行业务或重复提交。
     *          回执按值复制，不拥有业务、HTTP 或 executor；取消、半关闭及最终关闭仍归业务 owner。
     */
    struct OperationPublicationReceipt final
    {
        Preview::Fault::Failure WaiterSignalFailure{};
    };
}
