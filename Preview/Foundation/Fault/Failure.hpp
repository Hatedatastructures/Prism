/**
 * @file Failure.hpp
 * @brief 正式业务失败值，保留领域类别与原生错误身份。
 * @details 纯值可复制并跨 executor 传递，不拥有 I/O 或业务资源。
 *          不格式化错误消息，不抛出异常；取消、EOF 和容量拒绝均保留独立 Code。
 */
#pragma once

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>

#include <system_error>

namespace Preview::Fault
{
    /**
     * @brief 一次失败的领域分类与原生 cause。
     * @details Native 的 category 必须来自具有程序生命周期的标准/协议 category。
     *          本类型不执行取消、半关闭或最终关闭；这些行为由返回它的 owner 完成。
     */
    struct Failure final
    {
        Fault::Code Code{Fault::Code::Success}; ///< 正式失败类别，Success 表示无领域失败。
        std::error_code Native{}; ///< 原生 category/value，不转换为消息字符串。

        /** @brief 检查是否同时没有领域失败和原生失败；无 executor 或资源副作用。 */
        [[nodiscard]] auto Succeeded() const noexcept -> bool
        {
            return Code == Fault::Code::Success && !Native;
        }

        /** @brief 检查是否存在失败；EOF、取消和 Blocked 均保持其正式类别。 */
        [[nodiscard]] auto Failed() const noexcept -> bool
        {
            return !Succeeded();
        }
    };

    /**
     * @brief 将原生错误在正式边界一次映射为领域失败并保留 cause。
     * @param Native 按值复制的原生错误，空值表示成功。
     * @return 不分配的失败值；不拥有资源、不执行关闭，任意 executor 可同步调用。
     */
    [[nodiscard]] inline auto FromNative(const std::error_code Native) noexcept -> Failure
    {
        return {ToCode(Native), Native};
    }

    /**
     * @brief 在正式边界把失败值还原为原生/项目 error_code。
     * @param Value 同步借用的失败值；不保存引用，不执行关闭或取消。
     * @return Native 存在时保持其 category/value；否则用项目 category 表达领域码，成功为默认值。
     */
    [[nodiscard]] inline auto ToNative(const Failure &Value) noexcept -> std::error_code
    {
        if (Value.Native)
        {
            return Value.Native;
        }
        if (Value.Succeeded())
        {
            return {};
        }
        return make_error_code(Value.Code);
    }
}
