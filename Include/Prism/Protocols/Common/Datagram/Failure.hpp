/** @file Failure.hpp @brief 数据报 pump 与退休 owner 共有的原生异常投影。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <exception>
#include <optional>
namespace Prism::Protocols
{
    /** @brief 值持有 exception_ptr 并保留 native category/value；未知异常返回 IoError。
     * @details 只投影错误，不关闭资源、不发布 Fatal，也不改变取消或最终关闭者。 */
    class DatagramFailure final
    {
    public:
        /** @brief 合并多层 Drain 原因，保留首个类别及后续补全的 native identity。 */
        static auto Preserve(std::optional<Prism::Fault::Failure>& First,
                             Prism::Fault::Failure Next) noexcept -> void;

        [[nodiscard]] static auto FromException(std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure;
    };
}
