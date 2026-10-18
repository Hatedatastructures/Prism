/** @file DatagramFailure.hpp @brief 数据报 pump 与退休 owner 共有的原生异常投影。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <boost/system/system_error.hpp>
#include <exception>
#include <optional>
#include <system_error>
namespace Prism::Protocols
{
    /** @brief 值持有 exception_ptr 并保留 native category/value；未知异常返回 IoError。
     * @details 只投影错误，不关闭资源、不发布 Fatal，也不改变取消或最终关闭者。 */
    class DatagramFailure final
    {
    public:
        /** @brief 合并多层 Drain 原因，保留首个类别及后续补全的 native identity。 */
        static auto Preserve(std::optional<Prism::Fault::Failure>& First,
                             Prism::Fault::Failure Next) noexcept -> void
        {
            if (Next.Succeeded()) return;
            if (!First) First = Next;
            else if (!First->Native && Next.Native) First->Native = Next.Native;
        }

        [[nodiscard]] static auto FromException(std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure
        {
            try
            {
                if (Exception) std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error& Value)
            {
                return Prism::Fault::FromNative(static_cast<std::error_code>(Value.code()));
            }
            catch (const std::system_error& Value)
            {
                return Prism::Fault::FromNative(Value.code());
            }
            catch (...)
            {
                return Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }
            return Prism::Fault::Failure{Prism::Fault::Code::IoError};
        }
    };
}
