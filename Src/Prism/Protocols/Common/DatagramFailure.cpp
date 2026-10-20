/** @file DatagramFailure.cpp @brief Common 数据报异常与首因投影实现。 */

#include <Prism/Protocols/Common/DatagramFailure.hpp>

#include <boost/system/system_error.hpp>

#include <system_error>

namespace Prism::Protocols
{
    auto DatagramFailure::Preserve(
        std::optional<Prism::Fault::Failure>& First,
        Prism::Fault::Failure Next) noexcept -> void
    {
        if (Next.Succeeded()) return;
        if (!First) First = Next;
        else if (!First->Native && Next.Native) First->Native = Next.Native;
    }

    auto DatagramFailure::FromException(std::exception_ptr Exception) noexcept
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
} // namespace Prism::Protocols
