/**
 * @file UdpAssocFailureState.hpp
 * @brief SOCKS5 UDP 关联的首个失败与原生错误投影。
 * @details 独立保存失败事实；关联退休 owner 负责失败时的自我保留与等待者通知。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>

#include <boost/system/system_error.hpp>

#include <atomic>
#include <exception>
#include <memory>
#include <system_error>

namespace Prism::Socks5::Detail
{
    /**
     * @class UdpAssocFailureState
     * @brief 聚合 UDP 关联的首个 typed failure 与可用的原生错误。
     * @details 不负责生命周期、调度或通知；这些动作由持有本状态的关联退休 owner 完成。
     */
    class UdpAssocFailureState final
    {
    public:
        using Failure = Prism::Fault::Failure;

        /** @brief 保留首个领域错误，并补充首个可用原生错误码。 */
        auto Record(Failure Value) noexcept -> void
        {
            if (Value.Succeeded()) return;
            (void)Failure_.TrySet(Value);
            if (Value.Native && !NativeFailure_.load(std::memory_order_acquire))
            {
                try
                {
                    auto Native = std::make_shared<const std::error_code>(Value.Native);
                    std::shared_ptr<const std::error_code> Empty;
                    (void)NativeFailure_.compare_exchange_strong(
                        Empty, std::move(Native), std::memory_order_acq_rel);
                }
                catch (...)
                {
                }
            }
        }

        /** @brief 读取领域失败，并在其尚无原生码时补入已保存的原生错误。 */
        [[nodiscard]] auto Load() const noexcept -> Failure
        {
            auto Value = Failure_.Load();
            if (!Value.Native)
            {
                if (const auto Native = NativeFailure_.load(std::memory_order_acquire))
                    Value.Native = *Native;
            }
            return Value;
        }

        /** @brief 将异常投影为与关联 owner 现有规则一致的 typed/native failure。 */
        [[nodiscard]] static auto FromException(const std::exception_ptr Exception) noexcept -> Failure
        {
            try
            {
                if (Exception) std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error &ErrorValue)
            {
                const auto Native = static_cast<std::error_code>(ErrorValue.code());
                return {Prism::Fault::ToCode(Native), Native};
            }
            catch (const std::system_error &ErrorValue)
            {
                return {Prism::Fault::ToCode(ErrorValue.code()), ErrorValue.code()};
            }
            catch (...)
            {
                return {Prism::Fault::Code::IoError};
            }
            return {Prism::Fault::Code::IoError};
        }

    private:
        Prism::Fault::FailureState Failure_;
        std::atomic<std::shared_ptr<const std::error_code>> NativeFailure_;
    };
} // namespace Prism::Socks5::Detail
