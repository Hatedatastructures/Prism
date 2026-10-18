/** @file CloseFailure.hpp @brief 关闭失败的唯一 typed 结果，不将失败排空视为完成。 */
#pragma once
#include <stdexcept>
namespace Prism::Lifecycle
{
    enum class CloseFailureKind { DispatchUnavailable, CarrierClosure };
    class CloseFailure final : public std::runtime_error
    {
    public:
        explicit CloseFailure(CloseFailureKind Kind)
            : std::runtime_error(Kind == CloseFailureKind::DispatchUnavailable
                ? "original executor cannot retire closing resources" : "carrier closure failed"), Kind_(Kind) {}
        [[nodiscard]] auto Kind() const noexcept -> CloseFailureKind { return Kind_; }
    private:
        CloseFailureKind Kind_;
    };
}
