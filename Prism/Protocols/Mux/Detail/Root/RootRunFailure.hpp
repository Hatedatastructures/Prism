/** @file RootRunFailure.hpp @brief 统一处理 Mux root 正常关闭产生的运行取消。 */
#pragma once

#include <Prism/Protocols/Mux/Detail/Root/RootState.hpp>

namespace Prism::Mux::Detail
{
    /** @brief 只把正常 root Close 触发的 Run 取消转换为成功。 */
    [[nodiscard]] inline auto IsExpectedRootRunCancellation(
        const std::shared_ptr<RootState> &State,
        const std::expected<void, Prism::Fault::Failure> &Result) noexcept -> bool
    {
        return State && !Result &&
            Result.error().Code == Prism::Fault::Code::Canceled &&
            State->IsClosingNormally();
    }

    /** @brief 正常关闭触发的 H2 Run 取消交给外层 root 物理 Drain 判定。 */
    inline auto RecordHttp2RunFailure(
        const std::shared_ptr<RootState> &State,
        const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (!State || (State->IsClosingNormally() &&
            Failure.Code == Prism::Fault::Code::Canceled))
        {
            return;
        }
        State->RecordTerminalFailure(Failure);
    }
}
