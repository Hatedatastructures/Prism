/**
 * @file SessionIdAllocator.hpp
 * @brief 应用进程内共享的 SessionId 单调分配器。
 * @details TCP listener 与 Boundary QUIC connection 共用一条分配序列，
 *          避免不同入口生成重复的统计 Session scope；耗尽后返回空 ID。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>

namespace Prism::Foundation::Identifier
{

    /** @brief 预留不复用的进程级 SessionId；耗尽时返回空 ID。 */
    [[nodiscard]] auto ReserveSessionId() noexcept -> Prism::SessionId;

} // namespace Prism::Foundation::Identifier
