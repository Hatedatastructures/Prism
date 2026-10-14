/**
 * @file Types.hpp
 * @brief Preview 应用 shutdown 阶段共享的 typed 结果与 deadline 类型。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>

#include <chrono>
#include <expected>

namespace Preview::Application::Shutdown
{

    using ShutdownOutcome = std::expected<void, Preview::Fault::Failure>;
    using ShutdownDeadline = std::chrono::steady_clock::time_point;

} // namespace Preview::Application::Shutdown