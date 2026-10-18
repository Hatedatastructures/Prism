/**
 * @file Types.hpp
 * @brief Prism 应用 shutdown 阶段共享的 typed 结果与 deadline 类型。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <chrono>
#include <expected>

namespace Prism::Application::Shutdown
{

    using ShutdownOutcome = std::expected<void, Prism::Fault::Failure>;
    using ShutdownDeadline = std::chrono::steady_clock::time_point;

} // namespace Prism::Application::Shutdown