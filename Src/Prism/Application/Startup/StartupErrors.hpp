/**
 * @file StartupErrors.hpp
 * @brief Prism 应用内部启动错误构造接口。
 */
#pragma once

#include <Prism/Application/Definition.hpp>

#include <exception>
#include <string>

namespace Prism::Application::Startup
{

    [[nodiscard]] auto MakeStartupError(
        StartupErrorCode Code,
        std::string Path,
        std::string Message) -> StartupError;

    [[nodiscard]] auto DescribeException(const std::exception_ptr &Failure) -> std::string;

} // namespace Prism::Application::Startup
