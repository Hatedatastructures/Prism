/**
 * @file StartupErrors.hpp
 * @brief Prism 应用启动错误构造与异常文本转换。
 */
#pragma once

#include <Prism/Application/Definition.hpp>

#include <exception>
#include <string>
#include <utility>

namespace Prism::Application::Startup
{

    [[nodiscard]] inline auto MakeStartupError(
        const StartupErrorCode Code,
        std::string Path,
        std::string Message) -> StartupError
    {
        return StartupError{Code, std::move(Path), std::move(Message)};
    }

    [[nodiscard]] inline auto DescribeException(
        const std::exception_ptr &Failure) -> std::string
    {
        if (!Failure)
        {
            return {};
        }
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            return Error.what();
        }
        catch (...)
        {
            return "unknown exception";
        }
    }

} // namespace Prism::Application::Startup
