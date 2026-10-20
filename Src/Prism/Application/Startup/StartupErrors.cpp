/** @file StartupErrors.cpp @brief 启动错误值与异常描述实现。 */

#include <Prism/Application/Startup/StartupErrors.hpp>

#include <utility>

namespace Prism::Application::Startup
{

    auto MakeStartupError(const StartupErrorCode Code, std::string Path,
        std::string Message) -> StartupError
    {
        return StartupError{Code, std::move(Path), std::move(Message)};
    }

    auto DescribeException(const std::exception_ptr &Failure) -> std::string
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
