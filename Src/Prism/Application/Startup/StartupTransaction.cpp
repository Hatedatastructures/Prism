/** @file StartupTransaction.cpp @brief 启动事务回滚与提交实现。 */

#include <Prism/Application/Startup/StartupTransaction.hpp>
#include <Prism/Application/Shutdown.hpp>

#include <utility>

namespace Prism::Application::Startup
{

    StartupTransaction::StartupTransaction(
        std::shared_ptr<Application::RuntimeState> Runtime)
        : Runtime_(std::move(Runtime))
    {
    }

    StartupTransaction::~StartupTransaction() noexcept
    {
        if (Runtime_)
        {
            Shutdown::RunStartupRollback(Runtime_);
        }
    }

    auto StartupTransaction::Commit() noexcept
        -> std::shared_ptr<Application::RuntimeState>
    {
        return std::exchange(Runtime_, {});
    }

} // namespace Prism::Application::Startup
