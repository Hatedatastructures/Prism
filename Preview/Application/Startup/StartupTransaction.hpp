/**
 * @file StartupTransaction.hpp
 * @brief 启动期间资源的唯一回滚合同。
 */
#pragma once
#include <Preview/Application/Application.hpp>
#include <Preview/Application/Shutdown.hpp>

#include <memory>
#include <utility>

namespace Preview::Application::Startup
{
    /** @brief 控制线程持有未发布 runtime；提交之前任意返回或异常均排空并释放资源。 */
    class StartupTransaction final
    {
    public:
        explicit StartupTransaction(std::shared_ptr<Application::RuntimeState> Runtime)
            : Runtime_(std::move(Runtime))
        {
        }
        StartupTransaction(const StartupTransaction&) = delete;
        auto operator=(const StartupTransaction&) -> StartupTransaction& = delete;
        ~StartupTransaction() noexcept
        {
            if (Runtime_)
                Shutdown::RunStartupRollback(Runtime_);
        }
        /** @brief 全部阶段和输出发布成功后转移最终关闭责任给 Application。 */
        [[nodiscard]] auto Commit() noexcept -> std::shared_ptr<Application::RuntimeState>
        {
            return std::exchange(Runtime_, {});
        }

    private:
        std::shared_ptr<Application::RuntimeState> Runtime_;
    };
} // namespace Preview::Application::Startup
