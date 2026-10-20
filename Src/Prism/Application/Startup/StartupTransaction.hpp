/** @file StartupTransaction.hpp @brief 启动期间资源的唯一回滚合同。 */
#pragma once

#include <Prism/Application/Application.hpp>

#include <memory>

namespace Prism::Application::Startup
{

    class StartupTransaction final
    {
    public:
        explicit StartupTransaction(std::shared_ptr<Application::RuntimeState> Runtime);
        StartupTransaction(const StartupTransaction &) = delete;
        auto operator=(const StartupTransaction &) -> StartupTransaction & = delete;
        ~StartupTransaction() noexcept;

        /** @brief 所有启动阶段和发布成功后转交最终关闭责任。 */
        [[nodiscard]] auto Commit() noexcept
            -> std::shared_ptr<Application::RuntimeState>;

    private:
        std::shared_ptr<Application::RuntimeState> Runtime_;
    };

} // namespace Prism::Application::Startup
