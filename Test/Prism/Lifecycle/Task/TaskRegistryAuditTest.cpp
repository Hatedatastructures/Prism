/**
 * @file TaskRegistryAuditTest.cpp
 * @brief TaskRegistry 所有者隔离审计。
 */
#include <gtest/gtest.h>
#include <boost/asio/io_context.hpp>
#include <memory>
#include <optional>
#include <utility>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include "TaskHandleTestAccess.hpp"
#include <TestSupport/Fixtures/TaskRegistryAccess.hpp>
namespace
{
    auto CompleteTask() -> boost::asio::awaitable<void> { co_return; }

    /**
     * @brief 以 test-only seed 保留固定输入，不恢复生产指定 TaskId API。
     * @details guard 只在本测试中建立 owner 分配边界，并在离开作用域时恢复序列。
     */
    class NextTaskIdGuard final
    {
    public:
        explicit NextTaskIdGuard(const std::uint64_t Seed)
            : Saved_(Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(Seed))
        {
        }

        ~NextTaskIdGuard()
        {
            (void)Prism::Lifecycle::TaskRegistryTestAccess::ExchangeNextId(Saved_);
        }

    private:
        std::uint64_t Saved_;
    };
}
TEST(OwnershipAudit, TaskRegistryDanglingOwner)
    {
        auto IoContext = std::make_unique<boost::asio::io_context>();
        NextTaskIdGuard IdGuard{701U};
        std::optional<Prism::Lifecycle::TaskHandle> Task;
        {
            Prism::Lifecycle::TaskRegistry Registry(IoContext->get_executor());
            auto Submitted = Registry.SpawnTracked(
                Prism::Lifecycle::TaskRequest{
                    .Context = Prism::Lifecycle::TaskContext{
                        .SessionId = Prism::SessionId{701},
                        .StreamId = Prism::StreamId{701},
                        .WorkerId = Prism::WorkerId{701},
                        .Generation = Prism::GenerationId{701}},
                    .Cancel = {},
                    .StartOnSubmit = true},
                CompleteTask());
            ASSERT_TRUE(Submitted);
            Task.emplace(std::move(*Submitted));
        } // registry 析构；排队任务由 Lifecycle owner 隔离

        IoContext->run();
        ASSERT_TRUE(Task.has_value());
        EXPECT_TRUE(Task->IsCompleted());
        EXPECT_EQ(Task->Result().Outcome, Prism::Lifecycle::TaskOutcome::Quarantined);
        EXPECT_EQ(Task->CompletionCount(), 1U);
        const std::weak_ptr<Prism::Lifecycle::TaskState> WeakTask{
            Prism::Lifecycle::TaskHandleTestAccess::State(*Task)};
        Task.reset();
        EXPECT_TRUE(WeakTask.expired());
        // TaskState 的 cancellation domain 与 reclaimer 借用 executor，先释放再销毁 context。
        IoContext.reset();
    }
