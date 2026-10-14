/**
 * @file ContextOwner.hpp
 * @brief 可独立保留的 executor context 与 PMR owner，不包含运行时服务、绑定或任务。
 * @details 上下文中的窄生命周期 service 仅保存 weak owner/storage；载体按自己的实际
 *          executor 获取 owner。所有 channel、socket、协程和 allocator 先于本 owner 释放。
 */
#pragma once
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/FatalState.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/execution/context.hpp>
#include <boost/asio/query.hpp>
#include <memory>
#include <memory_resource>
namespace Preview::Executor
{
    namespace Net = boost::asio;
    class ContextOwner;
    /** @brief 绑定到真实 execution_context 的生命周期关联；无协议查找、调度或强反向引用。 */
    class ContextOwnership final : public Net::execution_context::service
    {
    public:
        inline static Net::execution_context::id id;
        explicit ContextOwnership(Net::execution_context& Context) : service(Context) {}
        std::weak_ptr<ContextOwner> Owner;
        std::weak_ptr<ClosingStorage> Storage;
    private:
        auto shutdown() -> void override { Owner.reset(); Storage.reset(); }
    };
    class ContextOwner final
    {
    public:
        ContextOwner() : Pool(std::pmr::pool_options{}, std::pmr::new_delete_resource()), Io(1)
        { Fatal = FatalState::Bind(Io); }
        /** @brief 冷路径创建独立 context/allocator 并关联进程存储；错误抛给启动事务。 */
        [[nodiscard]] static auto Create(std::shared_ptr<ClosingStorage> Storage = ClosingStorage::ProcessStorage())
            -> std::shared_ptr<ContextOwner>
        {
            auto Owner = std::make_shared<ContextOwner>();
            auto& Service = Net::use_service<ContextOwnership>(Owner->Io);
            Service.Owner = Owner;
            Service.Storage = std::move(Storage);
            return Owner;
        }
        /** @brief 按实际 carrier executor 获取独立 owner；外部 executor 须由调用者保活至 Drain。 */
        [[nodiscard]] static auto Find(const Net::any_io_executor& Executor) -> std::shared_ptr<ContextOwner>
        {
            auto& Context = Net::query(Executor, Net::execution::context);
            if (!Net::has_service<ContextOwnership>(Context)) return {};
            return Net::use_service<ContextOwnership>(Context).Owner.lock();
        }
        /** @brief 返回 context 对应的 L1 storage；没有关联时使用同一个进程终态存储。 */
        [[nodiscard]] static auto Storage(const Net::any_io_executor& Executor) -> std::shared_ptr<ClosingStorage>
        {
            auto& Context = Net::query(Executor, Net::execution::context);
            if (Net::has_service<ContextOwnership>(Context))
                if (auto Value = Net::use_service<ContextOwnership>(Context).Storage.lock()) return Value;
            return ClosingStorage::ProcessStorage();
        }
        /** @brief 已停止的 context 当前不能执行回收；调用者必须先 restart 并重新驱动。 */
        [[nodiscard]] auto CanDispatch() const noexcept -> bool { return !Io.stopped(); }
        std::pmr::unsynchronized_pool_resource Pool;
        Net::io_context Io;
        std::shared_ptr<FatalState> Fatal;
    };
}
