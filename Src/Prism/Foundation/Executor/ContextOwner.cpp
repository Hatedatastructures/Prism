/** @file ContextOwner.cpp @brief executor context 与 allocator owner 实现。 */
#include <Prism/Foundation/Executor/ContextOwner.hpp>

#include <boost/asio/query.hpp>
#include <boost/asio/execution_context.hpp>
#include <utility>

namespace Prism::Executor
{
    ContextOwnership::ContextOwnership(Net::execution_context& Context)
        : service(Context)
    {
    }

    auto ContextOwnership::shutdown() -> void
    {
        Owner.reset();
        Storage.reset();
    }

    ContextOwner::ContextOwner()
        : Pool(std::pmr::pool_options{}, std::pmr::new_delete_resource()), Io(1)
    {
        Fatal = FatalState::Bind(Io);
    }

    auto ContextOwner::Create(std::shared_ptr<ClosingStorage> Storage) -> std::shared_ptr<ContextOwner>
    {
        auto Owner = std::make_shared<ContextOwner>();
        auto& Service = Net::use_service<ContextOwnership>(Owner->Io);
        Service.Owner = Owner;
        Service.Storage = std::move(Storage);
        return Owner;
    }

    auto ContextOwner::Find(const Net::any_io_executor& Executor) -> std::shared_ptr<ContextOwner>
    {
        auto& Context = Net::query(Executor, Net::execution::context);
        if (!Net::has_service<ContextOwnership>(Context)) return {};
        return Net::use_service<ContextOwnership>(Context).Owner.lock();
    }

    auto ContextOwner::Storage(const Net::any_io_executor& Executor) -> std::shared_ptr<ClosingStorage>
    {
        auto& Context = Net::query(Executor, Net::execution::context);
        if (Net::has_service<ContextOwnership>(Context))
            if (auto Value = Net::use_service<ContextOwnership>(Context).Storage.lock()) return Value;
        return ClosingStorage::ProcessStorage();
    }
}
