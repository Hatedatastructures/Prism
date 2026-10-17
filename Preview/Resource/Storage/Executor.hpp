/** @file Executor.hpp @brief 单线程存储执行域，封止、真实排空及完成返回原 executor。 */
#pragma once
#include <Preview/Foundation/Storage/Sqlite.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <atomic>
#include <expected>
#include <functional>
#include <memory>
#include <type_traits>
#include <vector>

namespace Preview::Resource::Storage
{
    namespace Net = boost::asio;
    /**
     * @brief 所有 SQL 在唯一线程运行；Application 必须保活到 Shutdown 完成再在冷关闭路径 Join。
     * @details 输入按值转移，已受理事务不可被协程取消隐藏结果；不拥有网络资源，不执行网络关闭。
     *          Gate 同时记录封止位和已受理计数，排空覆盖封止前尚未完成投递的请求。
     */
    class Executor final : public std::enable_shared_from_this<Executor>
    {
    public:
        Executor() : Pool_(1) {}
        Executor(const Executor&) = delete;
        auto operator=(const Executor&) -> Executor& = delete;
        ~Executor() { Pool_.join(); }

        /** @brief 按值接管同步存储工作，返回原协程 executor；失败不丢原生错误。 */
        template<class Function>
        [[nodiscard]] auto Execute(Function Work) -> Net::awaitable<std::invoke_result_t<Function>>
        {
            auto Token = Net::use_awaitable;
            co_return co_await Net::async_initiate<decltype(Token), void(std::invoke_result_t<Function>)>(
                Start<Function>{shared_from_this(), std::move(Work)}, Token);
        }
        /** @brief 封止新工作，等全部已受理 SQL 后在存储线程执行关闭；不取消任何持久事务。 */
        template<class Function>
        [[nodiscard]] auto Shutdown(Function Close) -> Net::awaitable<std::expected<void, Fault::Failure>>
        {
            Gate_.fetch_or(ClosedBit, std::memory_order_acq_rel);
            auto Token = Net::use_awaitable;
            co_return co_await Net::async_initiate<decltype(Token), void(std::expected<void, Fault::Failure>)>(
                StartDrain<Function>{shared_from_this(), std::move(Close)}, Token);
        }
        /** @brief 仅进程冷关闭调用；调用前必须等待 Shutdown，禁止存储线程或网络协程同步调用。 */
        auto Join() -> void { Pool_.join(); }
    private:
        static constexpr auto ClosedBit = std::uint64_t{1} << 63U;
        [[nodiscard]] auto Enter() -> bool
        {
            auto Value = Gate_.load(std::memory_order_acquire);
            while (!(Value & ClosedBit))
            {
                if (Gate_.compare_exchange_weak(Value, Value + 1, std::memory_order_acq_rel)) return true;
            }
            return false;
        }
        auto Leave() -> void
        {
            if (Gate_.fetch_sub(1, std::memory_order_acq_rel) == ClosedBit + 1) NotifyDrain();
        }
        auto NotifyDrain() -> void
        {
            if (Gate_.load(std::memory_order_acquire) != ClosedBit) return;
            auto Waiting = std::move(DrainWaiters_);
            DrainWaiters_.clear();
            for (auto& Complete : Waiting) Complete();
        }
        template<class Function>
        static auto Invoke(Function& Work) -> std::invoke_result_t<Function>
        {
            try { return Work(); }
            catch (const Preview::Storage::SqliteError& Error)
            { return std::unexpected(Preview::Storage::SqliteFailure(Error.Code)); }
            catch (const std::system_error& Error)
            { return std::unexpected(Fault::Failure{Fault::Code::IoError, Error.code()}); }
            catch (...) { return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable}); }
        }
        template<class Function, class Handler>
        struct Job final
        {
            std::shared_ptr<Executor> Owner;
            Function Work;
            Handler Completion;
            decltype(Net::make_work_guard(Net::get_associated_executor(std::declval<Handler>()))) Guard;
            auto operator()() -> void
            {
                auto Result = Invoke(Work);
                Owner->Leave();
                Net::post(Guard.get_executor(), [Self = std::move(Owner), Done = std::move(Completion),
                    Keep = std::move(Guard), Value = std::move(Result)]() mutable { Done(std::move(Value)); });
            }
        };
        template<class Function>
        struct Start final
        {
            std::shared_ptr<Executor> Owner;
            Function Work;
            template<class Handler>
            auto operator()(Handler Completion) -> void
            {
                auto Guard = Net::make_work_guard(Net::get_associated_executor(Completion));
                if (!Owner->Enter())
                {
                    using Result = std::invoke_result_t<Function>;
                    Net::post(Guard.get_executor(), [Done = std::move(Completion), Keep = std::move(Guard)]() mutable
                        { Done(Result(std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable}))); });
                    return;
                }
                Net::post(Owner->Pool_, Job<Function, Handler>{Owner, std::move(Work),
                    std::move(Completion), std::move(Guard)});
            }
        };
        template<class Function, class Handler>
        struct DrainJob final
        {
            std::shared_ptr<Executor> Owner;
            Function Close;
            Handler Completion;
            decltype(Net::make_work_guard(Net::get_associated_executor(std::declval<Handler>()))) Guard;
            auto Finish() -> void
            {
                auto Result = Invoke(Close);
                Net::post(Guard.get_executor(), [Self = std::move(Owner), Done = std::move(Completion),
                    Keep = std::move(Guard), Value = std::move(Result)]() mutable { Done(std::move(Value)); });
            }
            auto operator()() -> void
            {
                const auto Self = Owner;
                Owner->DrainWaiters_.emplace_back([Value = std::move(*this)]() mutable { Value.Finish(); });
                Self->NotifyDrain();
            }
        };
        template<class Function>
        struct StartDrain final
        {
            std::shared_ptr<Executor> Owner;
            Function Close;
            template<class Handler>
            auto operator()(Handler Completion) -> void
            {
                auto Guard = Net::make_work_guard(Net::get_associated_executor(Completion));
                Net::post(Owner->Pool_, DrainJob<Function, Handler>{Owner, std::move(Close),
                    std::move(Completion), std::move(Guard)});
            }
        };
        Net::thread_pool Pool_;
        std::atomic<std::uint64_t> Gate_{0};
        std::vector<std::move_only_function<void()>> DrainWaiters_;
    };
}
