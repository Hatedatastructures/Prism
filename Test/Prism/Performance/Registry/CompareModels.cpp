/**
 * @file CompareModels.cpp
 * @brief 注册表模型工厂。
 */

#include "CompareModels.hpp"

#include <exception>
#include <latch>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace Prism::Runtime::Perf
{

    namespace
    {

        class ConcurrentRegistrationRun final
        {
        public:
            ConcurrentRegistrationRun(
                IModel &ModelValue,
                const std::array<SessionInfo, ConcurrentRegistryCount> &Infos)
                : Model_(ModelValue), Infos_(Infos)
            {
                try
                {
                    Threads_.reserve(ConcurrentRegistryCount);
                    for (std::size_t Index = 0; Index < ConcurrentRegistryCount; ++Index)
                    {
                        Threads_.emplace_back(&ConcurrentRegistrationRun::RunOne, this, Index);
                    }
                }
                catch (...)
                {
                    const auto Missing = static_cast<std::ptrdiff_t>(
                        ConcurrentRegistryCount - Threads_.size());
                    if (Missing != 0)
                    {
                        Ready_.count_down(Missing);
                        Done_.count_down(Missing);
                    }
                    Go_.count_down();
                    Join();
                    throw;
                }
            }

            ~ConcurrentRegistrationRun() noexcept { Join(); }

            auto Run() -> void
            {
                Ready_.wait();
                Go_.count_down();
                Done_.wait();
                Join();
                Rethrow();
            }

            auto TakeTokens() -> std::array<Token, ConcurrentRegistryCount>
            {
                return std::move(Tokens_);
            }

        private:
            auto RunOne(const std::size_t Index) noexcept -> void
            {
                Ready_.count_down();
                Go_.wait();
                try
                {
                    Tokens_[Index] = Model_.Register(Infos_[Index]);
                }
                catch (...)
                {
                    Failures[Index] = std::current_exception();
                }
                Done_.count_down();
            }

            auto Join() noexcept -> void
            {
                for (auto &Thread : Threads_)
                {
                    if (Thread.joinable())
                    {
                        Thread.join();
                    }
                }
            }

            auto Rethrow() const -> void
            {
                for (const auto &Failure : Failures)
                {
                    if (Failure)
                    {
                        std::rethrow_exception(Failure);
                    }
                }
            }

            IModel &Model_;
            std::array<SessionInfo, ConcurrentRegistryCount> Infos_;
            std::array<Token, ConcurrentRegistryCount> Tokens_{};
            std::array<std::exception_ptr, ConcurrentRegistryCount> Failures{};
            std::latch Ready_{ConcurrentRegistryCount};
            std::latch Go_{1};
            std::latch Done_{ConcurrentRegistryCount};
            std::vector<std::thread> Threads_;
        };

        class ConcurrentHookEmitRun final
        {
        public:
            explicit ConcurrentHookEmitRun(IModel &ModelValue) : Model_(ModelValue)
            {
                try
                {
                    Threads_.reserve(ConcurrentRegistryCount);
                    for (std::size_t Index = 0; Index < ConcurrentRegistryCount; ++Index)
                    {
                        Threads_.emplace_back(&ConcurrentHookEmitRun::RunOne, this, Index);
                    }
                }
                catch (...)
                {
                    const auto Missing = static_cast<std::ptrdiff_t>(
                        ConcurrentRegistryCount - Threads_.size());
                    if (Missing != 0)
                    {
                        Ready_.count_down(Missing);
                        Done_.count_down(Missing);
                    }
                    Go_.count_down();
                    Join();
                    throw;
                }
            }

            ~ConcurrentHookEmitRun() noexcept { Join(); }

            auto Run() -> void
            {
                Ready_.wait();
                Go_.count_down();
                Done_.wait();
                Join();
                Rethrow();
            }

            [[nodiscard]] auto Results() const
                -> std::array<bool, ConcurrentRegistryCount>
            {
                return Results_;
            }

        private:
            auto RunOne(const std::size_t Index) noexcept -> void
            {
                Ready_.count_down();
                Go_.wait();
                try
                {
                    Results_[Index] = Model_.EmitFailedErrorHook();
                }
                catch (...)
                {
                    Failures[Index] = std::current_exception();
                }
                Done_.count_down();
            }

            auto Join() noexcept -> void
            {
                for (auto &Thread : Threads_)
                {
                    if (Thread.joinable())
                    {
                        Thread.join();
                    }
                }
            }

            auto Rethrow() const -> void
            {
                for (const auto &Failure : Failures)
                {
                    if (Failure)
                    {
                        std::rethrow_exception(Failure);
                    }
                }
            }

            IModel &Model_;
            std::array<bool, ConcurrentRegistryCount> Results_{};
            std::array<std::exception_ptr, ConcurrentRegistryCount> Failures{};
            std::latch Ready_{ConcurrentRegistryCount};
            std::latch Go_{1};
            std::latch Done_{ConcurrentRegistryCount};
            std::vector<std::thread> Threads_;
        };

    } // namespace

    auto RunConcurrentRegistrations(
        IModel &Model, const std::array<SessionInfo, ConcurrentRegistryCount> &Infos)
        -> std::array<Token, ConcurrentRegistryCount>
    {
        ConcurrentRegistrationRun Coordinator(Model, Infos);
        Coordinator.Run();
        return Coordinator.TakeTokens();
    }

    auto RunConcurrentFailedHookEmits(IModel &Model)
        -> std::array<bool, ConcurrentRegistryCount>
    {
        ConcurrentHookEmitRun Coordinator(Model);
        Coordinator.Run();
        return Coordinator.Results();
    }

    auto MakeCurrentCowModel(std::size_t Executors) -> std::unique_ptr<IModel>;
    auto MakeShardedCowModel(std::size_t Shards) -> std::unique_ptr<IModel>;
    auto MakeExecutorTableModel(std::size_t Executors) -> std::unique_ptr<IModel>;

    auto MakeModel(const ModelKind Kind, const std::size_t Executors)
        -> std::unique_ptr<IModel>
    {
        switch (Kind)
        {
        case ModelKind::CurrentCow:
            return MakeCurrentCowModel(Executors);
        case ModelKind::ShardedCow:
            return MakeShardedCowModel(Executors);
        case ModelKind::ExecutorTable:
            return MakeExecutorTableModel(Executors);
        case ModelKind::All:
            break;
        }
        throw std::invalid_argument("all is not a concrete model");
    }

} // namespace Prism::Runtime::Perf
