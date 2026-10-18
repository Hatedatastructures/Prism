/** @file QuicBindingState.hpp @brief 实际 QUIC 连接集合、原 executor 回收与 typed 排空失败。 */
#pragma once
#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <algorithm>
#include <atomic>
#include <memory>
#include <optional>
#include <vector>
namespace Prism::Protocols
{
    /** @brief owner 集合持有真实实物及独立 context；通知只 weak 联系本对象，无 Runtime 强 pin。 */
    class QuicBindingState final : public Prism::Executor::ClosingResource,
        public std::enable_shared_from_this<QuicBindingState>
    {
    public:
        explicit QuicBindingState(boost::asio::any_io_executor Executor)
            :Context_(Prism::Executor::ContextOwner::Find(Executor)),
             Storage_(Prism::Executor::ContextOwner::Storage(Executor)),
             Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor))),Barrier_(Reclaimer_){}
        /** @brief listener executor 上登记完整 native owner；失败不发布连接，预约只计真实最终完成。 */
        [[nodiscard]] auto Track(std::shared_ptr<Prism::Contract::QuicConnectionOwner> Owner)->bool
        {
            if(Closed_.load() || !CanAdmit() || !Barrier_.Enter())return false;
            try{Connections_.push_back(std::move(Owner));Active_.fetch_add(1);}
            catch(...){Barrier_.Leave();throw;}
            return true;
        }
        auto Finished(const Prism::Contract::QuicConnectionOwner* Owner) noexcept -> void
        {
            const auto Found=std::find_if(Connections_.begin(),Connections_.end(),
                [Owner](const auto& Value){return Value.get()==Owner;});
            if(Found==Connections_.end())return;
            Connections_.erase(Found);Active_.fetch_sub(1);Barrier_.Leave();
        }
        [[nodiscard]] auto Closed() const noexcept -> bool {return Closed_.load();}
        [[nodiscard]] auto PendingCloseFailure() const noexcept
            ->std::optional<Prism::Fault::Failure>
        {return LoadCloseFailure();}
        [[nodiscard]] auto CanDispatch() const noexcept -> bool
        {return (!Context_ || Context_->CanDispatch()) && Reclaimer_->CanDispatch();}
        [[nodiscard]] auto CanAdmit() const noexcept -> bool
        {auto Storage=Storage_.lock();return CanDispatch() && (!Storage || !Storage->IsSealed());}
        /** @brief 任意线程封止接入并投递弱通知；真实 owner 集合保活 context 和协议材料。 */
        auto Close() noexcept -> void
        {
            if(Closed_.exchange(true))return;
            Barrier_.Seal();RequestRetirement();
        }
        auto Failed(Prism::Fault::Failure Reason={Prism::Fault::Code::Blocked}) noexcept -> void
        {
            if (Reason.Succeeded()) Reason = {Prism::Fault::Code::Blocked};
            Failure_.TrySet(Reason);
            DispatchFailed_.store(Reason.Code==Prism::Fault::Code::Blocked);
            Closed_.store(true);Barrier_.Seal();Barrier_.Block();HoldPending();
        }
        /** @brief 只有真实 owner 尚未 finalize 时接管至 L1；不创建第二回收队列。 */
        auto HoldPending() noexcept -> void
        {if(Active_.load()!=0)if(auto Storage=Storage_.lock())Storage->Retain(shared_from_this());}
        /** @brief 保留单连接关闭拒收首因，并让活动 owner 留在关闭存储中等待同 executor 重试。 */
        auto RetainRejectedCloseRequest(Prism::Fault::Failure Reason) noexcept -> void
        {
            if(Reason.Succeeded())Reason={Prism::Fault::Code::Blocked};
            SaveCloseFailure(Reason);
            HoldPending();
        }
        auto RequestRetirement() noexcept -> void override
        {
            const auto Weak=weak_from_this();
            if(!CanDispatch())
            {
                SaveCloseFailure({Prism::Fault::Code::Blocked});
                DispatchFailed_.store(true);
                HoldPending();
                return;
            }
            const auto Posted=Reclaimer_->Post([Weak]
            {
                if(auto State=Weak.lock())
                {
                    const auto Result=State->CloseOnExecutor();
                    if(!Result)State->SaveCloseFailure(Result.error());
                }
            });
            if(!Posted)
            {
                SaveCloseFailure(Posted.error());
                DispatchFailed_.store(true);
                HoldPending();
            }
        }
        /** @brief 物理退休只在关闭已封口且 Native/协议 finalizer 全部归还后成立。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {return Closed_.load(std::memory_order_acquire) && Active_.load(std::memory_order_acquire)==0 && Barrier_.Active()==0;}
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override {return DispatchFailed_.load();}
        /** @brief 等待实际 I/O 与 finalizer completion；不可调度和关闭失败返回原类型化失败。 */
        [[nodiscard]] auto Drain()
            ->boost::asio::awaitable<std::expected<void,Prism::Fault::Failure>>
        {
            Close();
            if(!CanDispatch())
            {
                const auto Failure=Failure_.Load();
                if(Failure.Failed())co_return std::unexpected(Failure);
                const auto CloseFailure=LoadCloseFailure();
                if(CloseFailure)co_return std::unexpected(*CloseFailure);
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_await boost::asio::dispatch(Reclaimer_->Executor(),boost::asio::use_awaitable);
            const auto CloseResult=CloseOnExecutor();
            if(!CloseResult)co_return std::unexpected(CloseResult.error());
            const auto Drained=co_await Barrier_.Drain();
            if(!Drained)
            {
                const auto Failure=Failure_.Load();
                if(Failure.Failed())co_return std::unexpected(Failure);
                co_return std::unexpected(Drained.error());
            }
            const auto Failure=Failure_.Load();
            if(Failure.Failed())co_return std::unexpected(Failure);
            co_return std::expected<void,Prism::Fault::Failure>{};
        }
    private:
        [[nodiscard]] auto CloseOnExecutor()
            ->std::expected<void,Prism::Fault::Failure>
        {
            auto FirstFailure=std::optional<Prism::Fault::Failure>{};
            for(const auto& Owner:Connections_)
            {
                const auto Result=Owner->RequestClose();
                if(!Result && !FirstFailure)FirstFailure=Result.error();
            }
            if(FirstFailure)
            {
                SaveCloseFailure(*FirstFailure);
                return std::unexpected(LoadCloseFailure().value_or(*FirstFailure));
            }
            ClearCloseFailure();
            return {};
        }
        auto SaveCloseFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            if(Failure.Succeeded())Failure={Prism::Fault::Code::Blocked};
            if(CloseFailure_.load(std::memory_order_acquire))return;
            try
            {
                auto Stored=std::make_shared<const Prism::Fault::Failure>(Failure);
                std::shared_ptr<const Prism::Fault::Failure> Empty;
                (void)CloseFailure_.compare_exchange_strong(
                    Empty, std::move(Stored), std::memory_order_acq_rel);
            }
            catch(...)
            {
                DispatchFailed_.store(true);
            }
        }
        [[nodiscard]] auto LoadCloseFailure() const noexcept
            ->std::optional<Prism::Fault::Failure>
        {
            const auto Failure=CloseFailure_.load(std::memory_order_acquire);
            if(!Failure)return std::nullopt;
            return *Failure;
        }
        auto ClearCloseFailure() noexcept -> void
        {
            CloseFailure_.store({},std::memory_order_release);
        }
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::weak_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Lifecycle::DrainBarrier Barrier_;
        std::vector<std::shared_ptr<Prism::Contract::QuicConnectionOwner>> Connections_;
        std::atomic<std::size_t> Active_{0};
        std::atomic<bool> Closed_{false},DispatchFailed_{false};
        Prism::Fault::FailureState Failure_;
        std::atomic<std::shared_ptr<const Prism::Fault::Failure>> CloseFailure_{};
    };
}
