/**
 * @file Retirement.hpp
 * @brief Restls 传输链的控制结果、真实 Activity drain 与失败实物回收。
 * @details 同步请求路径等待关闭与每层 Activity 退栈；失败时由现有进程级
 *          ClosingStorage 保持完整传输链，并通过其原 executor reclaimer 重试。
 */
#pragma once

#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Restls::Detail
{
    namespace Net = boost::asio;

    /**
     * @brief 一条 Restls 所有传输层的最终关闭与真实退栈 owner。
     * @details 输入的根 SharedTransmission 保有整条 NextLayer 链；本对象另存每层
     *          CarrierActivity，防止跨 await 后只等待包装层而漏掉原生层。正常路径
     *          由调用协程等待 RetireAndDrain；失败实物交给该 executor 关联的
     *          ClosingStorage，后续 Retry 仍由同一个 ExecutorReclaimer 执行。若本 owner
     *          分配失败，则只由按值持有根传输的 cleanup 协程在原 executor 尝试清理；
     *          此路径返回失败，不宣称已进入 ClosingStorage。
     */
    class TransportRetirement final : public Prism::Executor::ClosingResource,
                                      public std::enable_shared_from_this<TransportRetirement>
    {
        struct Delivery final
        {
            std::shared_ptr<TransportRetirement> Owner;
            bool Invoked{false};

            explicit Delivery(std::shared_ptr<TransportRetirement> Value)
                : Owner(std::move(Value)) {}
            Delivery(Delivery &&Other) noexcept
                : Owner(std::move(Other.Owner)), Invoked(Other.Invoked) {}
            ~Delivery()
            {
                if (Owner && !Invoked)
                {
                    Owner->Record({Prism::Fault::Code::Blocked});
                    Owner->Scheduled_.store(false, std::memory_order_release);
                }
            }

            auto operator()() -> void
            {
                Invoked = true;
                Owner->StartRetry();
            }
        };

        struct Completion final
        {
            std::shared_ptr<TransportRetirement> Owner;
            bool Invoked{false};

            explicit Completion(std::shared_ptr<TransportRetirement> Value)
                : Owner(std::move(Value)) {}
            Completion(Completion &&Other) noexcept
                : Owner(std::move(Other.Owner)), Invoked(Other.Invoked) {}
            ~Completion()
            {
                if (Owner && !Invoked)
                {
                    Owner->Record({Prism::Fault::Code::Blocked});
                    Owner->Scheduled_.store(false, std::memory_order_release);
                }
            }

            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) -> void
            {
                Invoked = true;
                if (Exception)
                    Owner->Record(FailureFromExecutorException(
                        Owner->Reclaimer_->Executor(), Exception));
                else if (!Result && !Owner->Retired_.load(std::memory_order_acquire))
                    Owner->Record(Result.error());
                Owner->Scheduled_.store(false, std::memory_order_release);
                if (Owner->Retired_.load(std::memory_order_acquire))
                    Owner->Storage_->Collect();
            }
        };

    public:
        /**
         * @brief 在传输原 executor 关闭整条链并等待真实 Activity 退栈。
         * @param Transport 按值移交根传输；本协程与 cleanup awaitable 持有共享 owner。
         * @return 仅 Close 成功且所有 Activity Drain 成功才返回成功；其余保留首因。
         * @details 正常路径由 TransportRetirement 与 ClosingStorage 接管失败实物；
         *          owner 构造失败时，按值 cleanup awaitable 通过 co_spawn 切至原 executor，
         *          逐层重新取得 Activity，不跨挂起保存裸 NextLayer 指针。
         * @note 若 owner 构造和 fallback awaitable 投递都失败，则只返回失败并保持
         *       Transport 至结果交付；不在调用方 executor 执行任何控制或伪报清理成功。
         */
        [[nodiscard]] static auto RetireAndDrain(SharedTransmission Transport)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Transport)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});

            const auto Executor = Transport->Executor();
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            std::shared_ptr<TransportRetirement> Owner;
            std::optional<Prism::Fault::Failure> ConstructionFailure;
            std::exception_ptr ConstructionException;
            try
            {
                Owner = std::shared_ptr<TransportRetirement>(
                    new TransportRetirement(Transport));
            }
            catch (...)
            {
                ConstructionException = std::current_exception();
                ConstructionFailure = FailureFromException(ConstructionException);
            }
            if (!Owner)
            {
                try
                {
                    auto Cleanup = RetirePinnedOnExecutor(PinnedRetirementRequest{
                        std::move(Transport), *ConstructionFailure,
                        ConstructionException});
                    co_return co_await Net::co_spawn(
                        Executor, std::move(Cleanup), Net::use_awaitable);
                }
                catch (...)
                {
                    const auto SpawnFailure = FailureFromExecutorException(
                        Executor, std::current_exception());
                    if (!ConstructionFailure->Native && SpawnFailure.Native)
                        ConstructionFailure->Native = SpawnFailure.Native;
                    co_return std::unexpected(*ConstructionFailure);
                }
            }

            Owner->Storage_->Retain(Owner);
            std::expected<void, Prism::Fault::Failure> Result;
            try
            {
                Result = co_await Net::co_spawn(
                    Owner->Reclaimer_->Executor(), Owner->RetireOnExecutor(),
                    Net::use_awaitable);
            }
            catch (...)
            {
                const auto Failure = FailureFromExecutorException(
                    Executor, std::current_exception());
                Owner->Record(Failure);
                Owner->Hold();
                co_return std::unexpected(Failure);
            }
            if (!Owner->Retired_.load(std::memory_order_acquire))
            {
                if (!Result) Owner->Record(Result.error());
                Owner->Hold();
            }
            Owner->Storage_->Collect();
            co_return Result;
        }

        /** @brief 进程级回收重试入口；只投递到本传输链原 executor。 */
        auto RequestRetirement() -> void override
        {
            if (Retired_.load(std::memory_order_acquire) ||
                Scheduled_.exchange(true, std::memory_order_acq_rel))
                return;

            try
            {
                auto Result = Reclaimer_->Post(Delivery(shared_from_this()));
                if (!Result)
                {
                    Scheduled_.store(false, std::memory_order_release);
                    Record(Result.error());
                }
            }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                Record(FailureFromExecutorException(
                    Reclaimer_->Executor(), std::current_exception()));
            }
        }

        /** @brief 只在 Close 成功且全部真实 Activity 退栈后报告退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 原 executor 不可投递或回收命令无法交付时保留失败事实。 */
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_->CanDispatch();
        }

    private:
        /** @brief owner OOM 路径按值持有的清理请求与首个异常事实。 */
        struct PinnedRetirementRequest final
        {
            SharedTransmission Transport;
            Prism::Fault::Failure Primary;
            std::exception_ptr FirstException;
        };

        /** @brief 捕获 executor/coroutine 失败时保留 system_error 原生身份。 */
        [[nodiscard]] static auto FailureFromException(const std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure
        {
            try
            {
                if (Exception) std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error &Error)
            {
                const auto Native = static_cast<std::error_code>(Error.code());
                return {Prism::Fault::ToCode(Native), Native};
            }
            catch (const std::system_error &Error)
            {
                return {Prism::Fault::ToCode(Error.code()), Error.code()};
            }
            catch (...)
            {
                return {Prism::Fault::Code::IoError};
            }
            return {Prism::Fault::Code::IoError};
        }

        /** @brief 把捕获的 executor 异常交给已绑定的 Fatal owner，并保留 typed cause。 */
        [[nodiscard]] static auto FailureFromExecutorException(
            const Net::any_io_executor &Executor,
            const std::exception_ptr Exception) noexcept
            -> Prism::Fault::Failure
        {
            try
            {
                if (const auto Owner = Prism::Executor::ContextOwner::Find(Executor);
                    Owner && Owner->Fatal)
                    Owner->Fatal->Publish(Exception);
            }
            catch (...)
            {
            }
            return FailureFromException(Exception);
        }

        /** @brief 保留首因 Code，并记录尚未存在的首个原生 cause。 */
        static auto PreserveFailure(
            Prism::Fault::Failure &Primary,
            const Prism::Fault::Failure &Next) noexcept -> void
        {
            if (!Primary.Failed()) Primary = Next;
            else if (!Primary.Native && Next.Native) Primary.Native = Next.Native;
        }

        /** @brief 临时 cleanup owner 按值 pin 链并在 Transport 原 executor 完成清理。 */
        [[nodiscard]] static auto RetirePinnedOnExecutor(PinnedRetirementRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            auto &Transport = Request.Transport;
            auto &Primary = Request.Primary;
            try
            {
                const auto Cancel = Transport->Cancel();
                if (!Cancel) PreserveFailure(Primary, Cancel.error());
            }
            catch (...)
            {
                CaptureFailure(Request, std::current_exception());
            }
            try
            {
                const auto Close = Transport->Close();
                if (!Close) PreserveFailure(Primary, Close.error());
            }
            catch (...)
            {
                CaptureFailure(Request, std::current_exception());
            }
            for (std::size_t Index = 0;; ++Index)
            {
                bool Found = false;
                const auto Activity = ActivityAt(Transport, Index, Found);
                if (!Found) break;
                if (!Activity)
                {
                    PreserveFailure(
                        Primary, Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                    break;
                }
                try
                {
                    const auto Drained = co_await Activity->Drain();
                    if (!Drained) PreserveFailure(Primary, Drained.error());
                }
                catch (...)
                {
                    CaptureFailure(Request, std::current_exception());
                }
            }
            if (Request.FirstException)
                PublishFatal(Transport->Executor(), Request.FirstException);
            co_return std::unexpected(Primary);
        }

        /** @brief 保存清理异常原件与 typed 投影，继续尝试后续的真实关闭步骤。 */
        static auto CaptureFailure(
            PinnedRetirementRequest &Request,
            const std::exception_ptr Exception) noexcept -> void
        {
            if (!Request.FirstException) Request.FirstException = Exception;
            PreserveFailure(Request.Primary, FailureFromException(Exception));
        }

        /** @brief 把已尝试完清理的异常交给其原 execution_context Fatal owner。 */
        static auto PublishFatal(
            const Net::any_io_executor &Executor,
            const std::exception_ptr Exception) noexcept -> void
        {
            try
            {
                if (const auto Owner = Prism::Executor::ContextOwner::Find(Executor);
                    Owner && Owner->Fatal)
                    Owner->Fatal->Publish(Exception);
            }
            catch (...)
            {
            }
        }

        /** @brief 每次无挂起地重新取得指定层 Activity，不跨 await 保存层裸指针。 */
        [[nodiscard]] static auto ActivityAt(
            const SharedTransmission &Transport,
            std::size_t Index,
            bool &Found) noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity>
        {
            auto *Layer = Transport.get();
            while (Layer && Index != 0)
            {
                Layer = Layer->NextLayer();
                --Index;
            }
            Found = Layer != nullptr;
            if (!Layer) return {};
            return Layer->Activity();
        }

        explicit TransportRetirement(SharedTransmission Transport)
            : Transport_(std::move(Transport)),
              Storage_(Prism::Executor::ContextOwner::Storage(Transport_->Executor())),
              Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Transport_->Executor()))
        {
            for (auto *Layer = Transport_.get(); Layer; Layer = Layer->NextLayer())
                Activities_.push_back(Layer->Activity());
        }

        /** @brief 同步请求方和回收 owner 共用一次串行关闭/Drain 实现。 */
        [[nodiscard]] auto RetireOnExecutor()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            std::expected<void, Prism::Fault::Failure> FirstFailure;
            std::exception_ptr FirstException;
            std::expected<void, Prism::Fault::Failure> Cancel;
            try
            {
                Cancel = Transport_->Cancel();
            }
            catch (...)
            {
                FirstException = std::current_exception();
                Cancel = std::unexpected(FailureFromException(FirstException));
            }
            if (!Cancel) FirstFailure = std::unexpected(Cancel.error());
            std::expected<void, Prism::Fault::Failure> Close;
            try
            {
                Close = Transport_->Close();
            }
            catch (...)
            {
                const auto Exception = std::current_exception();
                if (!FirstException) FirstException = Exception;
                Close = std::unexpected(FailureFromException(Exception));
            }
            if (!Close && FirstFailure) FirstFailure = std::unexpected(Close.error());

            bool AllDrained = true;
            for (const auto &Activity : Activities_)
            {
                std::expected<void, Prism::Fault::Failure> Drained;
                try
                {
                    Drained = co_await Activity->Drain();
                }
                catch (...)
                {
                    const auto Exception = std::current_exception();
                    if (!FirstException) FirstException = Exception;
                    Drained = std::unexpected(FailureFromException(Exception));
                }
                if (!Drained)
                {
                    AllDrained = false;
                    if (FirstFailure) FirstFailure = std::unexpected(Drained.error());
                }
            }

            if (Close && AllDrained)
            {
                Retired_.store(true, std::memory_order_release);
                Transport_.reset();
                Activities_.clear();
            }
            if (FirstException)
                PublishFatal(Reclaimer_->Executor(), FirstException);
            if (!FirstFailure) co_return std::unexpected(FirstFailure.error());
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 原 executor 上启动失败资源的异步重试，并让完成通知持有本 owner。 */
        auto StartRetry() -> void
        {
            auto Self = shared_from_this();
            try
            {
                Net::co_spawn(Reclaimer_->Executor(), RetireOnExecutor(), Completion(std::move(Self)));
            }
            catch (...)
            {
                Record(FailureFromExecutorException(
                    Reclaimer_->Executor(), std::current_exception()));
                Scheduled_.store(false, std::memory_order_release);
            }
        }

        /** @brief 保留首个关闭或 Drain cause，不覆盖更早的 I/O 失败。 */
        auto Record(const Prism::Fault::Failure Failure) noexcept -> void
        {
            Failure_.TrySet(Failure);
            Storage_->Retain(shared_from_this());
        }

        /** @brief 把尚未确认退休的真实传输链交给既有进程级 owner。 */
        auto Hold() noexcept -> void
        {
            Storage_->Retain(shared_from_this());
            RequestRetirement();
        }

        SharedTransmission Transport_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>> Activities_;
        Prism::Fault::FailureState Failure_;
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Retired_{false};
    };
}
