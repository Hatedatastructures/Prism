/**
 * @file Retirement.hpp
 * @brief ShadowTLS 传输链的控制结果、真实 Activity drain 与失败实物回收。
 * @details 同步请求路径等待关闭与每层 Activity 退栈；失败时由现有进程级
 *          ClosingStorage 保持完整传输链，并通过其原 executor reclaimer 重试。
 */
#pragma once

#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Protocols/Shadowtls/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

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

namespace Preview::Shadowtls::Detail
{
    namespace Net = boost::asio;

    /**
     * @brief 一条 ShadowTLS 所有传输层的最终关闭与真实退栈 owner。
     * @details 输入的根 SharedTransmission 保有整条 NextLayer 链；本对象另存每层
     *          CarrierActivity，防止跨 await 后只等待包装层而漏掉原生层。正常路径
     *          由调用协程等待 RetireAndDrain；失败实物交给该 executor 关联的
     *          ClosingStorage，后续 Retry 仍由同一个 ExecutorReclaimer 执行。
     */
    class TransportRetirement final : public Preview::Executor::ClosingResource,
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
                    Owner->Record({Preview::Fault::Code::Blocked});
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
                    Owner->Record({Preview::Fault::Code::Blocked});
                    Owner->Scheduled_.store(false, std::memory_order_release);
                }
            }

            auto operator()(
                std::exception_ptr Exception,
                Result<void> RetireResult) -> void
            {
                Invoked = true;
                if (Exception)
                    Owner->Record(FailureFromExecutorException(
                        Owner->Reclaimer_->Executor(), Exception));
                else if (!RetireResult && !Owner->Retired_.load(std::memory_order_acquire))
                    Owner->Record(RetireResult.error());
                Owner->Scheduled_.store(false, std::memory_order_release);
                if (Owner->Retired_.load(std::memory_order_acquire))
                    Owner->Storage_->Collect();
            }
        };

    public:
        /** @brief 关闭并等待所有层退栈；失败保留首因，且不释放未退休实物。 */
        [[nodiscard]] static auto RetireAndDrain(SharedTransmission Transport)
            -> Net::awaitable<Result<void>>
        {
            if (!Transport)
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument, {}, 0});

            const auto Executor = Transport->Executor();
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            std::shared_ptr<TransportRetirement> Owner;
            std::optional<Failure> ConstructionFailure;
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
                        std::move(Transport), *ConstructionFailure, ConstructionException});
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
            Result<void> RetireResult;
            try
            {
                RetireResult = co_await Net::co_spawn(
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
                if (!RetireResult) Owner->Record(RetireResult.error());
                Owner->Hold();
            }
            Owner->Storage_->Collect();
            co_return RetireResult;
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
                    Record(FailureFromFault(Result.error()));
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
        /** @brief 分配失败时按值持有真实链及原始异常的临时 retirement 请求。 */
        struct PinnedRetirementRequest final
        {
            SharedTransmission Transport;
            Failure Primary;
            std::exception_ptr FirstException;
        };

        /** @brief 将 executor 异常映射为协议 Failure，并保留系统错误 Native。 */
        [[nodiscard]] static auto FailureFromException(
            const std::exception_ptr Exception) noexcept -> Failure
        {
            try
            {
                if (Exception) std::rethrow_exception(Exception);
            }
            catch (const boost::system::system_error &Error)
            {
                const auto Native = static_cast<std::error_code>(Error.code());
                return {Preview::Fault::ToCode(Native), Native, 0};
            }
            catch (const std::system_error &Error)
            {
                return {Preview::Fault::ToCode(Error.code()), Error.code(), 0};
            }
            catch (...)
            {
                return {Preview::Fault::Code::IoError, {}, 0};
            }
            return {Preview::Fault::Code::IoError, {}, 0};
        }

        /** @brief 保留首个业务分类与尚未出现的首个 Native cause。 */
        static auto PreserveFailure(Failure &Primary, const Failure &Next) noexcept -> void
        {
            if (!Primary.Failed()) Primary = Next;
            else if (!Primary.Native && Next.Native) Primary.Native = Next.Native;
        }

        /** @brief 把异常发布到已绑定的 execution_context Fatal owner。 */
        static auto PublishFatal(
            const Net::any_io_executor &Executor,
            const std::exception_ptr Exception) noexcept -> void
        {
            try
            {
                if (const auto Context = Preview::Executor::ContextOwner::Find(Executor);
                    Context && Context->Fatal)
                    Context->Fatal->Publish(Exception);
            }
            catch (...)
            {
            }
        }

        /** @brief 发布已清理异常并保留可返回给协议 caller 的 typed projection。 */
        [[nodiscard]] static auto FailureFromExecutorException(
            const Net::any_io_executor &Executor,
            const std::exception_ptr Exception) noexcept -> Failure
        {
            PublishFatal(Executor, Exception);
            return FailureFromException(Exception);
        }

        /** @brief 保存 cleanup 异常原件与协议结果，继续尝试后续步骤。 */
        static auto CaptureFailure(
            PinnedRetirementRequest &Request,
            const std::exception_ptr Exception) noexcept -> void
        {
            if (!Request.FirstException) Request.FirstException = Exception;
            PreserveFailure(Request.Primary, FailureFromException(Exception));
        }

        /** @brief owner 分配失败后在原 executor 上清理按值 pin 的传输链。 */
        [[nodiscard]] static auto RetirePinnedOnExecutor(PinnedRetirementRequest Request)
            -> Net::awaitable<Result<void>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            auto &Transport = Request.Transport;
            auto &Primary = Request.Primary;

            std::expected<void, Preview::Fault::Failure> Cancel;
            try
            {
                Cancel = Transport->Cancel();
            }
            catch (...)
            {
                CaptureFailure(Request, std::current_exception());
                Cancel = std::unexpected(Preview::Fault::Failure{
                    Primary.Code, Primary.Native});
            }
            if (!Cancel) PreserveFailure(Primary, FailureFromFault(Cancel.error()));

            std::expected<void, Preview::Fault::Failure> Close;
            try
            {
                Close = Transport->Close();
            }
            catch (...)
            {
                CaptureFailure(Request, std::current_exception());
                Close = std::unexpected(Preview::Fault::Failure{
                    Primary.Code, Primary.Native});
            }
            if (!Close) PreserveFailure(Primary, FailureFromFault(Close.error()));

            for (std::size_t Index = 0;; ++Index)
            {
                bool Found = false;
                const auto Activity = ActivityAt(Transport, Index, Found);
                if (!Found) break;
                if (!Activity)
                {
                    PreserveFailure(Primary, Failure{
                        Preview::Fault::Code::InvalidArgument, {}, 0});
                    break;
                }
                try
                {
                    const auto Drained = co_await Activity->Drain();
                    if (!Drained) PreserveFailure(Primary, FailureFromFault(Drained.error()));
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

        /** @brief 每次同步重走 NextLayer 链，只返回共享 Activity 不保留裸层指针。 */
        [[nodiscard]] static auto ActivityAt(
            const SharedTransmission &Transport,
            std::size_t Index,
            bool &Found) noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity>
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
              Storage_(Preview::Executor::ContextOwner::Storage(Transport_->Executor())),
              Reclaimer_(std::make_shared<Preview::Executor::ExecutorReclaimer>(Transport_->Executor()))
        {
            for (auto *Layer = Transport_.get(); Layer; Layer = Layer->NextLayer())
                Activities_.push_back(Layer->Activity());
        }

        /** @brief 同步请求方和回收 owner 共用一次串行关闭/Drain 实现。 */
        [[nodiscard]] auto RetireOnExecutor()
            -> Net::awaitable<Result<void>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            Result<void> FirstFailure;
            std::exception_ptr FirstException;
            std::expected<void, Preview::Fault::Failure> Cancel;
            try
            {
                Cancel = Transport_->Cancel();
            }
            catch (...)
            {
                FirstException = std::current_exception();
                const auto Failure = FailureFromException(FirstException);
                Cancel = std::unexpected(
                    Preview::Fault::Failure{Failure.Code, Failure.Native});
            }
            if (!Cancel) FirstFailure = std::unexpected(FailureFromFault(Cancel.error()));
            std::expected<void, Preview::Fault::Failure> Close;
            try
            {
                Close = Transport_->Close();
            }
            catch (...)
            {
                const auto Exception = std::current_exception();
                if (!FirstException) FirstException = Exception;
                const auto Failure = FailureFromException(Exception);
                Close = std::unexpected(Preview::Fault::Failure{Failure.Code, Failure.Native});
            }
            if (!Close && FirstFailure) FirstFailure = std::unexpected(FailureFromFault(Close.error()));

            bool AllDrained = true;
            for (const auto &Activity : Activities_)
            {
                std::expected<void, Preview::Fault::Failure> Drained;
                try
                {
                    Drained = co_await Activity->Drain();
                }
                catch (...)
                {
                    const auto Exception = std::current_exception();
                    if (!FirstException) FirstException = Exception;
                    const auto Failure = FailureFromException(Exception);
                    Drained = std::unexpected(
                        Preview::Fault::Failure{Failure.Code, Failure.Native});
                }
                if (!Drained)
                {
                    AllDrained = false;
                    if (FirstFailure) FirstFailure = std::unexpected(FailureFromFault(Drained.error()));
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
            co_return Result<void>{};
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
        auto Record(const Shadowtls::Failure Failure) noexcept -> void
        {
            Failure_.TrySet(ToFaultFailure(Failure));
            Storage_->Retain(shared_from_this());
        }

        /** @brief 把尚未确认退休的真实传输链交给既有进程级 owner。 */
        auto Hold() noexcept -> void
        {
            Storage_->Retain(shared_from_this());
            RequestRetirement();
        }

        SharedTransmission Transport_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>> Activities_;
        Preview::Fault::FailureState Failure_;
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Retired_{false};
    };
}
