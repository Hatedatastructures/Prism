/**
 * @file AcceptedTransport.hpp
 * @brief XHTTP accepted stream 的唯一传输与关闭回执。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/CarrierCloseReceipt.hpp>
#include <Prism/Protocols/Xhttp/Detail/FactoryRetirement.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/this_coro.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <utility>

namespace Prism::Xhttp::Detail
{
    template<class State>
    struct AcceptedActivityResources final
    {
        std::shared_ptr<Prism::Contract::CarrierActivity> Front;
        std::shared_ptr<FactoryRetirement<State>> Retirement;
        Prism::SharedTransmission Inner;
        std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt;
    };

    template<class State>
    class AcceptedActivity final : public Prism::Contract::CarrierActivity
    {
        using RetirementType = FactoryRetirement<State>;

        struct Owner final
        {
            explicit Owner(AcceptedActivityResources<State> Resources)
                : Front(std::move(Resources.Front)),
                  Retirement(std::move(Resources.Retirement)),
                  Inner(std::move(Resources.Inner)), Receipt(std::move(Resources.Receipt))
            {
            }

            std::shared_ptr<Prism::Contract::CarrierActivity> Front;
            std::shared_ptr<RetirementType> Retirement;
            Prism::SharedTransmission Inner;
            std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt;
        };

    public:
        explicit AcceptedActivity(AcceptedActivityResources<State> Resources)
            : Owner_(std::make_shared<Owner>(std::move(Resources)))
        {
        }

        auto Seal() noexcept -> void override
        {
            Owner_->Front->Seal();
        }

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return Owner_->Front->Executor();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Owner_->Retirement->IsRetired() && Owner_->Front->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            return DrainOwner(Owner_);
        }

    private:
        [[nodiscard]] static auto DrainOwner(std::shared_ptr<Owner> Value)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            co_await boost::asio::this_coro::reset_cancellation_state(
                boost::asio::disable_cancellation());
            Value->Front->Seal();

            Prism::Fault::Failure Cause;
            const auto Closed = Value->Inner->Close();
            if (!Closed) Cause = Closed.error();
            const auto Failure = co_await Value->Retirement->Retire(Cause);
            if (!Value->Retirement->IsRetired())
            {
                if (Failure.Failed()) co_return std::unexpected(Failure);
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }

            Value->Receipt->ConfirmExternalClose();
            const auto Front = co_await Value->Front->Drain();
            auto FirstFailure = Failure;
            if (!Front && FirstFailure.Succeeded())
                FirstFailure = Front.error();
            if (!Value->Front->IsRetired() && FirstFailure.Succeeded())
                FirstFailure = {Prism::Fault::Code::Blocked};
            if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        std::shared_ptr<Owner> Owner_;
    };

    /**
     * @brief 把成功接受的 XHTTP 私有传输与其预建状态退休 ticket 合成唯一入口。
     * @details wrapper 持 ticket 与传输；ticket 中的状态只反向持有内层传输，不引用 wrapper，
     *          因而成功 accepted owner 没有引用环。关闭由内层 State/FactoryRetirement 在其原
     *          executor 执行，END_STREAM 仍沿原协议 writer，所有 Native Failure 由 Activity Drain
     *          返回；外层 close 槽仅在真实 ticket 退休后交付。
     */
    template<class State>
    class AcceptedTransport final : public Prism::Transmission
    {
    public:
        AcceptedTransport(
            std::shared_ptr<FactoryRetirement<State>> Retirement,
            Prism::SharedTransmission Inner)
            : Prism::Transmission(Inner->Executor()),
              Inner_(std::move(Inner)),
              Activity_(std::make_shared<AcceptedActivity<State>>(
                  AcceptedActivityResources<State>{
                      Prism::Transmission::Activity(), std::move(Retirement),
                      Inner_, CloseReceipt()}))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->WriteSome(Buffer, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Inner_->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Activity_->Seal();
            return Inner_->Close();
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Inner_->Cancel();
        }

        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
        {
            Inner_->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Inner_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission* override
        {
            return Inner_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission* override
        {
            return Inner_.get();
        }

    private:
        Prism::SharedTransmission Inner_;
        std::shared_ptr<AcceptedActivity<State>> Activity_;
    };
}
