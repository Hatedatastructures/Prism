/**
 * @file AcceptedClientTransport.hpp
 * @brief TrustTunnel client accepted H2 stream 的 typed close 回执前门。
 */
#pragma once

#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <Preview/Protocols/Trusttunnel/Detail/AcceptedCarrierActivity.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <utility>

namespace Preview::Trusttunnel::Detail
{
    /**
     * @brief 保持 client driver、writer、TLS 与 H2 stream owner 到真实退栈。
     * @details Activity 把正式 close receipt 交给原 executor 的 owner Drain；远端 END_STREAM
     *          只封止接收，不退休本端写队列。外层 close 槽只在全部层物理完成后归还。
     */
    template<class Owner>
    class AcceptedClientTransport final : public Preview::Transmission
    {
    public:
        explicit AcceptedClientTransport(std::shared_ptr<Owner> Value)
            : Preview::Transmission(Value->Executor()),
              Executor_(Value->Executor()), Owner_(std::move(Value)),
              Activity_(std::make_shared<AcceptedCarrierActivity<Owner>>(
                  Preview::Transmission::Activity(), Owner_, CloseReceipt()))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto RequiresExternalCloseReceipt() const noexcept -> bool override
        {
            return true;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Owner_->Transport)
            {
                Preview::Transport::Detail::PostResult(
                    Executor_, std::move(Handler),
                    {0, {Preview::Fault::Code::Canceled}});
                return;
            }
            Owner_->Transport->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Owner_->Transport)
            {
                Preview::Transport::Detail::PostResult(
                    Executor_, std::move(Handler),
                    {0, {Preview::Fault::Code::Canceled}});
                return;
            }
            Owner_->Transport->WriteSome(Buffer, std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!Owner_->Transport)
            {
                Preview::Transport::Detail::PostResult(
                    Executor_, std::move(Handler),
                    {0, {Preview::Fault::Code::Canceled}});
                return;
            }
            Owner_->Transport->WriteShutdown(std::move(Handler));
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Activity_->Seal();
            return Owner_->Close();
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Owner_->Cancel();
        }

        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
        {
            if (Owner_->Transport) Owner_->Transport->SetTimeout(Timeout);
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Owner_->IsRetired() && Owner_->Transport && Owner_->Transport->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission* override
        {
            return Owner_->Transport.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission* override
        {
            return Owner_->Transport.get();
        }

    private:
        ExecutorType Executor_;
        std::shared_ptr<Owner> Owner_;
        std::shared_ptr<AcceptedCarrierActivity<Owner>> Activity_;
    };
}