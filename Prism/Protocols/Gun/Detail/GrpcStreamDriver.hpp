/**
 * @file GrpcStreamDriver.hpp
 * @brief gRPC stream HTTP/2 读写驱动的启动与完成所有者。
 * @details 每个 driver 在投递前登记，在协程真实退栈后归还活动计数。
 */
#pragma once

#include <Prism/Protocols/Gun/Detail/GrpcStreamOwner.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>

#include <exception>
#include <memory>
#include <utility>

namespace Prism::Gun::Grpc::Detail
{
    /**
     * @class GrpcStreamDriver
     * @brief 唯一持有并启动 gRPC stream 的双向帧驱动。
     */
    struct GrpcStreamDriver final
    {
        /** @brief 启动唯一读驱动，并登记其真实协程寿命。 */
        static auto StartRead(const std::shared_ptr<StreamTransport> &Owner) -> void
        {
            if (!Owner->Activity_->StartDriver())
            {
                const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
                Owner->RecordFailure(Failure);
                Owner->SignalReady(Failure);
                return;
            }
            try
            {
                Net::co_spawn(Owner->Executor(), Owner->ReadLoop(),
                    [Owner](std::exception_ptr Exception)
                    { Complete(Owner, std::move(Exception)); });
            }
            catch (...)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                Owner->RecordFailure(Failure);
                Owner->SignalReady(Failure);
                Owner->Activity_->CompleteDriver(Failure);
            }
        }

        /** @brief 启动唯一写驱动，并登记其真实协程寿命。 */
        static auto StartWrite(const std::shared_ptr<StreamTransport> &Owner) -> void
        {
            if (!Owner->Activity_->StartDriver())
            {
                const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
                Owner->RecordFailure(Failure);
                Owner->SignalReady(Failure);
                return;
            }
            try
            {
                Net::co_spawn(Owner->Executor(), Owner->WriteLoop(),
                    [Owner](std::exception_ptr Exception)
                    { Complete(Owner, std::move(Exception)); });
            }
            catch (...)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                Owner->RecordFailure(Failure);
                Owner->SignalReady(Failure);
                Owner->Activity_->CompleteDriver(Failure);
            }
        }

    private:
        static auto Complete(
            const std::shared_ptr<StreamTransport> &Owner,
            std::exception_ptr Exception) noexcept -> void
        {
            if (Exception)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::move(Exception));
                Owner->RecordFailure(Failure);
                Owner->SignalReady(Failure);
            }
            Owner->Activity_->CompleteDriver(Owner->Activity_->Failure());
        }
    };
} // namespace Prism::Gun::Grpc::Detail
