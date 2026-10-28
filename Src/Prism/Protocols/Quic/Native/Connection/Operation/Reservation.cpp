/**
 * @file Reservation.cpp
 * @brief QUIC Native connection操作预约的实际 RAII 实现。
 */
#include <Prism/Protocols/Quic/Native/Connection.hpp>

#include <memory>
#include <utility>

namespace Prism::Quic::Detail
{
    NativeConnection::WritePermitRelease::WritePermitRelease(
        NotifyChannel &Permit) noexcept
        : Permit_(Permit)
    {
    }

    NativeConnection::WritePermitRelease::~WritePermitRelease() noexcept
    {
        (void)Permit_.try_send(boost::system::error_code{});
    }

    NativeConnection::OperationReservation::OperationReservation(
        std::shared_ptr<NativeConnection> OwnerValue) noexcept
        : Owner_(std::move(OwnerValue)),
          Entered_(Owner_ && Owner_->Loops_.Enter())
    {
    }

    NativeConnection::OperationReservation::OperationReservation(
        OperationReservation&& Other) noexcept
        : Owner_(std::move(Other.Owner_)),
          Entered_(std::exchange(Other.Entered_, false))
    {
    }

    NativeConnection::OperationReservation::~OperationReservation() noexcept
    {
        if (Entered_)
        {
            Owner_->Loops_.Leave();
        }
    }

    [[nodiscard]] NativeConnection::OperationReservation::operator bool() const noexcept
    {
        return Entered_;
    }
}
