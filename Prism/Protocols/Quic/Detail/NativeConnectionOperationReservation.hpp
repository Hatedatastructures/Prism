/**
 * @file NativeConnectionOperationReservation.hpp
 * @brief QUIC 连接运行预约的 RAII owner。
 * @details 持有连接 shared owner，并在其 loop barrier 上成对 Enter/Leave。
 */
#pragma once

#include <memory>
#include <utility>

namespace Prism::Quic::Detail
{
    template <class Owner>
    class NativeConnectionOperationReservation final
    {
    public:
        explicit NativeConnectionOperationReservation(std::shared_ptr<Owner> OwnerValue) noexcept
            : Owner_(std::move(OwnerValue)), Entered_(Owner_ && Owner_->Loops_.Enter())
        {
        }

        NativeConnectionOperationReservation(const NativeConnectionOperationReservation &) = delete;
        auto operator=(const NativeConnectionOperationReservation &)
            -> NativeConnectionOperationReservation & = delete;

        NativeConnectionOperationReservation(NativeConnectionOperationReservation &&Other) noexcept
            : Owner_(std::move(Other.Owner_)), Entered_(std::exchange(Other.Entered_, false))
        {
        }

        ~NativeConnectionOperationReservation()
        {
            if (Entered_)
            {
                Owner_->Loops_.Leave();
            }
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return Entered_;
        }

    private:
        std::shared_ptr<Owner> Owner_;
        bool Entered_{false};
    };
}
