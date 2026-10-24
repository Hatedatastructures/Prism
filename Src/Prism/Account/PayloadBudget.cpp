/** @file PayloadBudget.cpp @brief 逻辑有效载荷 permit 的 move 与结算实现。 */
#include <Prism/Contract/Account/PayloadBudget.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Contract
{
    PayloadPermit::PayloadPermit(
        std::uint64_t Bytes,
        std::shared_ptr<PayloadSettlement> Owner) noexcept
        : Bytes_(Bytes), Owner_(std::move(Owner))
    {
    }

    PayloadPermit::PayloadPermit(PayloadPermit &&Other) noexcept
        : Bytes_(std::exchange(Other.Bytes_, 0)), Owner_(std::move(Other.Owner_))
    {
    }

    auto PayloadPermit::operator=(PayloadPermit &&Other) noexcept -> PayloadPermit &
    {
        if (this != &Other)
        {
            Finish(0);
            Bytes_ = std::exchange(Other.Bytes_, 0);
            Owner_ = std::move(Other.Owner_);
        }
        return *this;
    }

    PayloadPermit::~PayloadPermit()
    {
        Finish(0);
    }

    auto PayloadPermit::Finish(const std::uint64_t Transferred) noexcept -> void
    {
        if (Owner_) Owner_->Complete(Bytes_, (std::min)(Transferred, Bytes_));
        Owner_.reset();
        Bytes_ = 0;
    }
}
