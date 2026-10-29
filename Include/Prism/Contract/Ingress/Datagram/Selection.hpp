/** @file Selection.hpp @brief 单包共享的同代 raw/QUIC ingress 选择。 */
#pragma once

#include <Prism/Contract/Ingress/QuicConnection.hpp>
#include <Prism/Contract/Ingress/Datagram/Raw.hpp>

#include <memory>
#include <utility>

namespace Prism::Contract
{
    /** @brief 将一代 raw 与 QUIC binding 固定为同一 packet admission 选择。 */
    class DatagramIngressSelection final
    {
    public:
        struct Options final
        {
            Prism::Foundation::GenerationPin Generation;
            std::shared_ptr<Prism::Foundation::GenerationUseState> UseState;
            std::shared_ptr<const RawDatagramIngressSnapshot> Raw;
            std::shared_ptr<const QuicIngressBindingSnapshot> Quic;
        };

        explicit DatagramIngressSelection(Options Value)
            : Generation_(std::move(Value.Generation)), UseState_(std::move(Value.UseState)),
              Raw_(std::move(Value.Raw)), Quic_(std::move(Value.Quic))
        {
        }

        /** @brief 检查同代 raw/QUIC snapshot 与 generation owner 身份。 */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Generation_ && UseState_ && Raw_ && Quic_ &&
                Raw_->Generation() == Generation_->Id() &&
                Raw_->UseStateOwner() == UseState_ && Quic_->IsValid() &&
                Quic_->GenerationOwner() == Generation_ && Quic_->UseState() == UseState_;
        }

        /** @brief 检查完整 pointer identity，阻止 raw 与 QUIC 来自不同发布代次。 */
        [[nodiscard]] auto Matches(
            const Prism::Foundation::GenerationPin& Generation,
            const std::shared_ptr<Prism::Foundation::GenerationUseState>& UseState) const noexcept -> bool
        {
            return IsValid() && Generation_ == Generation && UseState_ == UseState;
        }

        [[nodiscard]] auto GenerationOwner() const noexcept
            -> const Prism::Foundation::GenerationPin& { return Generation_; }
        [[nodiscard]] auto UseState() const noexcept
            -> const std::shared_ptr<Prism::Foundation::GenerationUseState>& { return UseState_; }
        [[nodiscard]] auto Raw() const noexcept
            -> const std::shared_ptr<const RawDatagramIngressSnapshot>& { return Raw_; }
        [[nodiscard]] auto Quic() const noexcept
            -> const std::shared_ptr<const QuicIngressBindingSnapshot>& { return Quic_; }

    private:
        const Prism::Foundation::GenerationPin Generation_;
        const std::shared_ptr<Prism::Foundation::GenerationUseState> UseState_;
        const std::shared_ptr<const RawDatagramIngressSnapshot> Raw_;
        const std::shared_ptr<const QuicIngressBindingSnapshot> Quic_;
    };
}
