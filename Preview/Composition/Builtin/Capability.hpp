#pragma once

#include <cstdint>
#include <initializer_list>

namespace Preview::Composition::Builtin
{

    /** @brief Builtin 可以声明或要求的能力位。 */
    enum class Capability : std::uint64_t
    {
        None = 0,
        Core = std::uint64_t{1} << 0,
        Request = std::uint64_t{1} << 1,
        Memory = std::uint64_t{1} << 2,
        Executor = std::uint64_t{1} << 3,
        Cancellation = std::uint64_t{1} << 4,
        Transport = std::uint64_t{1} << 5,
        Stream = std::uint64_t{1} << 6,
        Datagram = std::uint64_t{1} << 7,
        Tls = std::uint64_t{1} << 8,
        Multiplex = std::uint64_t{1} << 9,
        Inbound = std::uint64_t{1} << 10,
        Outbound = std::uint64_t{1} << 11,
        Observability = std::uint64_t{1} << 12,
        Session = std::uint64_t{1} << 13,
        Quic = std::uint64_t{1} << 14,
        Alpn = std::uint64_t{1} << 15,
        Dns = std::uint64_t{1} << 16,
        Route = std::uint64_t{1} << 17,
        Dial = std::uint64_t{1} << 18,
        Front = std::uint64_t{1} << 19,
        Operation = std::uint64_t{1} << 20,

        Network = Transport,
        Tcp = Stream,
        Udp = Datagram,
        Mux = Multiplex,
        Metrics = Observability,
    };

    /** @brief 自动补齐前置能力的不可变值集合。 */
    class CapabilitySet final
    {
    public:
        constexpr CapabilitySet() noexcept = default;

        constexpr explicit CapabilitySet(const Capability Value) noexcept
        {
            Add(Value);
        }

        constexpr CapabilitySet(const std::initializer_list<Capability> Values) noexcept
        {
            for (const auto Value : Values)
            {
                Add(Value);
            }
        }

        constexpr auto Add(const Capability Value) noexcept -> CapabilitySet &
        {
            if (Value == Capability::None)
            {
                return *this;
            }

            DeclaredMask_ |= MaskOf(Value);
            Mask_ = ClosureMask(Mask_ | MaskOf(Value));
            return *this;
        }

        [[nodiscard]] constexpr auto Contains(const Capability Value) const noexcept -> bool
        {
            return (Mask_ & MaskOf(Value)) == MaskOf(Value);
        }

        [[nodiscard]] constexpr auto Includes(const CapabilitySet Required) const noexcept -> bool
        {
            return (Mask_ & Required.Mask_) == Required.Mask_;
        }

        [[nodiscard]] constexpr auto Missing(const CapabilitySet Required) const noexcept
            -> CapabilitySet
        {
            CapabilitySet Result;
            Result.Mask_ = Required.Mask_ & ~Mask_;
            return Result;
        }

        [[nodiscard]] constexpr auto Empty() const noexcept -> bool
        {
            return Mask_ == 0;
        }

        [[nodiscard]] constexpr auto Mask() const noexcept -> std::uint64_t
        {
            return Mask_;
        }

        /** @brief 获取显式声明的能力位，不包含依赖闭包补齐的能力。 */
        [[nodiscard]] constexpr auto DeclaredMask() const noexcept -> std::uint64_t
        {
            return DeclaredMask_;
        }

        /** @brief 检查能力是否被直接声明，而非仅由依赖闭包获得。 */
        [[nodiscard]] constexpr auto Declares(const Capability Value) const noexcept -> bool
        {
            const auto RequiredMask = MaskOf(Value);
            return (DeclaredMask_ & RequiredMask) == RequiredMask;
        }

        friend constexpr auto operator==(const CapabilitySet &Left,
                                         const CapabilitySet &Right) noexcept -> bool
        {
            return Left.Mask_ == Right.Mask_;
        }

        friend constexpr auto operator|(CapabilitySet Left, const CapabilitySet Right) noexcept
            -> CapabilitySet
        {
            return FromMasks(Left.DeclaredMask_ | Right.DeclaredMask_,
                             Left.Mask_ | Right.Mask_);
        }

        friend constexpr auto operator|=(CapabilitySet &Left, const CapabilitySet Right) noexcept
            -> CapabilitySet &
        {
            Left.DeclaredMask_ |= Right.DeclaredMask_;
            Left.Mask_ = ClosureMask(Left.Mask_ | Right.Mask_);
            return Left;
        }

    private:
        static constexpr auto MaskOf(const Capability Value) noexcept -> std::uint64_t
        {
            return static_cast<std::uint64_t>(Value);
        }

        static constexpr auto ClosureMask(std::uint64_t MaskValue) noexcept -> std::uint64_t
        {
            const auto TransportMask = MaskOf(Capability::Transport);
            const auto StreamMask = MaskOf(Capability::Stream);
            const auto DatagramMask = MaskOf(Capability::Datagram);
            const auto TlsMask = MaskOf(Capability::Tls);
            const auto MultiplexMask = MaskOf(Capability::Multiplex);
            const auto QuicMask = MaskOf(Capability::Quic);
            const auto AlpnMask = MaskOf(Capability::Alpn);
            const auto DialMask = MaskOf(Capability::Dial);
            const auto FrontMask = MaskOf(Capability::Front);
            const auto OperationMask = MaskOf(Capability::Operation);
            const auto DirectionMask = MaskOf(Capability::Inbound) | MaskOf(Capability::Outbound);
            const auto SessionMask = MaskOf(Capability::Session);

            for (;;)
            {
                const auto Previous = MaskValue;
                if ((MaskValue & (StreamMask | DatagramMask | DirectionMask)) != 0)
                {
                    MaskValue |= TransportMask;
                }
                if ((MaskValue & (TlsMask | MultiplexMask)) != 0)
                {
                    MaskValue |= StreamMask;
                }
                if ((MaskValue & QuicMask) != 0)
                {
                    MaskValue |= TransportMask | StreamMask | DatagramMask | TlsMask;
                }
                if ((MaskValue & AlpnMask) != 0)
                {
                    MaskValue |= TlsMask | StreamMask | TransportMask;
                }
                if ((MaskValue & DialMask) != 0)
                {
                    MaskValue |= TransportMask | MaskOf(Capability::Dns) |
                                 MaskOf(Capability::Route);
                }
                if ((MaskValue & FrontMask) != 0)
                {
                    MaskValue |= TransportMask | StreamMask | DatagramMask |
                                 MaskOf(Capability::Executor) |
                                 MaskOf(Capability::Cancellation);
                }
                if ((MaskValue & OperationMask) != 0)
                {
                    MaskValue |= MaskOf(Capability::Executor) |
                                 MaskOf(Capability::Cancellation);
                }
                if ((MaskValue & SessionMask) != 0)
                {
                    MaskValue |= MaskOf(Capability::Memory) |
                                 MaskOf(Capability::Executor) |
                                 MaskOf(Capability::Cancellation);
                }
                if (MaskValue == Previous)
                {
                    return MaskValue;
                }
            }
        }

        static constexpr auto FromMasks(const std::uint64_t DeclaredMask,
                                        const std::uint64_t EffectiveMask) noexcept
            -> CapabilitySet
        {
            CapabilitySet Result;
            Result.DeclaredMask_ = DeclaredMask;
            Result.Mask_ = ClosureMask(EffectiveMask);
            return Result;
        }

        std::uint64_t Mask_{0};
        std::uint64_t DeclaredMask_{0};
    };

} // namespace Preview::Composition::Builtin
