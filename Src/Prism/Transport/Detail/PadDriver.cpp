/** @file PadDriver.cpp @brief keyed填充记录与载荷完成映射实现。 */
#include <Prism/Transport/Detail/PadDriver.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>

#include <blake3.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <utility>

namespace Prism::Transport::Detail
{
    class PadDriver::PadCompletion final : public AssociatedCompletion<Completion>
    {
    public:
        PadCompletion(std::size_t Payload, Completion Handler) : AssociatedCompletion(std::move(Handler)), Payload_(Payload) {}
        auto operator()(IoResult Result) -> void
        { Result.Bytes = (std::min)(Result.Bytes, Payload_); std::move(Handler_)(Result); }
    private:
        std::size_t Payload_;
    };

    PadDriver::PadDriver(SharedTransmission Inner, Options Value)
        : Inner_(std::move(Inner)), Policy_(std::move(Value.Policy))
    {
        if (!Policy_) return;
        Failure_ = {};
        std::expected<void, Fault::Failure> Result;
        if (Value.Random) Result = Prism::Crypto::FillRandom(std::span(Key_), std::move(Value.Random));
        else Result = Prism::Crypto::FillRandom(std::span(Key_));
        if (!Result) Failure_ = Result.error();
        if (Policy_->Targets.size() > 64) Failure_ = {Fault::Code::InvalidArgument};
        for (const auto& Range : Policy_->Targets) if (Range.MinVal > Range.MaxVal) Failure_ = {Fault::Code::InvalidArgument};
    }

    auto PadDriver::WritePartial(std::span<const std::byte> Input, Completion Handler) -> void
    {
        if (!Policy_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        if (!Policy_->Enabled() || Writes_ >= Policy_->StopAfter || Input.empty())
        { Inner_->WriteSome(Input, std::move(Handler)); return; }
        if (Failure_.Failed()) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, Failure_}); return; }
        const auto Padding = PaddingFor(Input.size());
        if (Input.size() > Record_.size() || Padding > Record_.size() - Input.size())
        { Inner_->WriteSome(Input, std::move(Handler)); return; }
        std::memcpy(Record_.data(), Input.data(), Input.size());
        Fill(std::span(Record_).subspan(Input.size(), Padding));
        ++Writes_;
        Inner_->WriteExact(std::span<const std::byte>(Record_).first(Input.size() + Padding),
            PadCompletion(Input.size(), std::move(Handler)));
    }

    auto PadDriver::WriteShutdown(Completion Handler) -> void
    {
        Inner_->WriteShutdown(std::move(Handler));
    }

    auto PadDriver::Cancel() -> ControlResult
    {
        return Inner_->Cancel();
    }

    auto PadDriver::Close() -> ControlResult
    {
        return Inner_->Close();
    }

    auto PadDriver::PaddingFor(std::size_t Size) -> std::size_t
    {
        const auto& Range = Policy_->Targets[Writes_ % Policy_->Targets.size()];
        const auto Target = Sample(Range.MinVal, Range.MaxVal);
        if (Size < Target) return Target - Size;
        return Sample(0, Policy_->MaxPadBytes);
    }

    auto PadDriver::Sample(std::uint16_t Minimum, std::uint16_t Maximum) -> std::uint16_t
    {
        if (Minimum == Maximum) return Minimum;
        std::array<std::byte, 2> Random;
        Fill(Random);
        const auto Value = static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(Random[0]) << 8) |
            std::to_integer<std::uint16_t>(Random[1]));
        const auto Width = static_cast<std::uint32_t>(Maximum) - Minimum + 1;
        return static_cast<std::uint16_t>(Minimum + Value % Width);
    }

    auto PadDriver::Refill() -> void
    {
        blake3_hasher Hasher;
        blake3_hasher_init_keyed(&Hasher, Key_.data());
        std::array<std::uint8_t, 8> Counter;
        auto Value = Counter_++;
        for (auto& Byte : Counter) { Byte = static_cast<std::uint8_t>(Value & 0xffU); Value >>= 8; }
        blake3_hasher_update(&Hasher, Counter.data(), Counter.size());
        blake3_hasher_finalize(&Hasher, Random_.data(), Random_.size());
        RandomOffset_ = 0;
    }

    auto PadDriver::Fill(std::span<std::byte> Output) -> void
    {
        std::size_t Offset = 0;
        while (Offset < Output.size())
        {
            if (RandomOffset_ == Random_.size()) Refill();
            const auto Count = (std::min)(Output.size() - Offset, Random_.size() - RandomOffset_);
            std::memcpy(Output.data() + Offset, Random_.data() + RandomOffset_, Count);
            Offset += Count; RandomOffset_ += Count;
        }
    }

}
