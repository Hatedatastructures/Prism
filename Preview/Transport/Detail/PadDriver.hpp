/** @file PadDriver.hpp @brief 序列化writer的填充record owner，独占固定缓冲和随机状态。 */
#pragma once
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/WriteDriver.hpp>
#include <Preview/Transport/PadPolicy.hpp>
#include <Preview/Foundation/Utility/Crypto/Random.hpp>
#include <blake3.h>
#include <cstring>
#include <functional>
namespace Preview::Transport::Detail
{
    /**
     * @brief 序列化 writer 的填充 record owner：独占固定缓冲与 keyed BLAKE3 随机状态。
     * @details 输入所有权：构造把 Inner 的共享所有权移入 Inner_、把 Options.Policy 移入 Policy_（:39，
     *          成员 :120-:121）；Options.Random 不被保存，只在构造期被同步消费一次用于填充 Key_（:44-:45）。
     *          输出与错误：三条写路径互不相同——无 Policy 时以 InvalidArgument 异步拒绝（:41、:55）；
     *          未启用、已达 StopAfter、空输入（:56-:57）或记录放不下（:60-:61）时直接透传 Inner 的
     *          WriteSome，保留原输入；加填充路径才把输入 memcpy 进本对象独占的 Record_ 再 WriteExact
     *          （:62-:66），PadCompletion 随后把上报字节夹回原输入长度，用户看不到填充字节（:77）。
     *          构造期校验依次覆盖 FillRandom 失败（:46）、Targets 超过 64 项（:47）与倒置区间（:48），
     *          结果写入 Failure_ 并只经 IsValid()（:50）暴露，热写路径不再判定。
     *          取消：Cancel() 只转交 Inner（:69），本类型自身没有取消状态；已发起操作的取消完成时点由
     *          Inner 的活动链证明，本文件不规定墙钟上限。
     *          半关闭：WriteShutdown 只转交 Inner 的写半关闭（:68），读取方向不受本层影响。
     *          最终关闭者：不是本类型——Close() 仅把命令交付 Inner（:70），其成功也只表示已经交付；
     *          裸描述符的最终 close 属于 leaf 载体（Reliable.hpp:80）。
     *          executor：Executor()（:51）与 Activity()（:52）都原样透传 Inner，本类型既不自建 strand，
     *          也不建 ActivityGroup；Record_/Key_/Counter_/RandomOffset_/Writes_（:122-:126）皆非原子，
     *          其排他性完全依赖调用方（Writer）所提供的执行域。
     * @note 未定义：Writes_ 为 std::uint8_t（:126），与 PadConfig::StopAfter（PadPolicy.hpp:37）同为 8 位，
     *       第 256 次写之后回绕会使 StopAfter 判定重新失效；整条记录超限时的处置（:60-:61 直接透传原输入）
     *       也没有规定，二者须由 Pad 策略与关闭链的收口卡决定，本卡不改代码。
     */
    class PadDriver final : public WriteDriver
    {
    public:
        using RandomSource = std::function<int(std::uint8_t*, int)>;
        struct Options final { std::shared_ptr<const PadConfig> Policy; RandomSource Random; };
        PadDriver(SharedTransmission Inner, Options Value) : Inner_(std::move(Inner)), Policy_(std::move(Value.Policy))
        {
            if (!Policy_) return;
            Failure_ = {};
            std::expected<void, Fault::Failure> Result;
            if (Value.Random) Result = Preview::Crypto::FillRandom(std::span(Key_), std::move(Value.Random));
            else Result = Preview::Crypto::FillRandom(std::span(Key_));
            if (!Result) Failure_ = Result.error();
            if (Policy_->Targets.size() > 64) Failure_ = {Fault::Code::InvalidArgument};
            for (const auto& Range : Policy_->Targets) if (Range.MinVal > Range.MaxVal) Failure_ = {Fault::Code::InvalidArgument};
        }
        [[nodiscard]] auto IsValid() const noexcept -> bool { return Failure_.Succeeded(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Inner_->Executor(); }
        [[nodiscard]] auto Activity() const -> std::shared_ptr<Contract::CarrierActivity> override { return Inner_->Activity(); }
        auto WritePartial(std::span<const std::byte> Input, Completion Handler) -> void override
        {
            if (!Policy_) { PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
            if (!Policy_->Enabled() || Writes_ >= Policy_->StopAfter || Input.empty())
            { Inner_->WriteSome(Input, std::move(Handler)); return; }
            if (Failure_.Failed()) { PostResult(Executor(), std::move(Handler), {0, Failure_}); return; }
            const auto Padding = PaddingFor(Input.size());
            if (Input.size() > Record_.size() || Padding > Record_.size() - Input.size())
            { Inner_->WriteSome(Input, std::move(Handler)); return; }
            std::memcpy(Record_.data(), Input.data(), Input.size());
            Fill(std::span(Record_).subspan(Input.size(), Padding));
            ++Writes_;
            Inner_->WriteExact(std::span<const std::byte>(Record_).first(Input.size() + Padding),
                PadCompletion(Input.size(), std::move(Handler)));
        }
        auto WriteShutdown(Completion Handler) -> void override { Inner_->WriteShutdown(std::move(Handler)); }
        [[nodiscard]] auto Cancel() -> ControlResult override { return Inner_->Cancel(); }
        [[nodiscard]] auto Close() -> ControlResult override { return Inner_->Close(); }
    private:
        class PadCompletion final : public AssociatedCompletion<Completion>
        {
        public:
            PadCompletion(std::size_t Payload, Completion Handler) : AssociatedCompletion(std::move(Handler)), Payload_(Payload) {}
            auto operator()(IoResult Result) -> void
            { Result.Bytes = (std::min)(Result.Bytes, Payload_); std::move(Handler_)(Result); }
        private:
            std::size_t Payload_;
        };
        [[nodiscard]] auto PaddingFor(std::size_t Size) -> std::size_t
        {
            const auto& Range = Policy_->Targets[Writes_ % Policy_->Targets.size()];
            const auto Target = Sample(Range.MinVal, Range.MaxVal);
            if (Size < Target) return Target - Size;
            return Sample(0, Policy_->MaxPadBytes);
        }
        [[nodiscard]] auto Sample(std::uint16_t Minimum, std::uint16_t Maximum) -> std::uint16_t
        {
            if (Minimum == Maximum) return Minimum;
            std::array<std::byte, 2> Random;
            Fill(Random);
            const auto Value = static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(Random[0]) << 8) |
                std::to_integer<std::uint16_t>(Random[1]));
            const auto Width = static_cast<std::uint32_t>(Maximum) - Minimum + 1;
            return static_cast<std::uint16_t>(Minimum + Value % Width);
        }
        auto Refill() -> void
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
        auto Fill(std::span<std::byte> Output) -> void
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
        SharedTransmission Inner_;
        std::shared_ptr<const PadConfig> Policy_;
        std::array<std::byte, 16384 + 256> Record_;
        std::array<std::uint8_t, 32> Key_{}, Random_{};
        std::uint64_t Counter_{0};
        std::size_t RandomOffset_{32};
        std::uint8_t Writes_{0};
        Fault::Failure Failure_{Fault::Code::InvalidArgument};
    };
}
