/** @file PadDriver.hpp @brief 序列化writer的填充record owner，独占固定缓冲和随机状态。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/WriteDriver.hpp>
#include <Prism/Transport/PadPolicy.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
namespace Prism::Transport::Detail
{
    /**
     * @brief 序列化 writer 的填充 record owner：独占固定缓冲与 keyed BLAKE3 随机状态。
     * @details 输入所有权：构造把 Inner 的共享所有权移入 Inner_、把 Options.Policy 移入 Policy_；
     *          Options.Random 不被保存，只在构造期被同步消费一次用于填充 Key_。
     *          输出与错误：三条写路径互不相同——无 Policy 时以 InvalidArgument 异步拒绝；
     *          未启用、已达 StopAfter、空输入或记录放不下时直接透传 Inner 的
     *          WriteSome，保留原输入；加填充路径才把输入 memcpy 进本对象独占的 Record_ 再 WriteExact，
     *          PadCompletion 把上报字节夹回原输入长度，用户看不到填充字节。
     *          构造期校验覆盖 FillRandom 失败、Targets 超过 64 项与倒置区间，结果写入 Failure_ 并只经
     *          IsValid() 暴露，热写路径不再判定。
     *          取消：Cancel() 只转交 Inner，本类型自身没有取消状态；已发起操作的取消完成时点由
     *          Inner 的活动链证明，本文件不规定墙钟上限。
     *          半关闭：WriteShutdown 只转交 Inner 的写半关闭，读取方向不受本层影响。
     *          最终关闭者：不是本类型——Close() 仅把命令交付 Inner，其成功也只表示已经交付；
     *          裸描述符的最终 close 属于 Reliable 叶子载体。
     *          executor：Executor() 与 Activity() 都原样透传 Inner，本类型既不自建 strand，
     *          也不建 ActivityGroup；Record_/Key_/Counter_/RandomOffset_/Writes_ 皆非原子，
     *          其排他性完全依赖调用方（Writer）所提供的执行域。
     * @note 未定义：Writes_ 为 std::uint8_t，与 PadConfig::StopAfter 同为 8 位，
     *       第 256 次写之后回绕会使 StopAfter 判定重新失效；整条记录超限时直接透传原输入，
     *       也没有规定，二者须由 Pad 策略与关闭链的收口卡决定，本卡不改代码。
     */
    class PadDriver final : public WriteDriver
    {
    public:
        using RandomSource = std::function<int(std::uint8_t*, int)>;
        struct Options final { std::shared_ptr<const PadConfig> Policy; RandomSource Random; };
        PadDriver(SharedTransmission Inner, Options Value);
        [[nodiscard]] auto IsValid() const noexcept -> bool { return Failure_.Succeeded(); }
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Inner_->Executor(); }
        [[nodiscard]] auto Activity() const -> std::shared_ptr<Contract::CarrierActivity> override { return Inner_->Activity(); }
        auto WritePartial(std::span<const std::byte> Input, Completion Handler) -> void override;
        auto WriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto Cancel() -> ControlResult override;
        [[nodiscard]] auto Close() -> ControlResult override;
    private:
        class PadCompletion;
        [[nodiscard]] auto PaddingFor(std::size_t Size) -> std::size_t;
        [[nodiscard]] auto Sample(std::uint16_t Minimum, std::uint16_t Maximum) -> std::uint16_t;
        auto Refill() -> void;
        auto Fill(std::span<std::byte> Output) -> void;
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
