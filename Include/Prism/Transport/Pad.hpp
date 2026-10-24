/** @file Pad.hpp @brief typed填充装饰器，所有写入通过唯一有界writer保持记录顺序。 */
#pragma once
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Transport/PadPolicy.hpp>
#include <Prism/Transport/Writer.hpp>
#include <Prism/Transport/Detail/PadDriver.hpp>
#include <cstddef>
#include <memory>
#include <span>
namespace Prism::Transport
{
    /**
     * @brief 填充装饰器的冷配置：冻结的不可变策略 owner、实际字节池与一次性随机源。
     * @details 输入所有权：Policy 以 shared_ptr<const PadConfig> 共享只读 owner，热路径不再复制 vector 或
     *          做数字→字符串→解析；为空时 PadDriver 的每次 WritePartial 直接以 InvalidArgument 拒绝。
     *          Bytes 移交内部 Writer，必须是装配层实际池（块形状不合 64KiB 时 Writer 明确拒绝）。
     *          Random 只被同步消费一次：PadDriver 构造用它填充 keyed BLAKE3 密钥，之后不保存该 std::function，
     *          因此其生命周期只需借用到构造返回；未提供时使用默认随机源。
     *          输出与错误：本结构不返回结果，校验事实（策略缺失、目标数超 64、倒置区间、随机填充失败）由
     *          PadDriver 构造写入 Failure_ 并经 PadTransport::IsValid() 暴露，原始 CryptoError 与 Native 保留。
     *          取消、半关闭、最终关闭者、executor：纯配置值，不执行取消或半关闭，不拥有描述符，不绑定执行域；
     *          这些语义全部由 PadTransport 与其内部 Writer 承担。
     */
    struct PadOptions final
    {
        std::shared_ptr<const PadConfig> Policy;
        std::shared_ptr<Memory::BytePool> Bytes;
        Detail::PadDriver::RandomSource Random;
    };
    /**
     * @brief typed 填充装饰器：读直连 Inner，写经唯一有界 Writer 串行并保持记录顺序。
     * @details 输入所有权：构造把 Inner 的共享所有权同时交给本层与 PadDriver，Bytes 移交 Writer；读写 span
     *          都只借用到该操作 completion——写侧输入被复制进 driver 独占的固定 record 缓冲并由 Writer 拥有
     *          自己的 64KiB 块，读侧直接落入调用方缓冲区。completion 恰好一次且异步交付，交付的 Bytes 已剔除
     *          填充长度，只计真实 payload 字节。
     *          输出与错误：结果沿用 IoResult{Bytes, Failure}；策略缺失或 driver 构造失败为 InvalidArgument
     *          或保留原 CryptoError/Native，Inner 缺失为 InvalidArgument，准入耗尽为 ResourceUnavailable，
     *          封止后新写为 Canceled，EOF 与底层错误保留 Native，四类互不折叠。
     *          取消：OnCancel 只转交 Writer 的取消，封止本层写序列；本层不调用 Inner 的取消。
     *          半关闭：StartWriteShutdown 走 Writer 的第 65 控制槽，排在所有先前 ticket 之后，再经 driver
     *          转交 Inner 的 WriteShutdown；读方向保持可用，填充计数与随机状态不复位。
     *          最终关闭者：OnClose 返回 Writer::Close()，Writer 在全部 native 写回调退出后才向 driver 下发
     *          Close，driver 再转交 Inner；本层未覆写 OwnsClose，故 Close 交付即行使本层关闭权，裸描述符的
     *          实际关闭者仍是 Inner 指向的叶子载体。
     *          executor：冷构造固定 Inner->Executor() 为原域，Writer 在其上另建 strand 串行化 ticket；
     *          driver 的 record 与 RNG 状态无锁，只被该 strand 上的唯一 active 写调用，要求单一执行域。
     * @note 未定义：装饰层的 Activity 组只包含本层前门与 Writer，不含 Inner 的 activity，因此 Drain 不证明
     *       Inner 的在途读已退栈；读方向的取消与最终退栈证据归属，留待 M13 决定。
     */
    class PadTransport final : public Transmission
    {
    public:
        PadTransport(SharedTransmission Inner, PadOptions Options);
        [[nodiscard]] auto Activity() const noexcept -> std::shared_ptr<Contract::CarrierActivity> override { return Activity_; }
        [[nodiscard]] auto IsValid() const noexcept -> bool { return Driver_->IsValid(); }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission* override { return Inner_.get(); }
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;
        auto StartWriteShutdown(Completion Handler) -> void override;
        [[nodiscard]] auto OnClose() -> ControlResult override;
        [[nodiscard]] auto OnCancel() -> ControlResult override;
    private:
        SharedTransmission Inner_;
        std::shared_ptr<Detail::PadDriver> Driver_;
        std::shared_ptr<Writer> Writer_;
        std::shared_ptr<Contract::CarrierActivity> Activity_;
    };
}
