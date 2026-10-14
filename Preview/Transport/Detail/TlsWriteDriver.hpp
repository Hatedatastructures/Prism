/** @file TlsWriteDriver.hpp @brief 通用writer的TLS端口，close_notify和应用写共享同一引擎。 */
#pragma once
#include <Preview/Transport/WriteDriver.hpp>
#include <Preview/Transport/Detail/TlsStream.hpp>
#include <Preview/Transport/Detail/ActivityGroup.hpp>
namespace Preview::Transport::Detail
{
    /**
     * @brief 通用 Writer 的 TLS 端口：把 WriteDriver 的命令转交给 TlsStream 与其内层 Transmission。
     * @details 输入所有权：构造接管 TlsStream 的共享所有权（:30，成员 :44），并以 Stream 的 activity 为父、
     *          内层 Transmission 的 activity 为唯一子组装 ActivityGroup（:31-:32，成员 :45）。
     *          输出与错误：本类型不自定义错误形状，只转交；WritePartial 的 Buffer 借用到该次 completion
     *          为止（:35-:36 → TlsStream.hpp:54-:56 只保留序列视图）。
     *          取消：Cancel() 只把命令交付内层（:39-:40），成功仅表示命令已经送达，本类型自身无取消状态；
     *          已发起操作的取消完成时点由 ActivityGroup 的排空链证明，不规定墙钟上限。
     *          半关闭：WriteShutdown 只让引擎发本端 close_notify（:37-:38），读取方向保持可用。
     *          最终关闭者：不是本类型——Close() 同样只转交内层（:41-:42），裸描述符的最终 close 属于
     *          leaf 载体（Reliable.hpp:80）；Close 受理后由 writer 经 Activity()->Drain() 等待真实退栈。
     *          executor：Executor()（:33）返回 TlsStream 构造时建立的唯一 strand（TlsStream.hpp:45），
     *          本类型不自建 strand，也不在此处切换执行域。
     * @note 未定义：构造函数无条件解引用 next_layer().NextLayer()（:32），而 Connector::NextLayer() 在
     *       Release()（Connector.hpp:49）之后返回空指针，Cancel/Close（:40、:42）却对同一指针做空判定；
     *       两处假设不一致，「链上无内层时应当拒绝还是失败」须由关闭链收口卡决定，本卡不改代码。
     * @note 未定义：无内层时 Cancel/Close 返回 {}（即成功），与「成功只表示命令已交付」的既有语义相争，
     *       该返回形状的定权属 W0-A 与 M15（唯一 socket 权限），本卡只记录 :40、:42 的 fallback 分支事实。
     */
    class TlsWriteDriver final : public WriteDriver
    {
    public:
        explicit TlsWriteDriver(std::shared_ptr<TlsStream> Stream) : Stream_(std::move(Stream)),
            Activity_(std::make_shared<ActivityGroup>(Stream_->Activity(),
                std::vector<std::shared_ptr<Contract::CarrierActivity>>{Stream_->next_layer().NextLayer()->Activity()})) {}
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override { return Stream_->get_executor(); }
        [[nodiscard]] auto Activity() const -> std::shared_ptr<Contract::CarrierActivity> override { return Activity_; }
        auto WritePartial(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { Stream_->WriteSome(Buffer, std::move(Handler)); }
        auto WriteShutdown(Completion Handler) -> void override
        { Stream_->WriteShutdown(std::move(Handler)); }
        [[nodiscard]] auto Cancel() -> ControlResult override
        { if (auto* Inner = Stream_->next_layer().NextLayer()) return Inner->Cancel(); return {}; }
        [[nodiscard]] auto Close() -> ControlResult override
        { if (auto* Inner = Stream_->next_layer().NextLayer()) return Inner->Close(); return {}; }
    private:
        std::shared_ptr<TlsStream> Stream_;
        std::shared_ptr<ActivityGroup> Activity_;
    };
}
