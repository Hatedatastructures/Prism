/** @file WriteDriver.hpp @brief 字节writer唯一底层能力，不包含协议、认证或stream标识。 */
#pragma once
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <span>
#include <expected>
namespace Prism::Transport
{
    namespace Net = boost::asio;
    /**
     * @brief 字节 writer 唯一的底层能力契约：partial 写、写半关闭与值结果控制命令，不含协议、认证或 stream 标识。
     * @details 输入所有权：WritePartial 的 Buffer 只借用到 Handler 返回，跨越该点继续使用必须由 driver
     *          自己拥有副本；Completion 按值转移给 driver 并持有到恰好一次完成；Activity() 交回共享所有权的
     *          CarrierActivity，供 writer 在 Close 受理后等待真实退栈。
     *          输出与错误：数据面唯一事实是 Completion 携带的 IoResult{Bytes, Failure}，Bytes 必须是真实
     *          partial 计数且与同次 Failure 一致；Cancel()/Close() 返回 ControlResult，成功只表示命令已交付
     *          到本 driver 的执行域，不表示底层已关闭。取消、EOF、本层封止后拒绝与底层原生错误四类各自保留
     *          Fault::Code 与 Native，不得折叠成一个 error_code。
     *          取消：Cancel() 是唯一取消入口且必须可重复；已发起的 WritePartial/WriteShutdown 仍要在取消后
     *          恰好完成一次，其发生时点由 Activity()->Drain() 证明，本接口不规定墙钟上限。
     *          半关闭与最终关闭者：WriteShutdown 必须在先前字节真实完成后才下发本端写半关闭，读取方向保持
     *          可用；Close() 才是最终关闭入口，实现方只转交命令（TlsWriteDriver 交底层 Transmission、
     *          PadDriver 交 Inner），真正的最终关闭者是持有裸描述符的 leaf 载体。
     *          executor：Executor() 返回冷构造时固定的唯一执行域；状态变更与该域上最后一次 completion 都
     *          必须在 Executor() 或其上再建立的 strand 上发生，要求单一执行域，禁止跨线程并发调用本接口。
     * @note 用户关联分配的操作必须在调用 Handler 前归还；不得把 erased allocator 代理保存到 Handler 消费
     *       之后的独立任务。取消与最后完成的持有者由实际 driver owner 承担。
     */
    class WriteDriver
    {
    public:
        using Completion = Detail::IoCompletion;
        using ControlResult = std::expected<void, Fault::Failure>;
        virtual ~WriteDriver() = default;
        [[nodiscard]] virtual auto Executor() const -> boost::asio::any_io_executor = 0;
        /** @brief 冷固定真正最终关闭所覆盖的活动；Close受理后由writer等待并保留晚到Failure。 */
        [[nodiscard]] virtual auto Activity() const -> std::shared_ptr<Contract::CarrierActivity> = 0;
        /** @brief Buffer借用到Handler返回；必须报告真实partial字节和同次Failure。
         * @details 用户关联分配的操作存储在调用Handler前归还；不得将erased allocator代理
         * 保存到Handler消费之后的独立任务。取消与最后完成均由实际driver owner持有。
         */
        virtual auto WritePartial(std::span<const std::byte> Buffer, Completion Handler) -> void = 0;
        /** @brief 在writer先前字节完成后发起真实写半关闭，读取方向保持可用。 */
        virtual auto WriteShutdown(Completion Handler) -> void = 0;
        [[nodiscard]] virtual auto Cancel() -> ControlResult = 0;
        [[nodiscard]] virtual auto Close() -> ControlResult = 0;
    };
}
