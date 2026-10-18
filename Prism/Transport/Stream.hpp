/** @file Stream.hpp @brief 正式typed流能力concept，无旧错误输出参数或同义门面。 */
#pragma once
#include <Prism/Transport/Transmission.hpp>
namespace Prism
{
    /**
     * @brief 正式 typed 流能力的编译期形状约束：读写前门、控制命令、开放状态与执行域。
     * @details 输入所有权：概念要求 ReadSome/WriteSome/ReadExact/WriteExact 接受 span 并返回 awaitable<IoResult>，
     *          即缓冲区只借用到该操作 completion，实现不得在 completion 之后继续引用它。
     *          输出与错误：唯一事实是 IoResult{Bytes, Failure} 与 expected<void, Fault::Failure>，
     *          没有 error_code 输出参数，也没有第二份错误事实；取消、EOF、本地封止与底层错误四类分别保留。
     *          取消：Cancel() 返回 ControlResult，成功只表示命令已被实现方接管，重复调用的幂等性由实现层
     *          （当前是 Transmission 的控制预约）提供。
     *          半关闭：WriteShutdown() 返回 awaitable<ControlResult>，只封止写方向，读取方向必须保持可用。
     *          最终关闭者：Close() 同样只表示交付，裸描述符的最终关闭者由实现内部 OwnsClose() 的那一层承担。
     *          executor：Executor() 必须返回冷构造时固定的单一 any_io_executor 执行域。
     * @note 未定义：概念只校验签名形状，不能证明 completion 恰好一次、不可重入或取消时序；这些运行语义的
     *       验收仍依赖 M13 之后的构建与真实请求层验证。
     */
    template<class T>
    concept Stream = TransmissionLike<T> && requires(T& Value)
    {
        { Value.IsOpen() } -> std::same_as<bool>;
        { Value.Executor() } -> std::same_as<Net::any_io_executor>;
    };
}
