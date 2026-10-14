/** @file Algorithm.hpp @brief 精确读写只组合partial操作，保留正字节及同次失败。 */
#pragma once
#include <Preview/Transport/Stream.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/steady_timer.hpp>
namespace Preview
{
    /**
     * @brief 精确读写的公开入口：只做 uint8 span 到正式 byte span 的职责转换，组合目标流的 partial 操作。
     * @details 输入所有权：Buffer 只借用到返回的 awaitable 完成，两个入口都不复制、不接管所有权；Carrier 以
     *          引用借用，实际操作与其预约由目标流拥有。
     *          输出与错误：唯一结果是 IoResult{Bytes, Failure}，累计真实字节并与同次失败一起交付；零进度为
     *          WouldBlock、越界为 InvalidArgument，EOF、取消与底层原生错误四类各自保留 Code 与 Native，
     *          不产生 error_code 输出参数，也不产生第二份错误事实。
     *          取消：本函数不定义自己的取消动作，取消沿目标流的 cancellation slot 与 Close/Cancel 生效，
     *          已交付字节不被清零。
     *          半关闭与最终关闭者：本函数不做写半关闭，也不关闭任何载体；半关闭与关闭命令归目标流。
     *          executor：awaiter 在调用方 executor 上恢复，实际操作仍固定在目标流冷构造的原域，要求该流
     *          处于单一执行域。
     */
    template<Stream S>
    [[nodiscard]] auto ReadExact(S& Carrier, std::span<std::uint8_t> Buffer) -> Net::awaitable<IoResult>
    { return Carrier.ReadExact(std::as_writable_bytes(Buffer)); }
    /** @brief 写侧精确入口，语义与上面的 ReadExact 完全对称：借用到完成、唯一 IoResult、不关闭载体。 */
    template<Stream S>
    [[nodiscard]] auto WriteExact(S& Carrier, std::span<const std::uint8_t> Buffer) -> Net::awaitable<IoResult>
    { return Carrier.WriteExact(std::as_bytes(Buffer)); }
    /** @brief 一次绝对期限覆盖整个exact操作；超时join真实操作后保留已完成字节。
     * @details Timeout 由本函数自建 steady_timer 与目标流的 exact 操作并行等待（wait_for_one），两个完成源
     *          都退出后才交付；到期只把领域 Code 改写为 Timeout，Bytes 与原有 Native 保持原样。
     *          非正期限退化为无期限的精确操作。输入借用、取消、半关闭与最终关闭者语义与上面的 exact 入口
     *          一致；timer 建在 Carrier.Executor() 上，因此仍要求单一执行域。
     * @note 未定义：超时交付不证明原生操作已从目标流退栈，严格墙钟上限未在代码中规定。
     */
    template<Stream S>
    [[nodiscard]] auto ReadExact(S& Carrier, std::span<std::uint8_t> Buffer, std::chrono::milliseconds Timeout)
        -> Net::awaitable<IoResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        if (Timeout.count() <= 0) co_return co_await Carrier.ReadExact(std::as_writable_bytes(Buffer));
        Net::steady_timer Timer(Carrier.Executor());
        Timer.expires_after(Timeout);
        auto [Order, Result, TimerError] = co_await Net::experimental::make_parallel_group(
            Carrier.ReadExact(std::as_writable_bytes(Buffer), Net::deferred), Timer.async_wait(Net::deferred))
            .async_wait(Net::experimental::wait_for_one(), Net::use_awaitable);
        if (Order[0] == 1 && !TimerError) Result.Failure.Code = Fault::Code::Timeout;
        co_return Result;
    }
}
