/**
 * @file Stream.hpp
 * @brief HTTP/2 流句柄与类型化创建入口。
 * @details 在 core/http2/Session.hpp 的 H2Session 接口之上提供
 * 流级操作句柄：
 * - StreamHandle：流 ID + 会话弱引用，封装读侧事件订阅与
 *   写侧提交（SubmitHeaders / Write / Reset / Close）。
 * 协议层（h2mux/grpc/CONNECT 代理）以句柄为单位管理流，底层状态机仍由 H2Session 持有。
 * @note 句柄不延长 Session 生命周期；调用者必须保留强 Session 和底层传输 owner。同步
 *       操作在 Session executor 上串行调用，句柄不拥有或关闭共享连接。
 */

#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Http2/Session.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>

namespace Preview::Http2
{

    /**
     * @class StreamHandle
     * @brief HTTP/2 流句柄
     * @details 持有流 ID 与会话弱引用，提供流级写操作：
     * - SubmitHeaders：提交头
     * - Write：提交数据
     * - Reset：RST_STREAM
     * - Close：正常关闭流（END_STREAM 语义的便捷封装）
     * 读侧事件（OnHeaders/OnData/OnStreamClose）仍由
     * 会话回调承载，句柄通过订阅接口收拢。句柄不持有强 Session，不拥有底层传输；
     * 调用者须保留连接 owner，并在 Session executor 上串行执行同步操作。
     */
    class StreamHandle : public std::enable_shared_from_this<StreamHandle>
    {
    public:
        /**
         * @brief 构造函数
         * @param StreamId 流 ID
         * @param Session 所属会话（仅保存弱引用，所有权不转移）
         * @details 调用者仍须保留强 Session 和底层传输；句柄析构不会关闭流或连接。
         */
        StreamHandle(std::int32_t StreamId, SharedH2Session Session)
            : StreamId_(StreamId), Session_(Session)
        {
        }

        /**
         * @brief 获取流 ID
         * @return 流 ID
         */
        [[nodiscard]] auto StreamId() const noexcept -> std::int32_t
        {
            return StreamId_;
        }

        /**
         * @brief 获取会话（可提升为强引用）
         * @return 会话强引用；会话已销毁返回 nullptr
         */
        [[nodiscard]] auto Session() const noexcept -> SharedH2Session
        {
            return Session_.lock();
        }

        /**
         * @brief 流是否仍有效（会话存活且流 ID 为正数）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return StreamId_ > 0 && !Session_.expired();
        }

        /**
         * @brief 提交头到本流
         * @param Headers 头列表
         * @param EndStream 是否结束流
         * @return 头帧已入队时成功；无效/关闭流或会话失效时保留完整 Failure。
         * @details 必须在 Session executor 上同步调用，不可取消。EndStream 只关闭本地
         *          发送半边；句柄不关闭 Session 或底层传输。
         */
        [[nodiscard]] auto SubmitHeaders(
            const HeaderList &Headers,
            bool EndStream) -> std::expected<void, Preview::Fault::Failure>
        {
            const auto LockedSession = Session();
            if (!LockedSession)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ConnectionAborted});
            }
            return LockedSession->SubmitHeaders(StreamId_, Headers, EndStream);
        }

        /**
         * @brief 原子提交完整 DATA 到本流。
         * @param Data 借用载荷；仅 Accepted 会在返回前复制并预约发送窗口。
         * @param EndStream Accepted 时是否结束本地发送半边。
         * @return Accepted、Blocked、Closed 或 Invalid；Blocked 保留调用方缓冲所有权。
         * @details 在 Session executor 上同步调用且不可取消。Accepted 的字节由 Session
         *          队列拥有；EndStream 只结束本地发送半边，不转移连接关闭责任。
         */
        [[nodiscard]] auto Write(
            std::span<const std::byte> Data,
            bool EndStream) -> SubmitDataStatus
        {
            const auto LockedSession = Session();
            if (!LockedSession)
            {
                return SubmitDataStatus::Closed;
            }
            return LockedSession->SubmitData(StreamId_, Data, EndStream);
        }

        /**
         * @brief 等待本流与连接窗口都可容纳下一次 Write。
         * @param RequiredBytes 下一次完整提交的数据字节数，必须大于零。
         * @return 窗口就绪时成功；取消、重置或 native wait 错误保留在完整 Failure。
         * @details 成功只表示可以重试；调用者仍持有数据，并须在成功后再次调用 Write。
         *          取消只取消本次等待；调用者须维持 Session 和连接 owner 存活。
         */
        [[nodiscard]] auto AwaitWritable(const std::size_t RequiredBytes)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            const auto LockedSession = Session();
            if (!LockedSession)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ConnectionAborted});
            }
            co_return co_await LockedSession->AwaitWritable(StreamId_, RequiredBytes);
        }

        /**
         * @brief 重置本流（RST_STREAM）
         * @param ErrorCode 错误码
         * @return RST_STREAM 已入队时成功；无效/关闭流或会话失效时保留完整 Failure。
         * @details 必须在 Session executor 上同步调用，不可取消；仅重置本流，不关闭共享
         *          Session 或底层传输。
         */
        [[nodiscard]] auto Reset(std::uint32_t ErrorCode)
            -> std::expected<void, Preview::Fault::Failure>
        {
            const auto LockedSession = Session();
            if (!LockedSession)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ConnectionAborted});
            }
            return LockedSession->ResetStream(StreamId_, ErrorCode);
        }

        /**
         * @brief 关闭本地发送半边并提交 END_STREAM。
         * @return Accepted、Closed 或 Invalid；有效 stream 的空 END_STREAM 不受 flow-control 窗口阻塞。
         * @details 在 Session executor 上同步调用且不可取消；等价于 Write({}, true)，只
         *          关闭本地发送半边并通知对端，不代表远端半边完成或连接已关闭。
         */
        [[nodiscard]] auto Close() -> SubmitDataStatus
        {
            const auto LockedSession = Session();
            if (!LockedSession)
            {
                return SubmitDataStatus::Closed;
            }
            return LockedSession->SubmitData(StreamId_, std::span<const std::byte>{}, true);
        }

    private:
        std::int32_t StreamId_{-1};      ///< 流 ID
        std::weak_ptr<H2Session> Session_; ///< 会话弱引用（防环）
    };

    /// 流句柄共享指针
    using SharedStreamHandle = std::shared_ptr<StreamHandle>;

    /**
     * @brief 打开新流并构造句柄（便捷组合）。
     * @param Session 目标会话；只借用并保存弱引用，调用者必须保留强引用。
     * @param Headers 初始头；仅借用至同步编码完成。
     * @param EndStream 是否立即结束本地发送半边。
     * @return 成功返回 stream ID 与会话弱引用句柄；空会话为 InvalidArgument，其余打开失败
     *         保留完整领域 Failure。
     * @details 必须在 Session executor 上同步调用且不可取消。句柄不接管 Session 或传输的
     *          所有权，不负责最终关闭。
     */
    [[nodiscard]] inline auto OpenStreamHandle(
        SharedH2Session Session,
        const HeaderList &Headers,
        bool EndStream) -> std::expected<SharedStreamHandle, Preview::Fault::Failure>
    {
        if (!Session)
        {
            return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        const auto StreamId = Session->OpenStream(Headers, EndStream);
        if (!StreamId)
        {
            return std::unexpected(StreamId.error());
        }
        auto Handle = std::make_shared<StreamHandle>(*StreamId, std::move(Session));
        // 成功路径断言：句柄内会话弱引用必须有效
        assert(Handle->Session() != nullptr);
        return Handle;
    }

} // namespace Preview::Http2
