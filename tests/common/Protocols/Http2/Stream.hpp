/**
 * @file Stream.hpp
 * @brief HTTP/2 流句柄（StreamHandle + StreamOpenResult）
 * @details 在 core/http2/Session.hpp 的 H2Session 接口之上提供
 * 流级操作句柄：
 * - StreamOpenResult：打开流结果（成功/失败 + 流 ID + 错误码）
 * - StreamHandle：流 ID + 会话弱引用，封装读侧事件订阅与
 *   写侧提交（SubmitHeaders / Write / Reset / Close）
 * 协议层（h2mux/grpc/CONNECT 代理）以句柄为单位管理流，
 * 底层状态机仍由 H2Session 持有，句柄仅做引用收拢。
 * @note 句柄持弱引用，会话销毁后所有操作安全失效（IsOpen=false）。
 */

#pragma once

#include <common/Protocols/Http2/Session.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>

namespace Preview::Http2
{

    /**
     * @struct StreamOpenResult
     * @brief 打开流的结果
     * @details 三要素：是否成功 + 流 ID + 错误码。
     * 失败时 StreamId 恒为 -1。
     */
    struct StreamOpenResult
    {
        bool Ok{false};            ///< 是否成功
        std::int32_t StreamId{-1}; ///< 流 ID（失败为 -1）
        std::error_code ec{};       ///< 错误码（成功为空）

        /**
         * @brief 快速构造成功结果
         * @param sid 流 ID
         * @return 成功结果
         */
        [[nodiscard]] static auto MakeSuccess(std::int32_t Sid) noexcept -> StreamOpenResult
        {
            return StreamOpenResult{true, Sid, {}};
        }

        /**
         * @brief 快速构造失败结果
         * @param err 错误码
         * @return 失败结果
         */
        [[nodiscard]] static auto MakeFailure(std::error_code err) noexcept -> StreamOpenResult
        {
            return StreamOpenResult{false, -1, err};
        }
    };

    /**
     * @class StreamHandle
     * @brief HTTP/2 流句柄
     * @details 持有流 ID 与会话弱引用，提供流级写操作：
     * - SubmitHeaders：提交头
     * - Write：提交数据
     * - Reset：RST_STREAM
     * - Close：正常关闭流（END_STREAM 语义的便捷封装）
     * 读侧事件（OnHeaders/OnData/OnStreamClose）仍由
     * 会话回调承载，句柄通过订阅接口收拢。
     */
    class StreamHandle : public std::enable_shared_from_this<StreamHandle>
    {
    public:
        /**
         * @brief 构造函数
         * @param StreamId 流 ID
         * @param Session 所属会话（弱引用持有）
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
         * @brief 流是否仍有效（会话存活且流 ID 合法）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsOpen() const noexcept -> bool
        {
            return StreamId_ >= 0 && !Session_.expired();
        }

        /**
         * @brief 提交头到本流
         * @param headers 头列表
         * @param EndStream 是否结束流
         * @return 成功返回 0；会话失效返回 -1
         */
        [[nodiscard]] auto SubmitHeaders(const HeaderList &headers, bool EndStream) -> std::int32_t
        {
            const auto S = Session();
            if (!S)
            {
                return -1;
            }
            return S->SubmitHeaders(StreamId_, headers, EndStream);
        }

        /**
         * @brief 提交数据到本流
         * @param Data 数据载荷
         * @param EndStream 是否结束流
         * @return 成功返回 0；会话失效返回 -1
         */
        [[nodiscard]] auto Write(std::span<const std::byte> Data, bool EndStream) -> std::int32_t
        {
            const auto S = Session();
            if (!S)
            {
                return -1;
            }
            return S->SubmitData(StreamId_, Data, EndStream);
        }

        /**
         * @brief 重置本流（RST_STREAM）
         * @param ErrorCode 错误码
         * @return 成功返回 0；会话失效返回 -1
         */
        [[nodiscard]] auto Reset(std::uint32_t ErrorCode) -> std::int32_t
        {
            const auto S = Session();
            if (!S)
            {
                return -1;
            }
            return S->ResetStream(StreamId_, ErrorCode);
        }

        /**
         * @brief 关闭本流（EndStream 语义）
         * @return 成功返回 0；会话失效返回 -1
         * @details 等价于 Write({}, true)，通知对端本流结束。
         */
        [[nodiscard]] auto Close() -> std::int32_t
        {
            const auto S = Session();
            if (!S)
            {
                return -1;
            }
            return S->SubmitData(StreamId_, std::span<const std::byte>{}, true);
        }

    private:
        std::int32_t StreamId_{-1};      ///< 流 ID
        std::weak_ptr<H2Session> Session_; ///< 会话弱引用（防环）
    };

    /// 流句柄共享指针
    using SharedStreamHandle = std::shared_ptr<StreamHandle>;

    /**
     * @brief 在会话上打开新流并返回句柄
     * @param Session 目标会话
     * @param headers 初始头（伪头 + 普通头）
     * @param EndStream 是否立即结束流
     * @return 打开结果（含句柄创建所需的流 ID）
     * @note 句柄由调用方通过 make_shared 包装；本函数仅返回
     *       打开结果，便于失败分支短路。
     */
    [[nodiscard]] inline auto OpenStream(SharedH2Session Session, const HeaderList &headers,
                                          bool EndStream) -> StreamOpenResult
    {
        if (!Session)
        {
            return StreamOpenResult::MakeFailure(
                std::make_error_code(std::errc::not_connected));
        }
        const auto Sid = Session->OpenStream(headers, EndStream);
        if (Sid < 0)
        {
            return StreamOpenResult::MakeFailure(
                std::make_error_code(std::errc::protocol_error));
        }
        return StreamOpenResult::MakeSuccess(Sid);
    }

    /**
     * @brief 打开新流并构造句柄（便捷组合）
     * @param Session 目标会话
     * @param headers 初始头
     * @param EndStream 是否立即结束流
     * @return 流句柄；打开失败返回 nullptr
     */
    [[nodiscard]] inline auto OpenStreamHandle(SharedH2Session Session, const HeaderList &headers,
                                                 bool EndStream) -> SharedStreamHandle
    {
        // 拷贝传参（refcount+1），成功路径再用 move 构造句柄，避免 use-after-move
        const auto Result = OpenStream(Session, headers, EndStream);
        if (!Result.Ok)
        {
            return nullptr;
        }
        auto Handle = std::make_shared<StreamHandle>(Result.StreamId, std::move(Session));
        // 成功路径断言：句柄内会话弱引用必须有效
        assert(Handle->Session().lock() != nullptr);
        return Handle;
    }

} // namespace Preview::Http2
