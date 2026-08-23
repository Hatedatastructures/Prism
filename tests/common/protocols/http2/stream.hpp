/**
 * @file stream.hpp
 * @brief HTTP/2 流句柄（stream_handle + stream_open_result）
 * @details 在 core/http2/session.hpp 的 h2_session 接口之上提供
 * 流级操作句柄：
 * - stream_open_result：打开流结果（成功/失败 + 流 ID + 错误码）
 * - stream_handle：流 ID + 会话弱引用，封装读侧事件订阅与
 *   写侧提交（submit_headers / write / reset / close）
 * 协议层（h2mux/grpc/CONNECT 代理）以句柄为单位管理流，
 * 底层状态机仍由 h2_session 持有，句柄仅做引用收拢。
 * @note 句柄持弱引用，会话销毁后所有操作安全失效（is_open=false）。
 */

#pragma once

#include <common/protocols/http2/session.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>

namespace preview::http2
{

    /**
     * @struct stream_open_result
     * @brief 打开流的结果
     * @details 三要素：是否成功 + 流 ID + 错误码。
     * 失败时 stream_id 恒为 -1。
     */
    struct stream_open_result
    {
        bool ok{false};            ///< 是否成功
        std::int32_t stream_id{-1}; ///< 流 ID（失败为 -1）
        std::error_code ec{};       ///< 错误码（成功为空）

        /**
         * @brief 快速构造成功结果
         * @param sid 流 ID
         * @return 成功结果
         */
        [[nodiscard]] static auto make_success(std::int32_t sid) noexcept -> stream_open_result
        {
            return stream_open_result{true, sid, {}};
        }

        /**
         * @brief 快速构造失败结果
         * @param err 错误码
         * @return 失败结果
         */
        [[nodiscard]] static auto make_failure(std::error_code err) noexcept -> stream_open_result
        {
            return stream_open_result{false, -1, err};
        }
    };

    /**
     * @class stream_handle
     * @brief HTTP/2 流句柄
     * @details 持有流 ID 与会话弱引用，提供流级写操作：
     * - submit_headers：提交头
     * - write：提交数据
     * - reset：RST_STREAM
     * - close：正常关闭流（END_STREAM 语义的便捷封装）
     * 读侧事件（on_headers/on_data/on_stream_close）仍由
     * 会话回调承载，句柄通过订阅接口收拢。
     */
    class stream_handle : public std::enable_shared_from_this<stream_handle>
    {
    public:
        /**
         * @brief 构造函数
         * @param stream_id 流 ID
         * @param session 所属会话（弱引用持有）
         */
        stream_handle(std::int32_t stream_id, shared_h2_session session)
            : stream_id_(stream_id), session_(session)
        {
        }

        /**
         * @brief 获取流 ID
         * @return 流 ID
         */
        [[nodiscard]] auto stream_id() const noexcept -> std::int32_t
        {
            return stream_id_;
        }

        /**
         * @brief 获取会话（可提升为强引用）
         * @return 会话强引用；会话已销毁返回 nullptr
         */
        [[nodiscard]] auto session() const noexcept -> shared_h2_session
        {
            return session_.lock();
        }

        /**
         * @brief 流是否仍有效（会话存活且流 ID 合法）
         * @return 有效返回 true
         */
        [[nodiscard]] auto is_open() const noexcept -> bool
        {
            return stream_id_ >= 0 && !session_.expired();
        }

        /**
         * @brief 提交头到本流
         * @param headers 头列表
         * @param end_stream 是否结束流
         * @return 成功返回 0；会话失效返回 -1
         */
        [[nodiscard]] auto submit_headers(const header_list &headers, bool end_stream) -> std::int32_t
        {
            const auto s = session();
            if (!s)
            {
                return -1;
            }
            return s->submit_headers(stream_id_, headers, end_stream);
        }

        /**
         * @brief 提交数据到本流
         * @param data 数据载荷
         * @param end_stream 是否结束流
         * @return 成功返回 0；会话失效返回 -1
         */
        [[nodiscard]] auto write(std::span<const std::byte> data, bool end_stream) -> std::int32_t
        {
            const auto s = session();
            if (!s)
            {
                return -1;
            }
            return s->submit_data(stream_id_, data, end_stream);
        }

        /**
         * @brief 重置本流（RST_STREAM）
         * @param error_code 错误码
         * @return 成功返回 0；会话失效返回 -1
         */
        [[nodiscard]] auto reset(std::uint32_t error_code) -> std::int32_t
        {
            const auto s = session();
            if (!s)
            {
                return -1;
            }
            return s->reset_stream(stream_id_, error_code);
        }

        /**
         * @brief 关闭本流（end_stream 语义）
         * @return 成功返回 0；会话失效返回 -1
         * @details 等价于 write({}, true)，通知对端本流结束。
         */
        [[nodiscard]] auto close() -> std::int32_t
        {
            const auto s = session();
            if (!s)
            {
                return -1;
            }
            return s->submit_data(stream_id_, std::span<const std::byte>{}, true);
        }

    private:
        std::int32_t stream_id_{-1};      ///< 流 ID
        std::weak_ptr<h2_session> session_; ///< 会话弱引用（防环）
    };

    /// 流句柄共享指针
    using shared_stream_handle = std::shared_ptr<stream_handle>;

    /**
     * @brief 在会话上打开新流并返回句柄
     * @param session 目标会话
     * @param headers 初始头（伪头 + 普通头）
     * @param end_stream 是否立即结束流
     * @return 打开结果（含句柄创建所需的流 ID）
     * @note 句柄由调用方通过 make_shared 包装；本函数仅返回
     *       打开结果，便于失败分支短路。
     */
    [[nodiscard]] inline auto open_stream(shared_h2_session session, const header_list &headers,
                                          bool end_stream) -> stream_open_result
    {
        if (!session)
        {
            return stream_open_result::make_failure(
                std::make_error_code(std::errc::not_connected));
        }
        const auto sid = session->open_stream(headers, end_stream);
        if (sid < 0)
        {
            return stream_open_result::make_failure(
                std::make_error_code(std::errc::protocol_error));
        }
        return stream_open_result::make_success(sid);
    }

    /**
     * @brief 打开新流并构造句柄（便捷组合）
     * @param session 目标会话
     * @param headers 初始头
     * @param end_stream 是否立即结束流
     * @return 流句柄；打开失败返回 nullptr
     */
    [[nodiscard]] inline auto open_stream_handle(shared_h2_session session, const header_list &headers,
                                                 bool end_stream) -> shared_stream_handle
    {
        // 拷贝传参（refcount+1），成功路径再用 move 构造句柄，避免 use-after-move
        const auto result = open_stream(session, headers, end_stream);
        if (!result.ok)
        {
            return nullptr;
        }
        auto handle = std::make_shared<stream_handle>(result.stream_id, std::move(session));
        // 成功路径断言：句柄内会话弱引用必须有效
        assert(handle->session().lock() != nullptr);
        return handle;
    }

} // namespace preview::http2
