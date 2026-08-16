/**
 * @file session.hpp
 * @brief HTTP/2 会话抽象（接口骨架）
 * @details HTTP/2 会话层：连接/流/帧编解码/优先级管理。
 * 设计目标：
 * 1. 定义统一契约（h2_session），供 h2mux、grpc、CONNECT 代理复用
 * 2. 生产实现基于 nghttp2（见 src/prism/protocol/multiplex/h2mux/control.cpp）
 * 3. 测试可注入内存实现（无 nghttp2 依赖）验证协议逻辑
 * @note 本文件仅定义接口契约；nghttp2 具体封装见生产库
 *       protocol/multiplex/h2mux/control.cpp。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <common/core/http2/frame.hpp>
#include <common/core/transmission.hpp>

namespace psmtest::http2
{

    namespace net = boost::asio;

    /// HTTP 头键值对
    struct header
    {
        std::string name;  ///< 头名称（小写）
        std::string value; ///< 头值
    };

    /// 头列表（保持顺序）
    using header_list = std::vector<header>;

    /**
     * @class h2_session
     * @brief HTTP/2 会话接口
     * @details 统一 h2 会话契约：
     * - 帧收发（feed/collect）
     * - 流管理（open_stream/reset_stream）
     * - 头/数据提交（submit_headers/submit_data）
     * - 事件回调（on_headers/on_data/on_stream_close）
     */
    class h2_session
    {
    public:
        virtual ~h2_session() = default;

        /**
         * @brief 投喂流数据（传输层 → h2 状态机）
         * @param data 收到的字节流
         * @param ec 错误码输出
         * @return 处理是否成功
         */
        [[nodiscard]] virtual auto feed(std::span<const std::byte> data, std::error_code &ec) -> bool = 0;

        /**
         * @brief 收集待发送帧（h2 状态机 → 传输层）
         * @param out 输出缓冲区
         * @return 是否还有更多待发数据
         */
        [[nodiscard]] virtual auto collect(std::vector<std::byte> &out) -> bool = 0;

        /**
         * @brief 打开新流
         * @param headers 初始头（伪头 + 普通头）
         * @param end_stream 是否立即结束流
         * @return 流 ID；<0 失败
         */
        [[nodiscard]] virtual auto open_stream(const header_list &headers, bool end_stream) -> std::int32_t = 0;

        /**
         * @brief 提交头到已开流
         * @param stream_id 流 ID
         * @param headers 头列表
         * @param end_stream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] virtual auto submit_headers(std::int32_t stream_id, const header_list &headers,
                                                  bool end_stream) -> std::int32_t = 0;

        /**
         * @brief 提交数据到流
         * @param stream_id 流 ID
         * @param data 数据载荷
         * @param end_stream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] virtual auto submit_data(std::int32_t stream_id, std::span<const std::byte> data,
                                               bool end_stream) -> std::int32_t = 0;

        /**
         * @brief 重置流（RST_STREAM）
         * @param stream_id 流 ID
         * @param error_code 错误码
         * @return 成功返回 0
         */
        [[nodiscard]] virtual auto reset_stream(std::int32_t stream_id, std::uint32_t error_code)
            -> std::int32_t = 0;

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;

        // ── 事件回调（协议层订阅） ──

        /// 收到流头（on_headers）
        std::function<void(std::int32_t stream_id, const header_list &headers, bool end_stream)> on_headers;
        /// 收到流数据（on_data）
        std::function<void(std::int32_t stream_id, std::span<const std::byte> data)> on_data;
        /// 流关闭（on_stream_close）
        std::function<void(std::int32_t stream_id, std::uint32_t error_code)> on_stream_close;
    };

    /// 会话共享指针
    using shared_h2_session = std::shared_ptr<h2_session>;

} // namespace psmtest::http2
