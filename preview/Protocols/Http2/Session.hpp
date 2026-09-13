/**
 * @file Session.hpp
 * @brief HTTP/2 会话抽象（接口骨架）
 * @details HTTP/2 会话层：连接/流/帧编解码/优先级管理。
 * 设计目标：
 * 1. 定义统一契约（H2Session），供 h2mux、grpc、CONNECT 代理复用
 * 2. 生产实现基于 nghttp2（见 src/prism/Protocol/multiplex/h2mux/control.cpp）
 * 3. 测试可注入内存实现（无 nghttp2 依赖）验证协议逻辑
 * @note 本文件仅定义接口契约；nghttp2 具体封装见生产库
 *       Protocol/multiplex/h2mux/control.cpp。
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

#include <preview/Protocols/Http2/Frame.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Http2
{

    namespace Net = boost::asio;

    /// HTTP 头键值对
    struct Header
    {
        std::string Name;  ///< 头名称（小写）
        std::string value; ///< 头值（保留以兼容现有调用方）
    };

    /// 头列表（保持顺序）
    using HeaderList = std::vector<Header>;

    /**
     * @class H2Session
     * @brief HTTP/2 会话接口
     * @details 统一 h2 会话契约：
     * - 帧收发（Feed/Collect）
     * - 流管理（OpenStream/ResetStream）
     * - 头/数据提交（SubmitHeaders/SubmitData）
     * - 事件回调（OnHeaders/OnData/OnStreamClose）
     */
    class H2Session
    {
    public:
        virtual ~H2Session() = default;

        /**
         * @brief 投喂流数据（传输层 → h2 状态机）
         * @param Data 收到的字节流
         * @param Error 错误码输出
         * @return 处理是否成功
         */
        [[nodiscard]] virtual auto Feed(
            std::span<const std::byte> Data,
            std::error_code &Error) -> bool = 0;

        /**
         * @brief 收集待发送帧（h2 状态机 → 传输层）
         * @param Output 输出缓冲区
         * @return 是否还有更多待发数据
         */
        [[nodiscard]] virtual auto Collect(std::vector<std::byte> &Output) -> bool = 0;

        /**
         * @brief 打开新流
         * @param Headers 初始头（伪头 + 普通头）
         * @param EndStream 是否立即结束流
         * @return 流 ID；<0 失败
         */
        [[nodiscard]] virtual auto OpenStream(
            const HeaderList &Headers,
            bool EndStream) -> std::int32_t = 0;

        /**
         * @brief 提交头到已开流
         * @param StreamId 流 ID
         * @param Headers 头列表
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] virtual auto SubmitHeaders(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream) -> std::int32_t = 0;

        /**
         * @brief 提交数据到流
         * @param StreamId 流 ID
         * @param Data 数据载荷
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] virtual auto SubmitData(
            std::int32_t StreamId,
            std::span<const std::byte> Data,
            bool EndStream) -> std::int32_t = 0;

        /**
         * @brief 确认应用层已经消费收到的 DATA
         * @param StreamId 数据所属流
         * @param Bytes 已消费的 DATA 帧载荷字节数
         * @details 实现必须分别恢复连接窗口和流窗口，并生成对应的
         * WINDOW_UPDATE 帧。Bytes 超过 31 位增量时必须拆分为多个帧。
         */
        virtual auto ConsumeData(std::int32_t StreamId, std::size_t Bytes) -> void = 0;

        /**
         * @brief 重置流（RST_STREAM）
         * @param StreamId 流 ID
         * @param ErrorCode 错误码
         * @return 成功返回 0
         */
        [[nodiscard]] virtual auto ResetStream(
            std::int32_t StreamId,
            std::uint32_t ErrorCode)
            -> std::int32_t = 0;

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] virtual auto Executor() const -> Net::any_io_executor = 0;

        // ── 事件回调（协议层订阅） ──

        /// 收到流头（OnHeaders）
        std::function<void(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream)> OnHeaders;
        /// 收到流数据（OnData）
        std::function<void(
            std::int32_t StreamId,
            std::span<const std::byte> Data)> OnData;
        /// 流关闭（OnStreamClose）
        std::function<void(
            std::int32_t StreamId,
            std::uint32_t ErrorCode)> OnStreamClose;
    };

    /// 会话共享指针
    using SharedH2Session = std::shared_ptr<H2Session>;

} // namespace Preview::Http2
