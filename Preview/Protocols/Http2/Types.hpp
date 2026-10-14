/**
 * @file Types.hpp
 * @brief HTTP/2 会话使用的稳定类型和事件合同。
 * @details 仅暴露连接调用者所需的头、设置、错误码及 stream 事件；帧和 HPACK
 *          编码模型由 Detail owner 私有持有。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Preview/Foundation/Fault/Failure.hpp>

namespace Preview::Http2
{

    namespace Net = boost::asio;

    /** @brief HTTP/2 头字段；Name 为小写字段名，Value 为字段值。 */
    struct Header final
    {
        std::string Name;
        std::string Value;
    };

    /** @brief 保留协议顺序的 HTTP/2 头列表。 */
    using HeaderList = std::vector<Header>;

    /** @brief 要发送的 HTTP/2 设置项；会话同步编码，不保留该对象。 */
    struct SettingsEntry final
    {
        std::uint16_t Id{0};
        std::uint32_t Value{0};
    };

    /** @brief SETTINGS 参数编号。 */
    inline constexpr std::uint16_t SettingsHeaderTableSize = 0x1;
    inline constexpr std::uint16_t SettingsEnablePush = 0x2;
    inline constexpr std::uint16_t SettingsMaxConcurrentStreams = 0x3;
    inline constexpr std::uint16_t SettingsInitialWindowSize = 0x4;
    inline constexpr std::uint16_t SettingsMaxFrameSize = 0x5;
    inline constexpr std::uint16_t SettingsMaxHeaderListSize = 0x6;

    /**
     * @brief 提交 DATA 的唯一结果。
     * @details Accepted 表示整个 Data 已复制进会话发送队列并预约窗口；Blocked 不排帧、
     *          不扣窗口且不保留 Data，调用者须持有原缓冲并等待 AwaitWritable 后重试。
     *          Closed 表示本地发送半边已封止或远端已重置；Invalid 表示 stream/载荷参数无效。
     */
    enum class SubmitDataStatus : std::uint8_t
    {
        Accepted,
        Blocked,
        Closed,
        Invalid
    };

    /** @brief RFC 9113 定义的 HTTP/2 stream 错误码。 */
    inline constexpr std::uint32_t ErrorNoError = 0x0;
    inline constexpr std::uint32_t ErrorProtocol = 0x1;
    inline constexpr std::uint32_t ErrorInternal = 0x2;
    inline constexpr std::uint32_t ErrorFlowControl = 0x3;
    inline constexpr std::uint32_t ErrorStreamClosed = 0x5;
    inline constexpr std::uint32_t ErrorFrameSize = 0x6;
    inline constexpr std::uint32_t ErrorRefusedStream = 0x7;
    inline constexpr std::uint32_t ErrorCancel = 0x8;
    inline constexpr std::uint32_t ErrorCompression = 0x9;

    /** @brief 远端关闭接收方向或重置 HTTP/2 stream 的事件种类。 */
    enum class StreamReceiveClosureKind : std::uint8_t
    {
        EndStream,
        Reset
    };

    /**
     * @brief 远端 stream 接收关闭事件。
     * @details EndStream 仅关闭接收半边；Reset 即使错误码为 NO_ERROR 仍表示 RST_STREAM。
     */
    struct StreamReceiveClosure final
    {
        std::int32_t StreamId{0};
        StreamReceiveClosureKind Kind{StreamReceiveClosureKind::EndStream};
        std::uint32_t ErrorCode{0};
    };

    /**
     * @class H2Session
     * @brief HTTP/2 连接会话的稳定消费合同。
     * @details 调用者拥有 Session 和底层传输，并在其 Executor 上串行调用同步状态操作。
     *          Feed/Collect 仅在本次调用期间借用缓冲；其余同步提交也没有取消点。
     *          AwaitWritable 是唯一可挂起操作，取消或 native 等待错误通过 Failure 返回。
     *          Session 不启动后台协程，也不关闭底层传输；调用者先停止驱动并排空已收集的
     *          输出，再销毁 Session，最终传输关闭仍由外层连接 owner 负责。END_STREAM 只
     *          关闭其所在 stream 的发送半边；远端 END_STREAM 只关闭接收半边。
     */
    class H2Session
    {
    public:
        virtual ~H2Session() = default;

        /** @brief 同步投喂收到的字节；Data 只借用至本次调用返回。 */
        [[nodiscard]] virtual auto Feed(
            std::span<const std::byte> Data,
            std::error_code &ErrorCode) -> bool = 0;

        /** @brief 收集当前已排队的发送字节；Output 由调用者拥有。 */
        [[nodiscard]] virtual auto Collect(std::vector<std::byte> &Output) -> bool = 0;

        /**
         * @brief 打开新 stream；头字段仅借用至同步编码完成。
         * @return 成功返回新流 ID；服务端角色返回 NotSupported，参数/状态错误返回相应
         *         Failure，stream ID 耗尽返回 ResourceUnavailable。
         * @details 必须在 Executor 上串行调用；本操作同步完成且不可取消。EndStream 只关闭
         *          新 stream 的本地发送半边。调用者仍负责会话和底层传输的最终关闭。
         */
        [[nodiscard]] virtual auto OpenStream(
            const HeaderList &Headers,
            bool EndStream) -> std::expected<std::int32_t, Preview::Fault::Failure> = 0;

        /**
         * @brief 向已有 stream 提交头；头字段仅借用至同步编码完成。
         * @return 成功表示帧已放入会话队列；非法、已关闭或未知流返回完整 Failure。
         * @details 必须在 Executor 上串行调用；同步提交不可取消。EndStream 只关闭指定
         *          stream 的本地发送半边，不关闭会话或底层传输。
         */
        [[nodiscard]] virtual auto SubmitHeaders(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream) -> std::expected<void, Preview::Fault::Failure> = 0;

        /**
         * @brief 原子提交完整 DATA；仅 Accepted 会复制 Data 并预约对应发送窗口。
         * @param StreamId 已打开的 stream。
         * @param Data 借用缓冲；调用返回前读取。Blocked/Closed/Invalid 均不保留此缓冲。
         * @param EndStream Accepted 时是否同时结束本地发送半边。
         * @return Accepted、Blocked、Closed 或 Invalid；Blocked 不排帧且不扣窗口。
         * @details 调用方须在 Executor() 上串行驱动会话。Accepted 将整份 DATA 分帧复制到
         *          Session 发送队列；Blocked 后调用者继续拥有原缓冲，AwaitWritable 返回后重试。
         *          远端 END_STREAM 只封接收半边，不阻止本端发送。调用者拥有 Session 和
         *          底层传输，并负责在停止 Feed/Collect 且发送队列排空后完成最终关闭。
         */
        [[nodiscard]] virtual auto SubmitData(
            std::int32_t StreamId,
            std::span<const std::byte> Data,
            bool EndStream) -> SubmitDataStatus = 0;

        /**
         * @brief 可取消地等待指定 stream 与连接窗口都足以接纳完整数据块。
         * @param StreamId 等待的 stream。
         * @param RequiredBytes 一次 SubmitData 所需的完整字节数，必须大于零。
         * @return 窗口就绪为成功；取消、本地封止/重置、无效 stream 或 native wait 错误为完整失败。
         * @details 等待由 H2Session 的 Executor 驱动；有效 WINDOW_UPDATE、SETTINGS 初始窗口变化、
         *          stream reset/本地结束会唤醒并重查。调用方在成功前持续拥有原数据；成功只代表
         *          可重试，并不消费数据或预约窗口。调用方负责保活 Session 并在成功后重试 SubmitData；
         *          本操作不会接管 Session/传输的关闭责任。
         */
        [[nodiscard]] virtual auto AwaitWritable(
            std::int32_t StreamId,
            std::size_t RequiredBytes)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;

        /**
         * @brief 确认应用已消费收到的 DATA 并归还相应 flow-control credit。
         * @param StreamId 数据所属 stream。
         * @param Bytes 已消费的 DATA 载荷字节数。
         */
        virtual auto ConsumeData(std::int32_t StreamId, std::size_t Bytes) -> void = 0;

        /**
         * @brief 仅重置指定 stream，不关闭共享 HTTP/2 连接。
         * @return 成功表示 RST_STREAM 已入队；非法、关闭或未知流返回完整 Failure。
         * @details 必须在 Executor 上串行调用；同步入队不可取消。Session 与底层传输的
         *          最终关闭仍由外层连接 owner 负责。
         */
        [[nodiscard]] virtual auto ResetStream(
            std::int32_t StreamId,
            std::uint32_t ErrorCode) -> std::expected<void, Preview::Fault::Failure> = 0;

        /** @brief 返回会话保留的执行器副本。 */
        [[nodiscard]] virtual auto Executor() const -> Net::any_io_executor = 0;

        /**
         * @brief 收到 HEADERS 时同步调用。
         * @details Headers 仅在回调执行期间有效；需要保留时，调用者必须在返回前复制。
         */
        std::function<void(std::int32_t StreamId, const HeaderList &Headers, bool EndStream)> OnHeaders;

        /**
         * @brief 收到 DATA 时同步调用。
         * @details Data 仅在回调执行期间有效；需要保留时，调用者必须在返回前复制。
         */
        std::function<void(std::int32_t StreamId, std::span<const std::byte> Data)> OnData;

        /** @brief 收到远端 END_STREAM 或 RST_STREAM 时同步调用。 */
        std::function<void(const StreamReceiveClosure &Closure)> OnStreamClose;
    };

    /** @brief 可共享的 HTTP/2 会话接口句柄。 */
    using SharedH2Session = std::shared_ptr<H2Session>;

} // namespace Preview::Http2
