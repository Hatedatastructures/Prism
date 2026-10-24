/**
 * @file TrafficSink.hpp
 * @brief 流量与 recognition admission 耗时的数值观察接口
 * @details 定义数据面与运行时统计之间的最小数值契约。普通流量报告不携带时间；
 *          recognition admission owner 只报告本次真实耗时和数值身份。
 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <variant>

namespace Prism::Foundation
{

    /** @brief 字节增量和一次终结观察分开计数；增量不得重复计入终结事件。 */
    enum class TrafficEventKind : std::uint8_t
    {
        Bytes,
        Completed,
        RecognitionLatency,
        ProtocolAssociated,
        NetworkLatency,
    };

    /** @brief 物理入口归属；未发布归属的路径保持 Unknown，不能推断为 TCP。 */
    enum class TrafficTransport : std::uint8_t { Unknown, Tcp, Udp, Quic };
    /** @brief 逻辑计量层级；Mux 子流不得再重复累计根承载字节。 */
    enum class TrafficPayloadLayer : std::uint8_t { Unknown, LogicalStream, Datagram, MuxStream };
    enum class NetworkLatencyStage : std::uint8_t { DnsResolution, TcpConnect };

    /** @struct TrafficEvent @brief 一次成功字节增量或终结的数值观察；终结不得重复累计已上报的字节。 */
    struct TrafficEvent final
    {
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId Task{};
        Prism::AccountId Account{};
        std::size_t Up{0};
        std::size_t Down{0};
        TrafficEventKind Kind{TrafficEventKind::Completed};
        /** @brief RecognitionLatency 事件中实际测得的 admission 微秒数。 */
        std::uint64_t DurationMicroseconds{0};
        std::uint64_t Protocol{0}; ///< 协议关联事件使用的 ProtocolType 数值身份。
        /** @brief 真实业务终态，观察丢弃及聚合失败另计，不改写此原因。 */
        Prism::Fault::Failure Failure{};
        std::uint64_t ProtocolInstance{0}; ///< 本代配置协议下标加一；零表示尚未归属。
        std::uint64_t Ingress{0}; ///< 本代配置入口下标加一；由 Transport 限定身份。
        TrafficTransport Transport{TrafficTransport::Unknown};
        TrafficPayloadLayer PayloadLayer{TrafficPayloadLayer::Unknown};
        NetworkLatencyStage NetworkStage{NetworkLatencyStage::DnsResolution};
    };

    /** @brief 一次真实入站 recognition admission 耗时；所有字段均为数值身份。 */
    struct RecognitionLatencySample final
    {
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        std::uint64_t DurationMicroseconds{0};
    };

    /**
     * @brief 入站 recognition admission 耗时 sink。
     * @details 调用方只在 owner 已安装时取时钟；实现必须非阻塞、无分配且 noexcept。
     *          样本生命周期归实现的有界队列，报告失败不得改变识别结果。
     */
    struct RecognitionLatencySink
    {
        virtual ~RecognitionLatencySink() = default;

        /** @brief 提交实际 measured duration；本接口不拥有调用方 Session。 */
        virtual auto ReportRecognitionLatency(RecognitionLatencySample Sample) noexcept -> void = 0;
    };

    /** @brief Session 动态统计 scope 的唯一最终关闭 owner。 */
    struct SessionTrafficOwner final
    {
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
    };

    /** @brief Stream 动态统计 scope 的唯一最终关闭 owner；wire ID 受父 Session 限定。 */
    struct StreamTrafficOwner final
    {
        Prism::WorkerId Worker{};
        Prism::SessionId ParentSession{};
        Prism::StreamId Stream{};
    };

    /** @brief Task 动态统计 scope 的真实 completion owner。 */
    struct TaskTrafficOwner final
    {
        Prism::WorkerId Worker{};
        Prism::TaskId Task{};
    };

    /** @brief 唯一允许退休的动态流量 scope；Process/Worker/Account 为累积事实。 */
    using TrafficRetirement = std::variant<SessionTrafficOwner, StreamTrafficOwner, TaskTrafficOwner>;

    /**
     * @struct TrafficSink
     * @brief 流量统计回调接口。
     * @details 数据面只提交 numeric TrafficEvent；观察失败或丢弃不得改变业务结果。
     *          实现不得拥有调用方数据面；退休必须由应用控制 executor 返回真实回执。
     */
    struct TrafficSink
    {
        virtual ~TrafficSink() = default;

        /** @brief 上报一次 numeric 流量统计；不得抛出或改变业务 fault。 */
        virtual auto Report(TrafficEvent Event) noexcept -> void = 0;

        /**
         * @brief 在应用控制 executor 刷新此前接收的报告并退休精确动态 scope。
         * @details Owner 按值移交且只含数值身份。调用者先完成业务取消、半关闭、最终关闭和 producer drain；
         *          本方法不执行网络关闭。开始前取消返回 Canceled；命令被接受后屏蔽取消，直至真实回执。
         *          executor 不可运行、scope 无效或聚合失败返回明确 Failure，不声称已退休。
         * @return 控制 executor 完成 Flush 与精确 scope 退休后的确认值。
         */
        virtual auto Retire(TrafficRetirement Owner)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
    };

    /**
     * @brief 持有统计 sink 至退休回执，将异步异常转成显式业务失败。
     * @details Sink 与 typed Owner 按值进入协程；调用者仍拥有 Session/Stream/Task 的关闭责任。
     */
    [[nodiscard]] auto RetireTraffic(std::shared_ptr<TrafficSink> Sink, TrafficRetirement Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

    /**
     * @brief 单个数据面的 owning 观察快照；只持 L1 sink 和数值身份，不保活业务 session。
     * @details 在实际 I/O executor 上报告成功写入的字节；不等待、不抛出。
     *          取消和半关闭不由观察器处理，最终业务 owner 排空后调用 Complete 一次。
     */
    struct TrafficObservation final
    {
        std::shared_ptr<TrafficSink> Sink;
        TrafficEvent Owner{};

        enum class Direction : std::uint8_t
        {
            Upload,
            Download
        };

        auto Transfer(std::size_t Count, Direction Way) const noexcept -> void;

        auto Complete(Prism::Fault::Failure Failure = {}) const noexcept -> void;
    };

} // namespace Prism::Foundation
