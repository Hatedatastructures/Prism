/**
 * @file Contract.hpp
 * @brief 多路复用会话的公开契约和共享状态。
 * @details 会话行为按状态、流控、写入、帧处理和拆除职责分布到聚合头；
 *          本文件只拥有类型契约、成员声明和跨职责共享的状态。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Mux/SessionOptions.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Mux/Codec.hpp>
#include <Prism/Protocols/Mux/Stream/State.hpp>

namespace Prism::Mux
{

    /**
     * @class Session
     * @brief 多路复用会话（共享框架，模板注入帧编解码策略）。
     * @tparam C 帧编解码策略（FrameCodec concept）。
     * @tparam Memory 会话内存策略（默认 8KB Arena；下发给流句柄）。
     * @details 本声明拥有跨职责共享的会话状态；成员实现由 Session.hpp
     *          聚合的职责头提供。
     */
    template <typename C,
              Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Session : public SessionIface,
                    public std::enable_shared_from_this<Session<C, Memory>>
    {
    private:
        using FlowNotify = Net::experimental::channel<void(boost::system::error_code)>;

        struct FlowState
        {
            std::uint64_t SendWindow{0};
            std::uint64_t ReceiveWindow{0};
            std::shared_ptr<FlowNotify> Notify{};
        };

        /**
         * @struct WriteRequest
         * @brief 唯一 writer 队列中的帧请求。
         * @details 请求节点由 producer 与 writer 共享所有权；完成通过 channel
         *          传递，writer 不依赖 producer 的二次确认即可推进队列。
         */
        struct WriteRequest
        {
            explicit WriteRequest(Net::any_io_executor Ex, std::vector<std::uint8_t> FrameValue)
                : Frame(std::move(FrameValue)), Completion(Ex, 1)
            {
            }

            std::vector<std::uint8_t> Frame;
            Net::experimental::channel<void(boost::system::error_code, ProtocolEc)> Completion;
            bool Canceled{false};
            bool BudgetReleased{false};
            bool CompletionSent{false};
        };

    public:
        using FrameType = typename C::FrameType;

        /// 内存策略类型（对外暴露，供嵌套层/测试使用）。
        using MemoryType = Memory;

        /** @brief 创建会话（同时启动帧循环）。 */
        static auto Create(SharedTransmission Raw, const SessionOptions &Options)
            -> std::shared_ptr<Session<C, Memory>>;

        /** @brief 打开新流（客户端视角）。 */
        auto OpenStream() -> Net::awaitable<std::shared_ptr<StreamHandle<Memory>>>;

        /** @brief 接受新流（服务端视角）。 */
        auto AcceptStream() -> Net::awaitable<std::shared_ptr<StreamHandle<Memory>>>;

        /** @brief 推送数据帧到流（StreamHandle 回调）。 */
        auto PushData(std::uint32_t StreamId, std::span<const std::uint8_t> Data)
            -> Net::awaitable<ProtocolEc> override;

        /** @brief 发送 FIN（StreamHandle 回调）。 */
        auto SendFin(std::uint32_t StreamId) -> Net::awaitable<void> override;

        /** @brief 发送 RST（StreamHandle 回调）。 */
        auto SendRst(std::uint32_t StreamId) -> Net::awaitable<void> override;

        /** @brief 移除流（StreamHandle 回调）。 */
        auto RemoveStream(std::uint32_t StreamId) -> void override;

        /** @brief 会话是否打开。 */
        [[nodiscard]] auto IsOpen() const -> bool override;

        /** @brief 流消费接收队列字节后的预算归还。 */
        void OnStreamRxConsumed(std::uint32_t StreamId, std::size_t Bytes) noexcept override;

        /** @brief 获取执行器。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override;

        /** @brief 当前活跃流数。 */
        [[nodiscard]] auto StreamCount() const -> std::size_t;

        /** @brief 关闭会话（全部流和底层连接）。 */
        auto Close() -> Net::awaitable<void>;
        /** @brief 请求本 engine 关闭且唤醒全部任务；无协程自登记，外部 Close await 实际 drain。 */
        auto RequestClose() noexcept -> void;

        /** @brief 取消挂起的 AcceptStream（不关闭会话）。 */
        auto Cancel() -> void;

        /** @brief 本 engine 的真实任务 scope，供 child FIN/reset 登记与外层最终 drain。 */
        [[nodiscard]] auto Tasks() const noexcept
            -> std::shared_ptr<Prism::Lifecycle::TaskRegistry>;

    private:
        [[nodiscard]] static constexpr auto UsesFlowControl() noexcept -> bool;
        [[nodiscard]] static constexpr auto InitialFlowWindow() noexcept -> std::uint64_t;

        auto InitializeLocalFlow(std::uint32_t StreamId) -> void;
        auto InitializeIncomingFlow(const FrameType &Frame) -> void;
        auto RemoveFlow(std::uint32_t StreamId) -> void;
        auto WakeFlowWaiters() noexcept -> void;
        auto AddSendWindow(std::uint32_t StreamId, std::uint32_t Delta) -> void;
        auto ReturnSendWindow(std::uint32_t StreamId, std::size_t Delta) -> void;
        [[nodiscard]] auto ReserveSendWindow(std::uint32_t StreamId, std::size_t Requested)
            -> std::size_t;
        [[nodiscard]] auto WaitForSendWindow(std::uint32_t StreamId) -> Net::awaitable<bool>;
        auto IncreaseReceiveWindow(std::uint32_t StreamId, std::uint32_t Delta) -> void;
        [[nodiscard]] auto DeliverRx(
            const std::shared_ptr<StreamHandle<Memory>> &Handle,
            std::span<const std::uint8_t> Payload) -> bool;

        auto EnqueueWrite(std::vector<std::uint8_t> Frame, ProtocolEc &ErrorCode)
            -> std::shared_ptr<WriteRequest>;
        auto RawWrite(std::vector<std::uint8_t> Frame) -> Net::awaitable<ProtocolEc>;

        template <std::size_t Size>
        auto RawWrite(std::array<std::uint8_t, Size> Frame) -> Net::awaitable<ProtocolEc>;

        auto DispatchOpen(const FrameType& Frame, std::span<const std::uint8_t> Payload) -> void;
        auto DispatchData(const FrameType& Frame, std::span<const std::uint8_t> Payload) -> void;

        Session(SharedTransmission Raw, const SessionOptions &Options);

        auto Start() -> void;
        auto StartWriter() -> void;
        auto CompleteWriteRequest(
            const std::shared_ptr<WriteRequest> &Request,
            const ProtocolEc &ErrorCode) -> void;
        auto FailPendingWrites(const ProtocolEc &ErrorCode) -> void;
        auto WriteLoop() -> Net::awaitable<void>;

        auto FrameLoop() -> Net::awaitable<void>;
        auto Dispatch(const FrameType &Frame, std::span<const std::uint8_t> Payload) -> void;
        auto AllocateId() -> std::uint32_t;
        [[nodiscard]] auto IsPeerStreamId(std::uint32_t Id) const noexcept -> bool;

        auto Teardown(
            Prism::Fault::Failure ReadTerminal = {},
            const ProtocolEc &PendingError = make_error_code(Error::BrokenPipe)) -> void;
        static auto DrainOnRequestClose(std::shared_ptr<Session> Self)
            -> Net::awaitable<void>;
        auto CloseOnExecutor() noexcept -> void;
        auto CancelRawOnExecutor() noexcept -> void;
        auto RetireStreamsOnExecutor() noexcept -> void;
        auto ReleasePendingWriteBudget(
            const std::shared_ptr<WriteRequest> &Request) noexcept -> void;
        auto ProtocolErrorTeardown() -> void;

        static auto RunFrame(std::shared_ptr<Session> Self) -> Net::awaitable<void>;
        static auto RunWriter(std::shared_ptr<Session> Self) -> Net::awaitable<void>;
        auto CancelRaw() noexcept -> void;
        [[nodiscard]] auto TaskContextForStream(std::uint32_t Id) const noexcept
            -> Prism::Lifecycle::TaskContext;

        SharedTransmission Raw_; ///< 底层传输。
        SessionOptions Opt_; ///< 会话选项。
        Net::any_io_executor Ex_; ///< 执行器。
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks_; ///< 协议拥有的 frame/writer/FIN scope。
        Prism::Lifecycle::TaskIdentity Identity_{}; ///< 父任务身份。
        Net::experimental::channel<void(boost::system::error_code)> AcceptNotify_; ///< 新流通知。
        std::map<std::uint32_t, std::shared_ptr<StreamHandle<Memory>>> Streams_; ///< 流表。
        std::deque<std::shared_ptr<StreamHandle<Memory>>> Incoming_; ///< 入向流队列。
        std::deque<std::shared_ptr<WriteRequest>> PendingWrites_; ///< 唯一 writer 队列。
        std::map<std::uint32_t, FlowState> Flow_; ///< 每流发送/接收窗口。
        std::uint32_t NextId_{0}; ///< 下一个流 ID 候选。
        bool StreamIdExhausted_{false}; ///< 32 位流 ID 已耗尽。
        std::size_t SessionRxBytes_{0}; ///< 会话接收队列当前总字节数。
        std::size_t PendingWriteBytes_{0}; ///< 当前未完成写请求总字节数。
        bool SessionClosed_{false}; ///< 会话已关闭。
        bool CloseStarted_{false}; ///< 本 executor 已接管唯一关闭动作。
        bool StreamsRetired_{false}; ///< 流表已切断反向 owner 并清空。
        bool Canceled_{false}; ///< Accept 被取消（一次性）。
        bool WriterRunning_{false}; ///< writer 协程已运行。
    };

} // namespace Prism::Mux
