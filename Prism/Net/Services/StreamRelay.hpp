/**
 * @file StreamRelay.hpp
 * @brief StreamRelay 端口的拥有型 Net 中继实现。
 */
#pragma once
#include <Prism/Contract/Services/Stream.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <cstddef>
#include <chrono>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Network
{
    /** @brief StreamRelay 冷路径快照；拥有 sink，并固定本次 relay 的缓冲区和空闲超时策略。 */
    struct StreamRelayOptions final
    {
        std::shared_ptr<Prism::Foundation::TrafficSink> Traffic;
        std::size_t BufferSize{16 * 1024};
        std::chrono::milliseconds IdleTimeout{0};
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    /**
     * @class StreamRelayService
     * @brief 实现中立 StreamRelay 端口的拥有型网络服务。
     * @details Run 按值接管请求中的两端 Transmission 与 stream 租约；BytePool 和统计 sink 由选项中的
     *          共享所有者持有。调用方执行器进入 Net::Relay 后固定到入站端的串行域，半关闭按
     *          双向 pump 顺序执行。成功字节和底层失败以 类型化结果结算；取消/失败会关闭两端并
     *          等待 Activity Drain，最终连接关闭由 Net::Relay 持有，租约在真实退栈后归还。
     * @note 本服务不保留跨请求的连接、缓冲区租约或执行器状态。
     */
    class StreamRelayService final : public Prism::Contract::StreamRelay
    {
    public:
        explicit StreamRelayService(StreamRelayOptions Options)
            : Options_(std::move(Options)) {}
        /**
         * @brief 按值接管两端与真实 stream 租约；当前协程执行器驱动 Net::Relay，实际 drain 完成后归还租约。
         * @details 半关闭和最终关闭由 Net owner，错误随 tunnel 收口；前置成功字节与 relay
         *          实际写入分别提交增量，终结只报告一次零字节事件，观察失败不入业务 fault。
         * @note 返回 awaitable 前按值复制 Options 并接管 Request；服务对象可在本次 relay 期间释放。
         */
        [[nodiscard]] auto Run(Prism::Contract::StreamRelayRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            return RunOwned(Options_, std::move(Request));
        }

    private:
        [[nodiscard]] static auto RunOwned(
            StreamRelayOptions Options,
            Prism::Contract::StreamRelayRequest Request)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Prism::Foundation::TrafficObservation Observation{
                Options.Traffic,
                Prism::Foundation::TrafficEvent{
                    .Generation = Request.Metadata.TaskIdentity.Generation,
                    .Worker = Request.Metadata.TaskIdentity.WorkerId,
                    .Session = Request.Metadata.TaskIdentity.SessionId,
                    .Stream = Request.Metadata.TaskIdentity.StreamId,
                    .Task = Request.Metadata.TaskIdentity.TaskId,
                    .Account = Request.AccountId}};
            Observation.Transfer(Request.InitialUploadBytes,
                Prism::Foundation::TrafficObservation::Direction::Upload);
            const auto Result = co_await Prism::Network::Relay::Run(
                {std::move(Request.Inbound), std::move(Request.Outbound),
                 Options.BufferSize, Options.IdleTimeout, Observation, Options.Bytes});
            Observation.Complete(Result.Failure);
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        StreamRelayOptions Options_;
    };
}
