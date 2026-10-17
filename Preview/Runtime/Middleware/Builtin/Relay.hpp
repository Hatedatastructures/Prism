/** @file Relay.hpp @brief Runtime 管线只消费唯一 Net 可靠 relay owner。 */
#pragma once
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Relay/Relay.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>

namespace Preview::Middleware::Builtin
{
    namespace Net = boost::asio;
    /**
     * @brief 借用管线上下文至 relay 完成并返回完整 Failure。
     * @details Net relay owner 持有两端，处理取消、双向半关闭与最终关闭；Runtime 只投影 Code 写日志。
     * @param Inbound 借用的入站传输；relay 完成前不得关闭或替换。
     * @param ContextValue 借用至 awaitable 完成，提供 owning 出站传输与统计观察目标。
     * @return 最早方向的领域错误及 Native；成功返回空 Failure。
     * @note 在入站传输 executor 上运行；取消由调用者 awaitable 传递，Net relay owner 执行最终关闭。
     */
    class RelayMiddleware final : public Middleware
    {
    public:
        explicit RelayMiddleware(Preview::SharedTransmission Outbound,
            std::chrono::milliseconds IdleTimeout = std::chrono::seconds(300))
            : Outbound_(std::move(Outbound)), IdleTimeout_(IdleTimeout) {}
        [[nodiscard]] auto Name() const -> std::string_view override { return "relay"; }
        [[nodiscard]] auto LastTotals() const noexcept -> const std::array<std::size_t, 2>& { return Last_.Total; }
        [[nodiscard]] auto LastDirectionFailures() const noexcept -> const std::array<Preview::Fault::Failure, 2>&
        { return Last_.DirectionFailure; }
        /** @brief 共享传输作为拥有值移交，返回完整最终 Failure；流量观察仅投影已结束结果。 */
        auto Handle(Preview::SharedTransmission& Inbound, Context& ContextValue)
            -> Net::awaitable<Preview::Fault::Failure> override
        {
            auto Outbound = ContextValue.Outbound;
            if (!Outbound) Outbound = Outbound_;
            auto Timeout = IdleTimeout_;
            if (ContextValue.Timeout.count() > 0) Timeout = ContextValue.Timeout;
            Preview::Foundation::TrafficObservation Observation{
                ContextValue.Traffic,
                Preview::Foundation::TrafficEvent{
                    .Generation = ContextValue.TaskIdentity.Generation,
                    .Worker = ContextValue.TaskIdentity.WorkerId,
                    .Session = ContextValue.TaskIdentity.SessionId,
                    .Stream = ContextValue.TaskIdentity.StreamId,
                    .Task = ContextValue.TaskIdentity.TaskId,
                    .Account = ContextValue.DataPlane.AccountId,
                    .Protocol = static_cast<std::uint64_t>(ContextValue.DataPlane.Protocol)}};
            Last_ = co_await Preview::Network::Relay::Run(
                {Inbound, Outbound, ContextValue.BufferSize, Timeout, Observation,
                 ContextValue.Bytes, ContextValue.FirstTransfer});
            Observation.Complete(Last_.Failure);
            co_return Last_.Failure;
        }
    private:
        Preview::SharedTransmission Outbound_;
        std::chrono::milliseconds IdleTimeout_;
        Preview::Network::Relay::Result Last_;
    };
}
