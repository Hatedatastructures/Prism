/** @file Relay.hpp @brief Runtime 管线只消费唯一 Net 可靠 relay owner。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace Prism::Middleware::Builtin
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
        explicit RelayMiddleware(Prism::SharedTransmission Outbound,
            std::chrono::milliseconds IdleTimeout = std::chrono::seconds(300))
            : Outbound_(std::move(Outbound)), IdleTimeout_(IdleTimeout) {}
        [[nodiscard]] auto Name() const -> std::string_view override { return "relay"; }
        [[nodiscard]] auto LastTotals() const noexcept -> const std::array<std::size_t, 2>& { return Last_.Total; }
        [[nodiscard]] auto LastDirectionFailures() const noexcept -> const std::array<Prism::Fault::Failure, 2>&
        { return Last_.DirectionFailure; }
        /** @brief 共享传输作为拥有值移交，返回完整最终 Failure；流量观察仅投影已结束结果。 */
        auto Handle(Prism::SharedTransmission& Inbound, Context& ContextValue)
            -> Net::awaitable<Prism::Fault::Failure> override;
    private:
        Prism::SharedTransmission Outbound_;
        std::chrono::milliseconds IdleTimeout_;
        Prism::Network::Relay::Result Last_;
    };
}
