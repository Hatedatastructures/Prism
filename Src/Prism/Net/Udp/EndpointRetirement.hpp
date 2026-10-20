/**
 * @file EndpointRetirement.hpp
 * @brief UDP relay 两端 Transmission 的类型化退休 owner。
 * @details 方向任务完成后依次交付 Cancel/Close 并等待两端 Activity::Drain；首个业务、取消、
 *          原生或退休失败优先返回。该 owner 不启动 socket I/O，也不定义 UDP 半关闭。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <exception>
#include <expected>
#include <memory>

namespace Prism::Transport
{
    class Unreliable;
}

namespace Prism::Network::Udp::Detail
{
    namespace Net = boost::asio;
    using RelayResult = std::expected<void, Prism::Fault::Failure>;

    /**
     * @class EndpointRetirement
     * @brief 持有两个 Unreliable 的唯一控制退休与活动排空 owner。
     * @details 方向协程组返回后调用 Finish。控制与排空的失败不会覆盖已记录的业务/取消/native 首因；
     *          未知致命异常在两端可达的退休步骤结束后重抛。
     */
    class EndpointRetirement final
    {
    public:
        /**
         * @brief 接管两个端点。
         * @param First A 端点；允许为空以返回 InvalidArgument。
         * @param Second B 端点；允许为空以返回 InvalidArgument。
         */
        EndpointRetirement(
            std::shared_ptr<Prism::Transport::Unreliable> First,
            std::shared_ptr<Prism::Transport::Unreliable> Second);

        /**
         * @brief 取消调用方取消并完成两端 Close/Drain。
         * @param Primary 方向操作的首个 typed/native 失败；成功时为空。
         * @param FatalException 非普通 Fault 异常；退休后重抛。
         * @return 首个 typed/native cause；所有交付及 drain 成功时返回成功。
         */
        [[nodiscard]] auto Finish(
            Prism::Fault::Failure Primary,
            std::exception_ptr FatalException) -> Net::awaitable<RelayResult>;

    private:
        auto Record(Prism::Fault::Failure Value) noexcept -> void;
        auto RecordException(std::exception_ptr Error) noexcept -> void;
        auto SubmitRetirement() -> void;
        [[nodiscard]] auto DrainRetired() -> Net::awaitable<void>;

        std::array<std::shared_ptr<Prism::Transport::Unreliable>, 2> Endpoints_;
        Prism::Fault::Failure Failure_;
        std::exception_ptr FatalException_;
    };
} // namespace Prism::Network::Udp::Detail
