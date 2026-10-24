/**
 * @file DataPlaneRelay.hpp
 * @brief typed data-plane、认证、拨号与双向中继 owner
 * @details admission 完成后，本 owner 只消费已经装配好的 Context；它负责
 *          mux/datagram 快路径和 stream 的 Auth/Pad/Dial/Relay 生命周期。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Fault/Failure.hpp>

namespace Prism::Middleware
{
    class Context;
}

namespace Prism::Runtime
{

    namespace Net = boost::asio;
    struct SessionRunContext;

    /**
     * @class SessionDataPlaneRelay
     * @brief Session typed data-plane 执行 owner
     */
    class SessionDataPlaneRelay final
    {
    public:
        /**
         * @brief 执行 mux、datagram 或 stream 数据面
         * @param Run 已完成 admission 的会话上下文
         * @return 数据面最终 typed failure；code-only 内部服务在本层显式投影。
         */
        [[nodiscard]] static auto Run(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>;

    private:
        [[nodiscard]] static auto RunMux(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto RunDatagram(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto RunStream(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto RunDialAndRelay(SessionRunContext &Run)
            -> Net::awaitable<Prism::Fault::Failure>;

        [[nodiscard]] static auto ApplyOutboundDecorator(SessionRunContext &Run) -> bool;

        static auto ReportCarrierInstallationFailure(
            SessionRunContext &Run,
            const Prism::Fault::Failure &Failure) -> void;

        [[nodiscard]] static auto InvokePostDial(
            Prism::Middleware::Context &Context,
            Prism::Fault::Failure Status) -> Net::awaitable<Prism::Fault::Failure>;
    };

} // namespace Prism::Runtime
