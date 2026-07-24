/**
 * @file forward_pipeline.hpp
 * @brief 转发流水线统一入口
 */
#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/resource/session.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/net/connect/target.hpp>
#include <prism/trace/context.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <memory>


namespace psm::connect
{
    namespace net = boost::asio;

    /**
     * @struct pipeline_options
     * @brief 转发流水线选项
     */
    struct pipeline_options
    {
        transport::shared_transmission inbound;
        std::shared_ptr<trace::trace_context> trace;

        explicit pipeline_options(
            transport::shared_transmission in,
            std::shared_ptr<trace::trace_context> tr)
            : inbound(std::move(in)), trace(std::move(tr))
        {
        }

        pipeline_options() = delete;
    };

    /**
     * @struct pipeline_stats
     */
    struct pipeline_stats
    {
        std::uint64_t total{0};
        std::uint64_t mux_sessions{0};
        std::uint64_t tcp_tunnels{0};
        std::uint64_t udp_associates{0};
        std::uint64_t failed{0};
    };

    /**
     * @brief 完整转发流水线
     */
    [[nodiscard]] auto forward_pipeline(
        psm::resource::session &res,
        const psm::connect::target &target,
        pipeline_options opts) -> net::awaitable<fault::code>;

    /**
     * @struct mux_session_options
     */
    struct mux_session_options
    {
        psm::resource::session &res;
        transport::shared_transmission transport;
        std::shared_ptr<trace::trace_context> trace;

        explicit mux_session_options(
            psm::resource::session &r,
            transport::shared_transmission t,
            std::shared_ptr<trace::trace_context> tr)
            : res(r), transport(std::move(t)), trace(std::move(tr))
        {
        }

        mux_session_options() = delete;
    };

    [[nodiscard]] auto spawn_mux_session(mux_session_options opts) -> net::awaitable<bool>;

} // namespace psm::connect
