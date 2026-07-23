/**
 * @file session.hpp
 * @brief 会话级资源容器
 * @details 纯数据 struct，1 函数（alive）。shared_ptr 由 runtime::session 持有。
 *          包含所有 session 级资源和上级 worker 的共享所有权。
 */
#pragma once

#include <prism/resource/worker.hpp>
#include <prism/account/entry.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/trace/context.hpp>

#include <array>
#include <cstdint>
#include <memory>


namespace psm::resource
{

/**
 * @struct metadata
 * @brief 请求级业务数据
 * @details 对标 mihomo 的 *Metadata。从 L1 构造，在 L2 各层流转，
 *          每层可读可填。shared_ptr 管理，detached 协程安全。
 */
struct metadata
{
    boost::asio::ip::tcp::endpoint src{};
    boost::asio::ip::tcp::endpoint dst{};
    std::array<std::byte, 16>      src_ip{};
    std::uint64_t                  conn_id{0};
};

/**
 * @struct session
 * @brief 会话级资源（L3）
 */
struct session
{
    /**
     * @brief 构造参数
     */
    struct options
    {
        std::shared_ptr<worker>                    worker;
        std::uint64_t                              conn = 0;
        std::uint32_t                              buffer = 0;
        psm::transport::shared_transmission        inbound;
        std::array<std::byte, 16>                  src = {};
        std::shared_ptr<psm::trace::trace_context> trace;
        std::shared_ptr<metadata>                  meta;
    };

    explicit session(options opts);

    session(const session&) = delete;
    auto operator=(const session&) -> session& = delete;

    /**
     * @brief 检查资源链是否存活
     * @return 上级 worker 未停止返回 true
     */
    [[nodiscard]] auto alive() const noexcept
        -> bool;

    std::shared_ptr<worker> worker;

    std::uint64_t                              conn;
    std::uint32_t                              buffer;
    psm::transport::shared_transmission        inbound;
    psm::transport::shared_transmission        outbound;
    psm::connect::protocol_type                detected{};
    psm::account::lease                        lease;
    std::shared_ptr<metadata>                  meta;
    std::shared_ptr<psm::trace::trace_context> trace;
    psm::memory::frame_arena                   arena;
    std::array<std::byte, 16>                  src;
};

} // namespace psm::resource
