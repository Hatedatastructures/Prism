/**
 * @file dial.hpp
 * @brief 出站统一拨号入口
 * @details 所有上游连接（含伪装层 fallback、协议 handler 拨号）必须通过
 * outbound::dial() 进入。内部完成：DNS 解析、Happy Eyeballs、连接池复用、
 * IPv6 策略、反向路由、流量统计通知。
 *
 * 设计目的：
 *   - 替代 restls/shadowtls 中裸 net::async_connect 的反模式
 *   - 替代 reality 中绕过 dial/router 的 outbound->async_connect 直调
 *   - 提供统一的诊断元数据（DNS 缓存命中、连接池命中、耗时、反向路由命中）
 *
 * @note 调用方必须先 lock worker::borrow 得到 handle 再传入
 * @warning 不允许在伪装层直接调 net::async_connect，必须走本入口
 */
#pragma once

#include <prism/worker/resources.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/net/transport/transmission.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/trace/context.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>


namespace psm::outbound
{
    namespace net = boost::asio;

    /**
     * @struct dial_options
     * @brief 拨号策略选项
     * @details 控制拨号超时、是否允许反向路由、是否上报流量等。
     */
    struct dial_options
    {
        std::shared_ptr<trace::trace_context> trace;                        ///< 日志前缀
        std::chrono::milliseconds timeout{std::chrono::seconds(10)};        ///< 拨号超时
        bool allow_reverse{true};                                           ///< 是否允许反向路由（伪装层 fallback 应禁用）
        bool report_traffic{true};                                          ///< 是否上报流量统计（traffic_state::on_connect）
    };

    /**
     * @struct dial_result
     * @brief 拨号结果
     * @details 包含错误码、传输层对象和诊断元数据（DNS 命中、连接池命中、耗时、反向路由命中）。
     * 诊断元数据用于 dial_stats 累加和日志诊断。
     */
    struct dial_result
    {
        fault::code code{fault::code::success};     ///< 错误码
        transport::shared_transmission transport;   ///< 传输层对象（失败时为空）
        std::chrono::milliseconds elapsed{0};       ///< 拨号耗时
        bool dns_cache_hit{false};                  ///< DNS 缓存命中标志
        bool pool_hit{false};                       ///< 连接池命中标志
        bool reverse_routed{false};                 ///< 反向路由命中标志
    };

    /**
     * @struct dial_stats
     * @brief 拨号累计统计
     * @details worker::resources 持有，通过 worker_snapshot 暴露给 balancer/HTTP API。
     * 所有字段为松散一致快照。
     */
    struct dial_stats
    {
        std::uint64_t total{0};                       ///< 总拨号次数
        std::uint64_t succeeded{0};                   ///< 成功次数
        std::uint64_t failed{0};                      ///< 失败次数
        std::uint64_t cache_hits{0};              ///< DNS 缓存命中次数
        std::uint64_t pool_hits{0};                   ///< 连接池命中次数
        std::uint64_t ipv6_rejected{0};               ///< IPv6 被拒绝次数
        std::uint64_t reverse_routed{0};              ///< 反向路由命中次数
        std::chrono::milliseconds avg_latency{0};     ///< 平均耗时（EMA 估算）
    };

    /**
     * @brief 统一拨号入口
     * @param handle worker 资源 handle（强引用，调用方持 shared_ptr）
     * @param target 拨号目标（host/port/positive 标记）
     * @param opts 拨号选项
     * @return 拨号结果（含传输层和诊断元数据）
     * @details 内部流程：
     *   1. 反向路由检查（target.positive == false 且 allow_reverse 时）
     *   2. IP 字面量直连（跳过 DNS）
     *   3. DNS 解析（dns_gateway）→ Happy Eyeballs（address_racer）
     *   4. 连接池复用（connection_pool::async_acquire）
     *   5. 流量统计通知（traffic_state::on_connect）
     *   6. 累加 dial_stats
     *
     * 失败时 code 非 success，transport 为空。
     */
    [[nodiscard]] auto dial(
        psm::worker::handle handle,
        const protocol::target &target,
        dial_options opts) -> net::awaitable<dial_result>;

    /**
     * @brief 数据报端点解析（UDP）
     * @param handle worker 资源 handle
     * @param host 目标主机
     * @param port 目标端口字符串
     * @return 错误码和 UDP 端点
     * @details 仅解析，不创建 UDP socket。供 UDP_ASSOCIATE 等场景使用。
     */
    [[nodiscard]] auto resolve_datagram(
        psm::worker::handle handle,
        std::string_view host,
        std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;

} // namespace psm::outbound
