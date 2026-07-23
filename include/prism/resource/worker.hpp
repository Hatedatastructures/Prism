/**
 * @file worker.hpp
 * @brief 工作级资源容器
 * @details 纯数据 struct，2 函数（alive + stop）。shared_ptr 由
 *          runtime::worker 和所有 session 共享。析构顺序：先 reset
 *          dns/router（cancel timer），再 poll ioc 清空 pending completion。
 */
#pragma once

#include <prism/resource/process.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/foundation/coroutine/registry.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/foundation/rate/counter.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/outbound/direct.hpp>
#include <prism/net/connect/outbound/proxy.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/route/table.hpp>
#include <prism/net/dns/resolver.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <memory>


namespace psm::resource
{

/**
 * @struct worker
 * @brief 工作级资源（L2）
 */
struct worker
{
    /**
     * @brief 构造参数
     */
    struct options
    {
        std::shared_ptr<process>       process;
        psm::memory::resource_pointer  mr;
        std::uint32_t                  index = 0;
    };

    explicit worker(options opts);
    ~worker() noexcept;

    worker(const worker&) = delete;
    auto operator=(const worker&) -> worker& = delete;

    /**
     * @brief 检查资源链是否存活
     * @return worker 未停止返回 true
     */
    [[nodiscard]] auto alive() const noexcept
        -> bool;

    /**
     * @brief 触发停机（停止 io_context）
     */
    auto stop() -> void;

    std::shared_ptr<process> process;

    psm::memory::resource_pointer               memory;
    boost::asio::io_context                     ioc;
    psm::connect::connection_pool               pool;
    std::unique_ptr<psm::connect::router>       router;
    psm::connect::route_table                   routes;
    std::unique_ptr<psm::outbound::direct>      outbound;
    psm::stats::traffic::traffic_state          traffic;
    psm::rate::counter                          rate;
    psm::coroutine::task_registry               tasks;

private:
    std::atomic<bool> alive_{true};
};

} // namespace psm::resource
