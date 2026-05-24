/**
 * @file MuxBootstrap.cpp
 * @brief bootstrap 协商单元测试
 * @details 测试 multiplex::bootstrap 的 sing-mux 协商路由逻辑：
 * 1. [Version=0, Protocol=0] 正确分发到 smux::craft
 * 2. [Version=0, Protocol=1] 正确分发到 yamux::craft
 * 3. [Version=0, Protocol=2] 正确分发到 h2mux::craft
 * 4. 无效版本号（Version>0 且无 padding 数据）被拒绝，返回 nullptr
 * 5. 无效协议号兜底到 smux::craft（default 分支）
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/connect/pool/pool.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/transport/transmission.hpp>

#include "common/TestRunner.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <system_error>
#include <vector>

#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

namespace net = boost::asio;

// ─── 本地 mock 传输层 ──────────────────────────────────────────────

/**
 * @class mock_transport
 * @brief bootstrap 测试用 mock 传输层
 * @details 预注入读取数据，数据耗尽后返回 connection_reset 错误。
 * 内部持有 io_context 引用以提供有效 executor，供 craft 构造函数
 * 创建 concurrent_channel 和 steady_timer。
 */
class mock_transport final : public psm::transport::transmission
{
public:
    /**
     * @brief 构造 mock 传输层
     * @param ioc 外部 io_context 引用，提供 executor
     */
    explicit mock_transport(net::io_context &ioc) : ioc_(ioc)
    {
    }

    [[nodiscard]] auto executor() const -> executor_type override
    {
        return ioc_.get_executor();
    }

    /**
     * @brief 异步读取，从预注入数据中返回
     * @details 数据耗尽时返回 connection_reset 错误，促使 negotiate 提前终止。
     */
    auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override
    {
        if (pos_ < data_.size())
        {
            const auto n = (std::min)(buffer.size(), data_.size() - pos_);
            std::copy_n(data_.data() + pos_, n, buffer.data());
            pos_ += n;
            co_return n;
        }
        ec = std::make_error_code(std::errc::connection_reset);
        co_return 0;
    }

    /**
     * @brief 异步写入（此测试不使用写入路径，直接返回成功）
     */
    auto async_write_some(std::span<const std::byte> buffer, std::error_code & /*ec*/)
        -> net::awaitable<std::size_t> override
    {
        co_return buffer.size();
    }

    void close() override
    {
    }

    void cancel() override
    {
    }

    /**
     * @brief 预注入读取数据
     * @param data 要注入的字节序列
     */
    auto feed(std::vector<std::byte> data) -> void
    {
        data_ = std::move(data);
        pos_ = 0;
    }

private:
    net::io_context &ioc_;
    std::vector<std::byte> data_;
    std::size_t pos_ = 0;
};

// ─── 测试运行器 ──────────────────────────────────────────────────

namespace
{
    psm::testing::TestRunner runner("MuxBootstrap");
} // namespace

// ─── 测试用例 ────────────────────────────────────────────────────

/**
 * @brief 测试 [Version=0, Protocol=0] 分发到 smux
 * @details Protocol=0 对应 multiplex::protocol_type::smux，
 * bootstrap 应创建 smux::craft 实例。
 */
void TestVersion0Protocol0Smux(net::io_context &ioc, psm::connect::router &rtr,
                                const psm::multiplex::config &cfg)
{
    runner.LogInfo("=== TestVersion0Protocol0Smux ===");

    auto transport = std::make_shared<mock_transport>(ioc);
    transport->feed({std::byte(0x00), std::byte(0x00)});

    psm::multiplex::bootstrap_context ctx{
        .transport = transport,
        .router = rtr,
        .cfg = cfg,
    };

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await psm::multiplex::bootstrap(std::move(ctx));

        runner.Check(result != nullptr, "[V=0,P=0] session created");
        runner.Check(dynamic_cast<psm::multiplex::smux::craft *>(result.get()) != nullptr,
                     "[V=0,P=0] session is smux::craft");
    };

    net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试 [Version=0, Protocol=1] 分发到 yamux
 * @details Protocol=1 对应 multiplex::protocol_type::yamux，
 * bootstrap 应创建 yamux::craft 实例。
 */
void TestVersion0Protocol1Yamux(net::io_context &ioc, psm::connect::router &rtr,
                                 const psm::multiplex::config &cfg)
{
    runner.LogInfo("=== TestVersion0Protocol1Yamux ===");

    auto transport = std::make_shared<mock_transport>(ioc);
    transport->feed({std::byte(0x00), std::byte(0x01)});

    psm::multiplex::bootstrap_context ctx{
        .transport = transport,
        .router = rtr,
        .cfg = cfg,
    };

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await psm::multiplex::bootstrap(std::move(ctx));

        runner.Check(result != nullptr, "[V=0,P=1] session created");
        runner.Check(dynamic_cast<psm::multiplex::yamux::craft *>(result.get()) != nullptr,
                     "[V=0,P=1] session is yamux::craft");
    };

    net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试 [Version=0, Protocol=2] 分发到 h2mux
 * @details Protocol=2 对应 multiplex::protocol_type::h2mux，
 * bootstrap 应创建 h2mux::craft 实例。
 */
void TestVersion0Protocol2H2mux(net::io_context &ioc, psm::connect::router &rtr,
                                 const psm::multiplex::config &cfg)
{
    runner.LogInfo("=== TestVersion0Protocol2H2mux ===");

    auto transport = std::make_shared<mock_transport>(ioc);
    transport->feed({std::byte(0x00), std::byte(0x02)});

    psm::multiplex::bootstrap_context ctx{
        .transport = transport,
        .router = rtr,
        .cfg = cfg,
    };

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await psm::multiplex::bootstrap(std::move(ctx));

        runner.Check(result != nullptr, "[V=0,P=2] session created");
        runner.Check(dynamic_cast<psm::multiplex::h2mux::craft *>(result.get()) != nullptr,
                     "[V=0,P=2] session is h2mux::craft");
    };

    net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试无效版本号被拒绝
 * @details Version=1 触发 negotiate 读取 padding 长度字段，
 * 但 mock 传输层仅提供 2 字节 header，后续读取返回 connection_reset。
 * negotiate 返回错误码，bootstrap 返回 nullptr。
 */
void TestInvalidVersionRejected(net::io_context &ioc, psm::connect::router &rtr,
                                 const psm::multiplex::config &cfg)
{
    runner.LogInfo("=== TestInvalidVersionRejected ===");

    auto transport = std::make_shared<mock_transport>(ioc);
    // Version=1, Protocol=0，但不提供后续 padding 数据
    transport->feed({std::byte(0x01), std::byte(0x00)});

    psm::multiplex::bootstrap_context ctx{
        .transport = transport,
        .router = rtr,
        .cfg = cfg,
    };

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await psm::multiplex::bootstrap(std::move(ctx));

        runner.Check(result == nullptr, "[V=1,P=0] no padding -> rejected (nullptr)");
    };

    net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试无效协议号被拒绝
 * @details Protocol=99 不在合法枚举范围 [smux=0, yamux=1, h2mux=2] 内，
 * bootstrap 的 switch 命中 default 分支，兜底创建 smux::craft。
 */
void TestInvalidProtocolRejected(net::io_context &ioc, psm::connect::router &rtr,
                                  const psm::multiplex::config &cfg)
{
    runner.LogInfo("=== TestInvalidProtocolRejected ===");

    auto transport = std::make_shared<mock_transport>(ioc);
    // Version=0, Protocol=99 (无效值)
    transport->feed({std::byte(0x00), std::byte(0x63)});

    psm::multiplex::bootstrap_context ctx{
        .transport = transport,
        .router = rtr,
        .cfg = cfg,
    };

    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await psm::multiplex::bootstrap(std::move(ctx));

        runner.Check(result != nullptr, "[V=0,P=99] session created (smux fallback)");
        runner.Check(dynamic_cast<psm::multiplex::smux::craft *>(result.get()) != nullptr,
                     "[V=0,P=99] fallback to smux::craft");
    };

    net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

// ─── 入口 ────────────────────────────────────────────────────────

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    try
    {
        psm::memory::system::enable_global_pooling();
        psm::trace::init({});

        // 共享基础设施：io_context、连接池、路由器、多路复用配置
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        psm::connect::router rtr(pool, ioc, psm::resolve::dns::config{});
        psm::multiplex::config mux_cfg;

        TestVersion0Protocol0Smux(ioc, rtr, mux_cfg);
        ioc.restart();

        TestVersion0Protocol1Yamux(ioc, rtr, mux_cfg);
        ioc.restart();

        TestVersion0Protocol2H2mux(ioc, rtr, mux_cfg);
        ioc.restart();

        TestInvalidVersionRejected(ioc, rtr, mux_cfg);
        ioc.restart();

        TestInvalidProtocolRejected(ioc, rtr, mux_cfg);

        return runner.Summary();
    }
    catch (const std::exception &e)
    {
        psm::trace::shutdown();
        psm::trace::error("[MuxBootstrap] fatal: {}", e.what());
        return 1;
    }
}
