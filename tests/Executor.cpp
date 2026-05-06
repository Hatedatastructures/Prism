/**
 * @file Executor.cpp
 * @brief scheme_executor 管道逻辑单元测试
 * @details 测试 scheme_executor 的候选排序、跳过禁用方案、
 * 未知方案名跳过、native 兜底等管道行为。
 * 使用 mock scheme 替代真实方案，避免实际 TLS 握手。
 */

#include <prism/stealth/executor.hpp>
#include <prism/stealth/registry.hpp>
#include <prism/stealth/scheme.hpp>
#include <prism/recognition/result.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/fault/code.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory.hpp>
#include <prism/trace.hpp>
#include <prism/config.hpp>
#include <prism/channel/transport/transmission.hpp>
#include "common/TestRunner.hpp"

#include <boost/asio.hpp>

#ifdef WIN32
#include <windows.h>
#endif

namespace net = boost::asio;
using psm::recognition::confidence;

namespace
{
    /**
     * @class mock_transport
     * @brief 用于测试的 mock 传输层
     * @details 满足 executor 的成功条件检查（transport != nullptr）
     */
    class mock_transport final : public psm::channel::transport::transmission
    {
    public:
        explicit mock_transport(net::any_io_executor exec) : exec_(exec)
        {
        }

        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return exec_;
        }

        auto async_read_some(std::span<std::byte> /*buffer*/, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec = std::make_error_code(std::errc::operation_not_supported);
            co_return 0;
        }

        auto async_write_some(std::span<const std::byte> /*buffer*/, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec = std::make_error_code(std::errc::operation_not_supported);
            co_return 0;
        }

        void close() override
        {
        }

        void cancel() override
        {
        }

    private:
        net::any_io_executor exec_;
    };

    /**
     * @class mock_scheme
     * @brief 用于测试的 mock 伪装方案
     * @details execute() 返回预设的 scheme_result，不做任何 I/O。
     * detect() 始终返回 none（不影响 executor 管道逻辑测试）。
     */
    class mock_scheme final : public psm::stealth::stealth_scheme
    {
    public:
        mock_scheme(std::string name, psm::protocol::protocol_type detected,
                    bool enabled = true) noexcept
            : name_(std::move(name)), detected_(detected), enabled_(enabled)
        {
        }

        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return name_;
        }

        [[nodiscard]] auto is_enabled([[maybe_unused]] const psm::config &cfg) const noexcept
            -> bool override
        {
            return enabled_;
        }

        [[nodiscard]] auto detect([[maybe_unused]] const psm::protocol::tls::client_hello_features &features,
                                  [[maybe_unused]] const psm::config &cfg) const
            -> psm::stealth::detection_result override
        {
            return {.confidence = confidence::none, .reason = "mock"};
        }

        [[nodiscard]] auto execute(psm::stealth::scheme_context ctx)
            -> net::awaitable<psm::stealth::scheme_result> override
        {
            psm::stealth::scheme_result result;
            result.detected = detected_;
            // 使用 mock transport 满足 executor 的成功条件检查
            // executor 要求 transport != nullptr 才认为执行成功
            if (ctx.inbound)
                result.transport = ctx.inbound;
            else
                result.transport = std::make_shared<mock_transport>(net::system_executor());
            co_return result;
        }

    private:
        std::string name_;
        psm::protocol::protocol_type detected_;
        bool enabled_;
    };

    auto register_mocks() -> void
    {
        auto &reg = psm::stealth::scheme_registry::instance();

        // mock_a: 返回 TLS（表示"不是我"，executor 应跳过）
        reg.add(std::make_shared<mock_scheme>("mock_a", psm::protocol::protocol_type::tls));
        // mock_b: 返回 Trojan（表示成功匹配）
        reg.add(std::make_shared<mock_scheme>("mock_b", psm::protocol::protocol_type::trojan));
        // mock_disabled: 返回 Trojan 但 is_enabled=false
        reg.add(std::make_shared<mock_scheme>("mock_disabled", psm::protocol::protocol_type::trojan, false));
        // mock_tls2: 返回 TLS（第二个"不是我"）
        reg.add(std::make_shared<mock_scheme>("mock_tls2", psm::protocol::protocol_type::tls));
    }
} // namespace

// ─── executor 测试 ──────────────────────────────────────────────────

/**
 * @brief 测试空候选时按注册顺序执行
 * @details 候选为空 → executor 按注册顺序遍历 → mock_a(TLS) 跳过 → mock_b(Trojan) 成功
 */
void TestExecutorEmptyCandidates(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestExecutorEmptyCandidates ===");

    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    // candidates 为空

    psm::stealth::scheme_context ctx{
        .inbound = nullptr,
        .cfg = nullptr,
        .router = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        runner.Check(result.detected == psm::protocol::protocol_type::trojan,
                     "empty candidates: detected = trojan (mock_b)");
        runner.Check(std::string_view(result.executed_scheme) == "mock_b",
                     "empty candidates: executed_scheme = mock_b");
        runner.Check(!psm::fault::failed(result.error),
                     "empty candidates: no error");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试按指定候选列表执行
 * @details candidates = ["mock_b"] → 直接执行 mock_b → Trojan 成功
 */
void TestExecutorFindByOrder(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestExecutorFindByOrder ===");

    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("mock_b");

    psm::stealth::scheme_context ctx{
        .inbound = nullptr,
        .cfg = nullptr,
        .router = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        runner.Check(result.detected == psm::protocol::protocol_type::trojan,
                     "find by order: detected = trojan");
        runner.Check(std::string_view(result.executed_scheme) == "mock_b",
                     "find by order: executed_scheme = mock_b");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试跳过禁用的方案
 * @details candidates = ["mock_disabled", "mock_b"] → mock_disabled 被跳过 → mock_b 成功
 */
void TestExecutorSkipDisabled(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestExecutorSkipDisabled ===");

    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("mock_disabled");
    analysis.candidates.emplace_back("mock_b");

    psm::config cfg;
    psm::stealth::scheme_context ctx{
        .inbound = nullptr,
        .cfg = &cfg,
        .router = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        runner.Check(result.detected == psm::protocol::protocol_type::trojan,
                     "skip disabled: detected = trojan (mock_b)");
        runner.Check(std::string_view(result.executed_scheme) == "mock_b",
                     "skip disabled: executed_scheme = mock_b");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试不存在的方案名被跳过
 * @details candidates = ["nonexistent", "mock_b"] → nonexistent 跳过 → mock_b 成功
 */
void TestExecutorNotFound(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestExecutorNotFound ===");

    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("nonexistent");
    analysis.candidates.emplace_back("mock_b");

    psm::stealth::scheme_context ctx{
        .inbound = nullptr,
        .cfg = nullptr,
        .router = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        runner.Check(result.detected == psm::protocol::protocol_type::trojan,
                     "not found: detected = trojan (mock_b)");
        runner.Check(std::string_view(result.executed_scheme) == "mock_b",
                     "not found: executed_scheme = mock_b");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

/**
 * @brief 测试 TLS 结果触发 pass-through 继续下一个方案
 * @details candidates = ["mock_a", "mock_b"] → mock_a(TLS) pass-through → mock_b(Trojan) 成功
 */
void TestExecutorPassthrough(psm::testing::TestRunner &runner)
{
    runner.LogInfo("=== TestExecutorPassthrough ===");

    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("mock_a");
    analysis.candidates.emplace_back("mock_b");

    psm::stealth::scheme_context ctx{
        .inbound = nullptr,
        .cfg = nullptr,
        .router = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        runner.Check(result.detected == psm::protocol::protocol_type::trojan,
                     "passthrough: detected = trojan (mock_b after mock_a TLS)");
        runner.Check(std::string_view(result.executed_scheme) == "mock_b",
                     "passthrough: executed_scheme = mock_b");
    };

    auto token = [&ioc, &ep](const std::exception_ptr &e)
    {
        ep = e;
        ioc.stop();
    };

    net::co_spawn(ioc, coro(), token);
    ioc.run();

    if (ep)
        std::rethrow_exception(ep);
}

// ─── 入口 ──────────────────────────────────────────────────────────

int main()
{
    try
    {
        psm::memory::system::enable_global_pooling();
        psm::trace::init({});

        // 注册 mock 方案
        register_mocks();

        psm::testing::TestRunner runner("Executor");

        TestExecutorEmptyCandidates(runner);
        TestExecutorFindByOrder(runner);
        TestExecutorSkipDisabled(runner);
        TestExecutorNotFound(runner);
        TestExecutorPassthrough(runner);

        psm::trace::shutdown();
        return runner.Summary();
    }
    catch (const std::exception &e)
    {
        psm::trace::shutdown();
        psm::trace::error("[Executor] fatal: {}", e.what());
        return 1;
    }
}
