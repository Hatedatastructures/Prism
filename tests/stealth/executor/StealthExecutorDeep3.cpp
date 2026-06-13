/**
 * @file StealthExecutorDeep3.cpp
 * @brief scheme_executor 异步函数深度测试
 * @details 测试 execute_single、execute_pipeline、execute_by_analysis、execute
 *          四个异步函数。使用 MockScheme 控制 handshake 返回值，验证：
 *          - execute_single 设置 scheme name
 *          - execute_pipeline 的 facade 成功/stack 成功/stack 失败回退/TLS 检测继续
 *          - execute_by_analysis 的空候选默认顺序/有候选按顺序/native 兜底
 *          - execute 委托到 execute_pipeline
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/MockTransport.hpp"

#define private public
#include <prism/net/transport/snapshot.hpp>
#include <prism/stealth/executor.hpp>
#undef private

#include <prism/config/config.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <utility>

#include <boost/asio.hpp>

namespace net = boost::asio;
namespace stealth = psm::stealth;
namespace transport = psm::transport;

namespace
{

// ─── Mock Scheme ─────────────────────────────────────────────

/**
 * @brief 可控行为的伪装方案 Mock
 * @details 通过 preset_result 控制 handshake() 返回值，
 * 通过 active_flag 控制 active() 返回值
 */
class MockScheme final : public stealth::stealth_scheme
{
public:
    stealth::handshake_result preset_result;
    bool active_flag = true;
    stealth::scheme_category category_ = stealth::scheme_category::facade;

    [[nodiscard]] auto name() const noexcept -> std::string_view override
    {
        return name_;
    }

    [[nodiscard]] auto category() const noexcept -> stealth::scheme_category override
    {
        return category_;
    }

    [[nodiscard]] auto active(const psm::config & /*cfg*/) const noexcept -> bool override
    {
        return active_flag;
    }

    [[nodiscard]] auto handshake(stealth::handshake_context /*ctx*/)
        -> net::awaitable<stealth::handshake_result> override
    {
        co_return preset_result;
    }

    // 设置名称的便捷方法
    void set_name(std::string_view n)
    {
        name_ = n;
    }

private:
    std::string_view name_ = "mock";
};

/**
 * @brief 创建 MockScheme shared_ptr 的便捷函数
 */
auto make_mock(std::string_view name,
               stealth::handshake_result result,
               bool active = true,
               stealth::scheme_category cat = stealth::scheme_category::facade)
    -> std::shared_ptr<MockScheme>
{
    auto m = std::make_shared<MockScheme>();
    m->set_name(name);
    m->preset_result = std::move(result);
    m->active_flag = active;
    m->category_ = cat;
    return m;
}

/**
 * @brief 创建最小的 handshake_context
 */
auto make_context() -> stealth::handshake_context
{
    stealth::handshake_context ctx;
    ctx.inbound = std::make_shared<psm::testing::MockTransport>();
    ctx.cfg = nullptr;
    return ctx;
}

// ─── 协程运行辅助 ──────────────────────────────────────────

// 注：每个测试直接内联 net::co_spawn + ioc.run() 模式，
// 避免模板函数与 std::function + lambda 的兼容性问题。

// ─── execute_single 测试 ──────────────────────────────────

TEST(StealthExecutorDeep3, ExecuteSingle_SetsSchemeName)
{
    stealth::scheme_registry registry;
    auto mock = make_mock("test_scheme", stealth::handshake_result{});
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        result = co_await exec.execute_single(mock, make_context());
    };

    net::co_spawn(ioc, coro(), [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    if (ep)
    {
        try
        {
            std::rethrow_exception(ep);
        }
        catch (const std::exception &e)
        {
            FAIL() << "exception: " << e.what();
        }
    }

    EXPECT_EQ(result.scheme, "test_scheme") << "execute_single sets scheme name";
}

TEST(StealthExecutorDeep3, ExecuteSingle_PreservesTransport)
{
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result preset;
    preset.transport = mock_transport;
    preset.detected = psm::protocol::protocol_type::socks5;

    auto mock = make_mock("test", std::move(preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_single(mock, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_TRUE(result.transport == mock_transport) << "execute_single preserves transport";
    EXPECT_TRUE(result.detected == psm::protocol::protocol_type::socks5) << "execute_single preserves detected";
}

// ─── execute_pipeline 测试 ──────────────────────────────────

TEST(StealthExecutorDeep3, ExecutePipeline_FacadeSuccess)
{
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result preset;
    preset.transport = mock_transport;
    preset.detected = psm::protocol::protocol_type::http;

    auto mock = make_mock("facade_ok", std::move(preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("facade_ok");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_TRUE(result.transport == mock_transport) << "pipeline facade success: transport set";
    EXPECT_EQ(result.scheme, "facade_ok") << "pipeline facade success: scheme name";
}

TEST(StealthExecutorDeep3, ExecutePipeline_StackSuccess)
{
    // Stack 方案：不返回 transport，无错误 → 成功终止
    stealth::handshake_result preset;
    preset.transport = nullptr;
    preset.error = psm::fault::code::success;

    auto mock = make_mock("stack_ok", std::move(preset), true, stealth::scheme_category::stack);
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("stack_ok");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_TRUE(!result.transport) << "pipeline stack success: no transport";
    EXPECT_EQ(result.scheme, "stack_ok") << "pipeline stack success: scheme name";
}

TEST(StealthExecutorDeep3, ExecutePipeline_StackFailContinue)
{
    // Stack 方案失败（返回 transport），应继续尝试下一个
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();

    // 第一个 stack 方案失败
    stealth::handshake_result fail_preset;
    fail_preset.transport = mock_transport;
    fail_preset.error = psm::fault::code::success;
    auto stack_fail = make_mock("stack_fail", std::move(fail_preset), true, stealth::scheme_category::stack);

    // 第二个 facade 方案成功
    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::trojan;
    auto facade_ok = make_mock("facade_ok", std::move(ok_preset));

    stealth::scheme_registry registry;
    registry.add(stack_fail);
    registry.add(facade_ok);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("stack_fail");
    order.emplace_back("facade_ok");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "facade_ok") << "pipeline stack fail -> next scheme";
}

TEST(StealthExecutorDeep3, ExecutePipeline_TlsDetectedContinue)
{
    // Facade 方案返回 detected=tls → "不是我的"，继续下一个
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();

    stealth::handshake_result tls_preset;
    tls_preset.transport = mock_transport;
    tls_preset.detected = psm::protocol::protocol_type::tls;
    auto tls_scheme = make_mock("tls_detector", std::move(tls_preset));

    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::socks5;
    auto ok_scheme = make_mock("real_match", std::move(ok_preset));

    stealth::scheme_registry registry;
    registry.add(tls_scheme);
    registry.add(ok_scheme);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("tls_detector");
    order.emplace_back("real_match");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "real_match") << "pipeline tls detected -> continue to next";
}

TEST(StealthExecutorDeep3, ExecutePipeline_AllFail_NotSupported)
{
    // 所有方案都不返回 transport 且有错误
    stealth::handshake_result fail_preset;
    fail_preset.transport = nullptr;
    fail_preset.error = psm::fault::code::connection_refused;

    auto mock = make_mock("fail_scheme", std::move(fail_preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("fail_scheme");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    // facade 无 transport 但有错误 → 走 rewind 路径，rewind 失败则返回该方案结果
    EXPECT_TRUE(psm::fault::failed(result.error)) << "pipeline all fail: error is set";
}

TEST(StealthExecutorDeep3, ExecutePipeline_SchemeNotFound_Skipped)
{
    // 列表中包含不存在的 scheme → 跳过，下一个成功
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::http;

    auto mock = make_mock("existing", std::move(ok_preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("nonexistent");
    order.emplace_back("existing");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "existing") << "pipeline skips not-found scheme";
}

TEST(StealthExecutorDeep3, ExecutePipeline_SchemeDisabled_Skipped)
{
    // 方案 active=false → 跳过
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::http;

    auto disabled = make_mock("disabled", stealth::handshake_result{}, false);
    auto enabled = make_mock("enabled", std::move(ok_preset), true);
    stealth::scheme_registry registry;
    registry.add(disabled);
    registry.add(enabled);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("disabled");
    order.emplace_back("enabled");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "enabled") << "pipeline skips disabled scheme";
}

TEST(StealthExecutorDeep3, ExecutePipeline_EmptyOrder_NotSupported)
{
    stealth::scheme_registry registry;
    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_TRUE(result.error == psm::fault::code::not_supported) << "pipeline empty order -> not_supported";
}

// ─── execute_by_analysis 测试 ──────────────────────────────

TEST(StealthExecutorDeep3, ExecuteByAnalysis_EmptyCandidates_DefaultOrder)
{
    // 空候选列表 → 按 registry 注册顺序执行
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::http;

    auto mock = make_mock("scheme_a", std::move(ok_preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::recognition::analysis_result analysis;
    // candidates 为空

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_by_analysis(analysis, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "scheme_a") << "by_analysis empty candidates uses default order";
}

TEST(StealthExecutorDeep3, ExecuteByAnalysis_WithCandidates_PipelineOrder)
{
    // 有候选列表 → 按候选顺序执行
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::trojan;

    auto scheme_b = make_mock("scheme_b", std::move(ok_preset));
    stealth::scheme_registry registry;
    registry.add(scheme_b);

    stealth::scheme_executor exec(registry);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("scheme_b");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_by_analysis(analysis, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "scheme_b") << "by_analysis with candidates follows order";
}

// ─── execute 测试 ─────────────────────────────────────────

TEST(StealthExecutorDeep3, Execute_DelegatesToPipeline)
{
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();
    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    ok_preset.detected = psm::protocol::protocol_type::socks5;

    auto mock = make_mock("delegate_test", std::move(ok_preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> candidates;
    candidates.emplace_back("delegate_test");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute(candidates, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "delegate_test") << "execute delegates to pipeline";
    EXPECT_TRUE(result.transport == mock_transport) << "execute preserves transport";
}

TEST(StealthExecutorDeep3, Execute_MultipleCandidatesFirstWins)
{
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();

    stealth::handshake_result first_ok;
    first_ok.transport = mock_transport;
    first_ok.detected = psm::protocol::protocol_type::http;

    stealth::handshake_result second_ok;
    second_ok.transport = mock_transport;
    second_ok.detected = psm::protocol::protocol_type::socks5;

    auto first = make_mock("first", std::move(first_ok));
    auto second = make_mock("second", std::move(second_ok));

    stealth::scheme_registry registry;
    registry.add(first);
    registry.add(second);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> candidates;
    candidates.emplace_back("first");
    candidates.emplace_back("second");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute(candidates, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "first") << "execute first candidate wins";
    EXPECT_TRUE(result.detected == psm::protocol::protocol_type::http) << "execute preserves first detected";
}

// ─── pipeline 错误回退测试 ────────────────────────────────

TEST(StealthExecutorDeep3, ExecutePipeline_ErrorRewindFail)
{
    // 方案失败且无法 rewind（非 snapshot transport）→ 返回错误
    stealth::handshake_result fail_preset;
    fail_preset.transport = nullptr;
    fail_preset.error = psm::fault::code::connection_refused;
    fail_preset.polluted = false;

    auto mock = make_mock("fail_no_rewind", std::move(fail_preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("fail_no_rewind");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_TRUE(psm::fault::failed(result.error)) << "pipeline error: returns error when rewind fails";
}

TEST(StealthExecutorDeep3, ExecutePipeline_FacadeWithPrereadSecondaryProbe)
{
    // facade 成功且有 preread → secondary_probe 覆盖 detected
    auto mock_transport = std::make_shared<psm::testing::MockTransport>();

    stealth::handshake_result ok_preset;
    ok_preset.transport = mock_transport;
    // 初始 detected 不能是 tls（否则走 "不是我" 分支）
    ok_preset.detected = psm::protocol::protocol_type::unknown;
    // preread 内容为 HTTP GET → secondary_probe 通过 detect_tls 检测
    ok_preset.preread.push_back(std::byte{'G'});
    ok_preset.preread.push_back(std::byte{'E'});
    ok_preset.preread.push_back(std::byte{'T'});
    ok_preset.preread.push_back(std::byte{' '});
    ok_preset.preread.push_back(std::byte{'/'});
    ok_preset.preread.push_back(std::byte{' '});
    ok_preset.preread.push_back(std::byte{'H'});
    ok_preset.preread.push_back(std::byte{'T'});
    ok_preset.preread.push_back(std::byte{'T'});
    ok_preset.preread.push_back(std::byte{'P'});

    auto mock = make_mock("preread_probe", std::move(ok_preset));
    stealth::scheme_registry registry;
    registry.add(mock);

    stealth::scheme_executor exec(registry);

    psm::memory::vector<psm::memory::string> order;
    order.emplace_back("preread_probe");

    net::io_context ioc;
    stealth::handshake_result result;
    std::exception_ptr ep;

    net::co_spawn(ioc,
                  [&]() -> net::awaitable<void>
                  { result = co_await exec.execute_pipeline(order, make_context()); },
                  [&](std::exception_ptr e)
                  { ep = e; ioc.stop(); });
    ioc.run();

    ASSERT_TRUE(!ep);
    EXPECT_EQ(result.scheme, "preread_probe") << "pipeline preread: scheme set";
    // detected 被 secondary_probe 覆盖
    // secondary_probe 调用 detect_tls("GET / HTTP") → 阶段1 HTTP 检测 → 返回 http
    EXPECT_TRUE(result.detected == psm::protocol::protocol_type::http)
        << "pipeline preread: HTTP preread detected as http";
}

} // namespace
