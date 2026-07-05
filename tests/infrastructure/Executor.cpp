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
#include <prism/stealth/recognition/result.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/trace.hpp>
#include <prism/config/config.hpp>
#include <prism/net/transport/transmission.hpp>
#include <gtest/gtest.h>

#include <boost/asio.hpp>

namespace net = boost::asio;

namespace
{
    /**
     * @class mock_transport
     * @brief 用于测试的 mock 传输层
     * @details 满足 executor 的成功条件检查（transport != nullptr）
     */
    class mock_transport final : public psm::transport::transmission
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
     * @details handshake() 返回预设的 handshake_result，不做任何 I/O。
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

        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 2; // Tier 2 模糊匹配
        }

        [[nodiscard]] auto unique() const noexcept -> bool override
        {
            return false;
        }

        [[nodiscard]] auto active([[maybe_unused]] const psm::config &cfg) const noexcept
            -> bool override
        {
            return enabled_;
        }

        [[nodiscard]] auto guess([[maybe_unused]] const psm::config &cfg) const
            -> psm::stealth::verify_result override
        {
            return {.score = 100, .solo_flag = 0, .note = "mock"};
        }

        [[nodiscard]] auto handshake(psm::stealth::handshake_context ctx)
            -> net::awaitable<psm::stealth::handshake_result> override
        {
            psm::stealth::handshake_result result;
            result.detected = detected_;
            // 使用 mock transport 满足 executor 的成功条件检查
            // executor 要求 transport != nullptr 才认为执行成功
            if (ctx.transport)
                result.transport = ctx.transport;
            else
                result.transport = std::make_shared<mock_transport>(net::system_executor());
            result.scheme = psm::memory::string(name_);
            co_return result;
        }

    private:
        std::string name_;
        psm::protocol::protocol_type detected_;
        bool enabled_;
    };

    void register_mocks()
    {
        auto &reg = psm::stealth::scheme_registry::instance();

        // 避免重复注册（add 不幂等）
        if (reg.find("mock_a") != nullptr)
            return;

        // mock_a: 返回 TLS（表示"不是我"，executor 应跳过）
        reg.add(std::make_shared<mock_scheme>("mock_a", psm::protocol::protocol_type::tls));
        // mock_b: 返回 Trojan（表示成功匹配）
        reg.add(std::make_shared<mock_scheme>("mock_b", psm::protocol::protocol_type::trojan));
        // mock_disabled: 返回 Trojan 但 active=false
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
TEST(Executor, EmptyCandidates)
{
    register_mocks();

    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    // candidates 为空

    psm::stealth::handshake_context ctx{
        .transport = nullptr,
        .cfg = nullptr,
        .outbound = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        EXPECT_TRUE(result.detected == psm::protocol::protocol_type::trojan)
            << "empty candidates: detected = trojan (mock_b)";
        EXPECT_TRUE(std::string_view(result.scheme) == "mock_b")
            << "empty candidates: scheme = mock_b";
        EXPECT_TRUE(!psm::fault::failed(result.error))
            << "empty candidates: no error";
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
TEST(Executor, FindByOrder)
{
    register_mocks();
    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("mock_b");

    psm::stealth::handshake_context ctx{
        .transport = nullptr,
        .cfg = nullptr,
        .outbound = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        EXPECT_TRUE(result.detected == psm::protocol::protocol_type::trojan)
            << "find by order: detected = trojan";
        EXPECT_TRUE(std::string_view(result.scheme) == "mock_b")
            << "find by order: scheme = mock_b";
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
TEST(Executor, SkipDisabled)
{
    register_mocks();
    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("mock_disabled");
    analysis.candidates.emplace_back("mock_b");

    psm::config cfg;
    psm::stealth::handshake_context ctx{
        .inbound = nullptr,
        .cfg = &cfg,
        .router = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        EXPECT_TRUE(result.detected == psm::protocol::protocol_type::trojan)
            << "skip disabled: detected = trojan (mock_b)";
        EXPECT_TRUE(std::string_view(result.scheme) == "mock_b")
            << "skip disabled: scheme = mock_b";
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
TEST(Executor, NotFound)
{
    register_mocks();
    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("nonexistent");
    analysis.candidates.emplace_back("mock_b");

    psm::stealth::handshake_context ctx{
        .transport = nullptr,
        .cfg = nullptr,
        .outbound = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        EXPECT_TRUE(result.detected == psm::protocol::protocol_type::trojan)
            << "not found: detected = trojan (mock_b)";
        EXPECT_TRUE(std::string_view(result.scheme) == "mock_b")
            << "not found: scheme = mock_b";
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
TEST(Executor, Passthrough)
{
    register_mocks();
    auto &reg = psm::stealth::scheme_registry::instance();
    psm::stealth::scheme_executor executor(reg);

    psm::recognition::analysis_result analysis;
    analysis.candidates.emplace_back("mock_a");
    analysis.candidates.emplace_back("mock_b");

    psm::stealth::handshake_context ctx{
        .transport = nullptr,
        .cfg = nullptr,
        .outbound = nullptr,
        .session = nullptr};

    net::io_context ioc;
    std::exception_ptr ep;

    auto coro = [&]() -> net::awaitable<void>
    {
        auto result = co_await executor.execute_by_analysis(analysis, std::move(ctx));

        EXPECT_TRUE(result.detected == psm::protocol::protocol_type::trojan)
            << "passthrough: detected = trojan (mock_b after mock_a TLS)";
        EXPECT_TRUE(std::string_view(result.scheme) == "mock_b")
            << "passthrough: scheme = mock_b";
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
