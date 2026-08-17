/**
 * @file PreviewMiddlewareTest.cpp
 * @brief preview 中间件管线测试（core/middleware）
 * @details 覆盖 pipeline/context：
 * 1. 中间件链按序执行
 * 2. 非 success 终止管线
 * 3. context 共享状态（identity 传递）
 * 4. context 默认值
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <common/core/fault/code.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/middleware/pipeline.hpp>
#include <common/core/transmission.hpp>

namespace
{

    namespace net = boost::asio;

    /// 最小叶子传输（供管线入站）
    class stub_transmission final : public preview::transmission
    {
    public:
        using preview::transmission::async_read_some;
        using preview::transmission::async_write_some;

        explicit stub_transmission(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        auto executor() const -> executor_type override
        {
            return ex_;
        }

        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            std::memset(buffer.data(), 0, buffer.size());
            ec.clear();
            co_return buffer.size();
        }

        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            (void)buffer;
            ec.clear();
            co_return buffer.size();
        }

        auto close() -> void override
        {
        }

        auto cancel() -> void override
        {
        }

    private:
        net::any_io_executor ex_;
    };

    /// 记录型中间件：记录调用顺序，返回指定错误码
    class recording_middleware final : public preview::middleware::middleware
    {
    public:
        recording_middleware(std::string_view name, preview::fault::code result, std::vector<std::string> &log)
            : name_(name), result_(result), log_(log)
        {
        }

        [[nodiscard]] auto name() const -> std::string_view override
        {
            return name_;
        }

        auto handle(preview::shared_transmission &inbound, preview::middleware::context &ctx)
            -> net::awaitable<preview::fault::code> override
        {
            (void)inbound;
            (void)ctx;
            log_.push_back(std::string(name_));
            co_return result_;
        }

    private:
        std::string_view name_;
        preview::fault::code result_;
        std::vector<std::string> &log_;
    };

    /// 运行协程（co_spawn + ioc.run 模式）
    template <typename Coro>
    static auto run_coro(net::io_context &ioc, Coro &&coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::forward<Coro>(coro)(), [&](std::exception_ptr e)
                      { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    TEST(PreviewMiddleware, OrderedExecution)
    {
        net::io_context ioc;
        std::vector<std::string> log;
        preview::middleware::pipeline pipe;
        pipe.add(std::make_shared<recording_middleware>("a", preview::fault::code::success, log));
        pipe.add(std::make_shared<recording_middleware>("b", preview::fault::code::success, log));

        auto inbound = std::make_shared<stub_transmission>(ioc.get_executor());
        preview::middleware::context ctx;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const auto ec = co_await pipe.run(inbound, ctx);
            EXPECT_EQ(ec, preview::fault::code::success); });

        ASSERT_EQ(log.size(), 2U);
        EXPECT_EQ(log[0], "a");
        EXPECT_EQ(log[1], "b");
    }

    TEST(PreviewMiddleware, StopOnFailure)
    {
        net::io_context ioc;
        std::vector<std::string> log;
        preview::middleware::pipeline pipe;
        pipe.add(std::make_shared<recording_middleware>("a", preview::fault::code::success, log));
        pipe.add(std::make_shared<recording_middleware>("b", preview::fault::code::auth_failed, log));
        pipe.add(std::make_shared<recording_middleware>("c", preview::fault::code::success, log));

        auto inbound = std::make_shared<stub_transmission>(ioc.get_executor());
        preview::middleware::context ctx;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const auto ec = co_await pipe.run(inbound, ctx);
            EXPECT_EQ(ec, preview::fault::code::auth_failed); });

        // b 失败后 c 不执行
        ASSERT_EQ(log.size(), 2U);
        EXPECT_EQ(log[0], "a");
        EXPECT_EQ(log[1], "b");
    }

    TEST(PreviewMiddleware, ContextState)
    {
        net::io_context ioc;
        preview::middleware::pipeline pipe;

        // 写 identity 的中间件
        struct identity_writer final : public preview::middleware::middleware
        {
            [[nodiscard]] auto name() const -> std::string_view override
            {
                return "identity-writer";
            }

            auto handle(preview::shared_transmission &, preview::middleware::context &ctx)
                -> net::awaitable<preview::fault::code> override
            {
                ctx.identity = "alice";
                co_return preview::fault::code::success;
            }
        };

        // 读 identity 的中间件
        struct identity_reader final : public preview::middleware::middleware
        {
            std::string *out;

            explicit identity_reader(std::string *o) : out(o)
            {
            }

            [[nodiscard]] auto name() const -> std::string_view override
            {
                return "identity-reader";
            }

            auto handle(preview::shared_transmission &, preview::middleware::context &ctx)
                -> net::awaitable<preview::fault::code> override
            {
                *out = ctx.identity;
                co_return preview::fault::code::success;
            }
        };

        std::string seen;
        pipe.add(std::make_shared<identity_writer>());
        pipe.add(std::make_shared<identity_reader>(&seen));

        auto inbound = std::make_shared<stub_transmission>(ioc.get_executor());
        preview::middleware::context ctx;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const auto ec = co_await pipe.run(inbound, ctx);
            EXPECT_EQ(ec, preview::fault::code::success); });

        EXPECT_EQ(seen, "alice");
        EXPECT_EQ(ctx.identity, "alice");
    }

    TEST(PreviewMiddleware, ContextDefaults)
    {
        preview::middleware::context ctx;
        EXPECT_EQ(ctx.inbound, nullptr);
        EXPECT_EQ(ctx.outbound, nullptr);
        EXPECT_EQ(ctx.detected, 0U);
        EXPECT_TRUE(ctx.identity.empty());
        EXPECT_EQ(ctx.buffer_size, 16384U);
        EXPECT_EQ(ctx.timeout, std::chrono::milliseconds{0});
        EXPECT_EQ(ctx.pad, nullptr);
        EXPECT_EQ(ctx.traffic, nullptr);
    }

} // namespace