/**
 * @file PreviewMiddlewareTest.cpp
 * @brief Preview 中间件管线测试（core/Middleware）
 * @details 覆盖 Pipeline/Context：
 * 1. 中间件链按序执行
 * 2. 非 success 终止管线
 * 3. Context 共享状态（identity 传递）
 * 4. Context 默认值
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

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Middleware/Pipeline.hpp>
#include <preview/Transport/Transmission.hpp>

namespace
{

    namespace net = boost::asio;

    /// 最小叶子传输（供管线入站）
    class stub_transmission final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit stub_transmission(net::any_io_executor ex) : Ex_(std::move(ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            std::memset(Buffer.data(), 0, Buffer.size());
            ec.clear();
            co_return Buffer.size();
        }

        auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            (void)Buffer;
            ec.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
        }

        auto Cancel() -> void override
        {
        }

    private:
        net::any_io_executor Ex_;
    };

    /// 记录型中间件：记录调用顺序，返回指定错误码
    class recording_middleware final : public Preview::Middleware::Middleware
    {
    public:
        recording_middleware(std::string_view Name, Preview::Fault::Code Result, std::vector<std::string> &log)
            : name_(Name), result_(Result), log_(log)
        {
        }

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return name_;
        }

        auto Handle(Preview::SharedTransmission &Inbound, Preview::Middleware::Context &ctx)
            -> net::awaitable<Preview::Fault::Code> override
        {
            (void)Inbound;
            (void)ctx;
            log_.push_back(std::string(name_));
            co_return result_;
        }

    private:
        std::string_view name_;
        Preview::Fault::Code result_;
        std::vector<std::string> &log_;
    };

    /// 运行协程（co_spawn + ioc.Run 模式）
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
        Preview::Middleware::Pipeline pipe;
        pipe.Add(std::make_shared<recording_middleware>("a", Preview::Fault::Code::Success, log));
        pipe.Add(std::make_shared<recording_middleware>("b", Preview::Fault::Code::Success, log));

        auto Inbound = std::make_shared<stub_transmission>(ioc.get_executor());
        Preview::Middleware::Context ctx;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const auto ec = co_await pipe.Run(Inbound, ctx);
            EXPECT_EQ(ec, Preview::Fault::Code::Success); });

        ASSERT_EQ(log.size(), 2U);
        EXPECT_EQ(log[0], "a");
        EXPECT_EQ(log[1], "b");
    }

    TEST(PreviewMiddleware, StopOnFailure)
    {
        net::io_context ioc;
        std::vector<std::string> log;
        Preview::Middleware::Pipeline pipe;
        pipe.Add(std::make_shared<recording_middleware>("a", Preview::Fault::Code::Success, log));
        pipe.Add(std::make_shared<recording_middleware>("b", Preview::Fault::Code::AuthFailed, log));
        pipe.Add(std::make_shared<recording_middleware>("c", Preview::Fault::Code::Success, log));

        auto Inbound = std::make_shared<stub_transmission>(ioc.get_executor());
        Preview::Middleware::Context ctx;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const auto ec = co_await pipe.Run(Inbound, ctx);
            EXPECT_EQ(ec, Preview::Fault::Code::AuthFailed); });

        // b 失败后 c 不执行
        ASSERT_EQ(log.size(), 2U);
        EXPECT_EQ(log[0], "a");
        EXPECT_EQ(log[1], "b");
    }

    TEST(PreviewMiddleware, ContextState)
    {
        net::io_context ioc;
        Preview::Middleware::Pipeline pipe;

        // 写 identity 的中间件
        struct identity_writer final : public Preview::Middleware::Middleware
        {
            [[nodiscard]] auto Name() const -> std::string_view override
            {
                return "identity-writer";
            }

            auto Handle(Preview::SharedTransmission &, Preview::Middleware::Context &ctx)
                -> net::awaitable<Preview::Fault::Code> override
            {
                ctx.identity = "alice";
                co_return Preview::Fault::Code::Success;
            }
        };

        // 读 identity 的中间件
        struct identity_reader final : public Preview::Middleware::Middleware
        {
            std::string *out;

            explicit identity_reader(std::string *o) : out(o)
            {
            }

            [[nodiscard]] auto Name() const -> std::string_view override
            {
                return "identity-reader";
            }

            auto Handle(Preview::SharedTransmission &, Preview::Middleware::Context &ctx)
                -> net::awaitable<Preview::Fault::Code> override
            {
                *out = ctx.identity;
                co_return Preview::Fault::Code::Success;
            }
        };

        std::string seen;
        pipe.Add(std::make_shared<identity_writer>());
        pipe.Add(std::make_shared<identity_reader>(&seen));

        auto Inbound = std::make_shared<stub_transmission>(ioc.get_executor());
        Preview::Middleware::Context ctx;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            const auto ec = co_await pipe.Run(Inbound, ctx);
            EXPECT_EQ(ec, Preview::Fault::Code::Success); });

        EXPECT_EQ(seen, "alice");
        EXPECT_EQ(ctx.identity, "alice");
    }

    TEST(PreviewMiddleware, ContextDefaults)
    {
        Preview::Middleware::Context ctx;
        EXPECT_EQ(ctx.Inbound, nullptr);
        EXPECT_EQ(ctx.Outbound, nullptr);
        EXPECT_EQ(ctx.detected, 0U);
        EXPECT_TRUE(ctx.identity.empty());
        EXPECT_EQ(ctx.BufferSize, 16384U);
        EXPECT_EQ(ctx.timeout, std::chrono::milliseconds{0});
        EXPECT_EQ(ctx.pad, nullptr);
        EXPECT_EQ(ctx.traffic, nullptr);
    }

} // namespace
