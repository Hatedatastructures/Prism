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

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/Middleware/Pipeline.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Preview::Fault;
    namespace MiddlewareNamespace = Preview::Middleware;
    using Preview::SharedTransmission;
    using Preview::Transmission;

    /// 最小叶子传输（供管线入站）
    class StubTransmission final : public Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit StubTransmission(Net::any_io_executor Executor) : Ex_(std::move(Executor))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            std::memset(Buffer.data(), 0, Buffer.size());
            ErrorCode.clear();
            co_return Buffer.size();
        }

        auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            (void)Buffer;
            ErrorCode.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
        }

        auto Cancel() -> void override
        {
        }

    private:
        Net::any_io_executor Ex_;
    };

    /// 记录型中间件：记录调用顺序，返回指定错误码
    class RecordingMiddleware final : public MiddlewareNamespace::Middleware
    {
    public:
        RecordingMiddleware(std::string_view Name, Fault::Code Result, std::vector<std::string> &Log)
            : Name_(Name), Result_(Result), Log_(Log)
        {
        }

        [[nodiscard]] auto Name() const -> std::string_view override
        {
            return Name_;
        }

        auto Handle(SharedTransmission &Inbound, MiddlewareNamespace::Context &Context)
            -> Net::awaitable<Fault::Code> override
        {
            (void)Inbound;
            (void)Context;
            Log_.push_back(std::string(Name_));
            co_return Result_;
        }

    private:
        std::string_view Name_;
        Fault::Code Result_;
        std::vector<std::string> &Log_;
    };

    /// 运行协程（co_spawn + IoContext.Run 模式）
    template <typename Coro>
    static auto RunCoroutine(Net::io_context &IoContext, Coro &&Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::forward<Coro>(Coroutine)(),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(PreviewMiddleware, OrderedExecution)
    {
        Net::io_context IoContext;
        std::vector<std::string> Log;
        MiddlewareNamespace::Pipeline Pipeline;
        Pipeline.Add(std::make_shared<RecordingMiddleware>("a", Fault::Code::Success, Log));
        Pipeline.Add(std::make_shared<RecordingMiddleware>("b", Fault::Code::Success, Log));

        auto Inbound = std::make_shared<StubTransmission>(IoContext.get_executor());
        MiddlewareNamespace::Context MiddlewareContext;

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                 {
            const auto ErrorCode = co_await Pipeline.Run(Inbound, MiddlewareContext);
            EXPECT_EQ(ErrorCode, Fault::Code::Success); });

        ASSERT_EQ(Log.size(), 2U);
        EXPECT_EQ(Log[0], "a");
        EXPECT_EQ(Log[1], "b");
    }

    TEST(PreviewMiddleware, StopOnFailure)
    {
        Net::io_context IoContext;
        std::vector<std::string> Log;
        MiddlewareNamespace::Pipeline Pipeline;
        Pipeline.Add(std::make_shared<RecordingMiddleware>("a", Fault::Code::Success, Log));
        Pipeline.Add(std::make_shared<RecordingMiddleware>("b", Fault::Code::AuthFailed, Log));
        Pipeline.Add(std::make_shared<RecordingMiddleware>("c", Fault::Code::Success, Log));

        auto Inbound = std::make_shared<StubTransmission>(IoContext.get_executor());
        MiddlewareNamespace::Context MiddlewareContext;

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                 {
            const auto ErrorCode = co_await Pipeline.Run(Inbound, MiddlewareContext);
            EXPECT_EQ(ErrorCode, Fault::Code::AuthFailed); });

        // b 失败后 c 不执行
        ASSERT_EQ(Log.size(), 2U);
        EXPECT_EQ(Log[0], "a");
        EXPECT_EQ(Log[1], "b");
    }

    TEST(PreviewMiddleware, ContextState)
    {
        Net::io_context IoContext;
        MiddlewareNamespace::Pipeline Pipeline;

        // 写 identity 的中间件
        struct IdentityWriter final : public MiddlewareNamespace::Middleware
        {
            [[nodiscard]] auto Name() const -> std::string_view override
            {
                return "identity-writer";
            }

            auto Handle(SharedTransmission &, MiddlewareNamespace::Context &MiddlewareContext)
                -> Net::awaitable<Fault::Code> override
            {
                MiddlewareContext.identity = "alice";
                co_return Fault::Code::Success;
            }
        };

        // 读 identity 的中间件
        struct IdentityReader final : public MiddlewareNamespace::Middleware
        {
            std::string *Output;

            explicit IdentityReader(std::string *Output) : Output(Output)
            {
            }

            [[nodiscard]] auto Name() const -> std::string_view override
            {
                return "identity-reader";
            }

            auto Handle(SharedTransmission &, MiddlewareNamespace::Context &MiddlewareContext)
                -> Net::awaitable<Fault::Code> override
            {
                *Output = MiddlewareContext.identity;
                co_return Fault::Code::Success;
            }
        };

        std::string Seen;
        Pipeline.Add(std::make_shared<IdentityWriter>());
        Pipeline.Add(std::make_shared<IdentityReader>(&Seen));

        auto Inbound = std::make_shared<StubTransmission>(IoContext.get_executor());
        MiddlewareNamespace::Context MiddlewareContext;

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                 {
            const auto ErrorCode = co_await Pipeline.Run(Inbound, MiddlewareContext);
            EXPECT_EQ(ErrorCode, Fault::Code::Success); });

        EXPECT_EQ(Seen, "alice");
        EXPECT_EQ(MiddlewareContext.identity, "alice");
    }

    TEST(PreviewMiddleware, ContextDefaults)
    {
        MiddlewareNamespace::Context MiddlewareContext;
        EXPECT_EQ(MiddlewareContext.Inbound, nullptr);
        EXPECT_EQ(MiddlewareContext.Outbound, nullptr);
        EXPECT_EQ(MiddlewareContext.detected, 0U);
        EXPECT_TRUE(MiddlewareContext.identity.empty());
        EXPECT_EQ(MiddlewareContext.BufferSize, 16384U);
        EXPECT_EQ(MiddlewareContext.timeout, std::chrono::milliseconds{0});
        EXPECT_EQ(MiddlewareContext.pad, nullptr);
        EXPECT_EQ(MiddlewareContext.traffic, nullptr);
    }

} // namespace
