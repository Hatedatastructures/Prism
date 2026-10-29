/**
 * @file ExecutionTest.cpp
 * @brief Prism 中间件管线测试（Core/Middleware）
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

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>
#include <Prism/Runtime/Middleware/Pipeline.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Fault = Prism::Fault;
    namespace MiddlewareNamespace = Prism::Middleware;
    using Prism::SharedTransmission;
    using Prism::Transmission;

    /// 最小叶子传输（供管线入站）
    class StubTransmission final : public Transmission
    {
    public:
        explicit StubTransmission(Net::any_io_executor Executor)
            : Prism::Transmission(Executor), Ex_(std::move(Executor))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Error;
            std::memset(Buffer.data(), 0, Buffer.size());
            Error.clear();
            Prism::Transmission::PostResult(Ex_,
                std::move(Handler), Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(Error)});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code Error;
            (void)Buffer;
            Error.clear();
            Prism::Transmission::PostResult(Ex_,
                std::move(Handler), Prism::IoResult{Buffer.size(), Prism::Fault::FromNative(Error)});
        }

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际 inner 转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Prism::Transmission::PostResult(Ex_, std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return {};
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
            -> Net::awaitable<Fault::Failure> override
        {
            (void)Inbound;
            (void)Context;
            Log_.push_back(std::string(Name_));
            co_return Fault::Failure{Result_};
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

    TEST(PrismMiddleware, OrderedExecution)
    {
        Net::io_context IoContext;
        std::vector<std::string> Log;
        MiddlewareNamespace::Pipeline Pipeline;
        Pipeline.Add(std::make_shared<RecordingMiddleware>("a", Fault::Code::Success, Log));
        Pipeline.Add(std::make_shared<RecordingMiddleware>("b", Fault::Code::Success, Log));

        auto Inbound = std::make_shared<StubTransmission>(IoContext.get_executor());
        MiddlewareNamespace::Context MiddlewareContext;
        MiddlewareContext.Inbound() = Inbound;

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                 {
            const auto Result = co_await Pipeline.Run(MiddlewareContext);
            EXPECT_TRUE(Result.Succeeded()); });

        ASSERT_EQ(Log.size(), 2U);
        EXPECT_EQ(Log[0], "a");
        EXPECT_EQ(Log[1], "b");
    }

    TEST(PrismMiddleware, StopOnFailure)
    {
        Net::io_context IoContext;
        std::vector<std::string> Log;
        MiddlewareNamespace::Pipeline Pipeline;
        Pipeline.Add(std::make_shared<RecordingMiddleware>("a", Fault::Code::Success, Log));
        Pipeline.Add(std::make_shared<RecordingMiddleware>("b", Fault::Code::AuthFailed, Log));
        Pipeline.Add(std::make_shared<RecordingMiddleware>("c", Fault::Code::Success, Log));

        auto Inbound = std::make_shared<StubTransmission>(IoContext.get_executor());
        MiddlewareNamespace::Context MiddlewareContext;
        MiddlewareContext.Inbound() = Inbound;

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                 {
            const auto Result = co_await Pipeline.Run(MiddlewareContext);
            EXPECT_EQ(Result.Code, Fault::Code::AuthFailed); });

        // b 失败后 c 不执行
        ASSERT_EQ(Log.size(), 2U);
        EXPECT_EQ(Log[0], "a");
        EXPECT_EQ(Log[1], "b");
    }

    TEST(PrismMiddleware, ContextState)
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
                -> Net::awaitable<Fault::Failure> override
            {
                MiddlewareContext.Identity() = "alice";
                co_return Fault::Failure{};
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
                -> Net::awaitable<Fault::Failure> override
            {
                *Output = MiddlewareContext.Identity();
                co_return Fault::Failure{};
            }
        };

        std::string Seen;
        Pipeline.Add(std::make_shared<IdentityWriter>());
        Pipeline.Add(std::make_shared<IdentityReader>(&Seen));

        auto Inbound = std::make_shared<StubTransmission>(IoContext.get_executor());
        MiddlewareNamespace::Context MiddlewareContext;
        MiddlewareContext.Inbound() = Inbound;

        RunCoroutine(IoContext, [&]() -> Net::awaitable<void>
                 {
            const auto Result = co_await Pipeline.Run(MiddlewareContext);
            EXPECT_TRUE(Result.Succeeded()); });

        EXPECT_EQ(Seen, "alice");
        EXPECT_EQ(MiddlewareContext.Identity(), "alice");
    }

    TEST(PrismMiddleware, ContextDefaults)
    {
        MiddlewareNamespace::Context MiddlewareContext;
        EXPECT_EQ(MiddlewareContext.Inbound(), nullptr);
        EXPECT_EQ(MiddlewareContext.Outbound, nullptr);
        EXPECT_EQ(static_cast<std::uint16_t>(MiddlewareContext.DataPlane.Protocol), 0U);
        EXPECT_TRUE(MiddlewareContext.Identity().empty());
        EXPECT_EQ(MiddlewareContext.BufferSize, 16384U);
        EXPECT_EQ(MiddlewareContext.Timeout, std::chrono::milliseconds{0});
        EXPECT_EQ(MiddlewareContext.Pad, nullptr);
        EXPECT_EQ(MiddlewareContext.Traffic, nullptr);
    }

} // namespace
