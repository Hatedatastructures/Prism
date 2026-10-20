/**
 * @file SchemeExecutorTest.cpp
 * @brief 伪装方案执行器注册表验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>

#include <Experiments/Prism/SchemeExecutor.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Recognition = Prism::Recognition;
    using Prism::SharedTransmission;
    using Prism::Transmission;
    using Recognition::Experiment::SchemeExecutor;

    struct FakeTransmission final : Transmission
    {
        explicit FakeTransmission(Net::any_io_executor Executor) : Prism::Transmission(Executor), Ex_(Executor) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Ex_; }
        auto StartRead(std::span<std::byte>, Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}}); }
        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}}); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { Prism::Transmission::PostResult(Executor(), std::move(Handler), {}); }
        [[nodiscard]] auto OnClose() -> ControlResult override { return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return {}; }
        Net::any_io_executor Ex_;
    };

    class Decorator final : public Transmission
    {
    public:
        explicit Decorator(SharedTransmission Inner) : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Inner_->Executor(); }
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override { Inner_->ReadSome(Buffer, std::move(Handler)); }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override { Inner_->WriteSome(Buffer, std::move(Handler)); }
        auto StartWriteShutdown(Completion Handler) -> void override { Inner_->WriteShutdown(std::move(Handler)); }
        [[nodiscard]] auto OnClose() -> ControlResult override { return Inner_->Close(); }
        [[nodiscard]] auto OnCancel() -> ControlResult override { return Inner_->Cancel(); }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        bool wrapped{true};
    private:
        SharedTransmission Inner_;
    };

    auto RunCoro(Net::io_context &Ioc, auto Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error){ Exception=Error; Ioc.stop(); });
        Ioc.run();
        if (Exception) std::rethrow_exception(Exception);
    }

    TEST(SchemeExecutor, RegisterAndExecute)
    {
        Net::io_context ioc;
        SchemeExecutor exec;
        bool called = false;
        exec.RegisterScheme("anytls", [&](SharedTransmission Inbound) -> Net::awaitable<SharedTransmission>
        {
            called = true;
            co_return std::make_shared<Decorator>(std::move(Inbound));
        });
        EXPECT_TRUE(exec.Has("anytls"));
        EXPECT_EQ(exec.Size(), 1u);
        EXPECT_FALSE(exec.RegisterScheme("anytls", [](SharedTransmission in) -> Net::awaitable<SharedTransmission> { co_return in; }));

        bool wrapped = false;
        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            auto Inner = std::make_shared<FakeTransmission>(ioc.get_executor());
            auto out = co_await exec.Execute("anytls", Inner);
            auto dec = std::dynamic_pointer_cast<Decorator>(out);
            wrapped = dec && dec->wrapped;
        });
        EXPECT_TRUE(called);
        EXPECT_TRUE(wrapped);
    }

    TEST(SchemeExecutor, EmptySchemePassthrough)
    {
        Net::io_context ioc;
        SchemeExecutor exec;
        exec.RegisterScheme("reality", [](SharedTransmission in) -> Net::awaitable<SharedTransmission> { co_return in; });
        RunCoro(ioc, [&]() -> Net::awaitable<void>
        {
            auto Inner = std::make_shared<FakeTransmission>(ioc.get_executor());
            auto out = co_await exec.Execute("", Inner);
            EXPECT_EQ(out.get(), Inner.get());
            auto out2 = co_await exec.Execute("unknown", Inner);
            EXPECT_EQ(out2, nullptr);
        });
    }

    TEST(SchemeExecutor, MultipleSchemes)
    {
        SchemeExecutor exec;
        exec.RegisterScheme("shadowtls", [](SharedTransmission in) -> Net::awaitable<SharedTransmission> { co_return in; });
        exec.RegisterScheme("restls", [](SharedTransmission in) -> Net::awaitable<SharedTransmission> { co_return in; });
        exec.RegisterScheme("ws", [](SharedTransmission in) -> Net::awaitable<SharedTransmission> { co_return in; });
        EXPECT_EQ(exec.Size(), 3u);
        EXPECT_TRUE(exec.Has("shadowtls"));
        EXPECT_TRUE(exec.Has("restls"));
        EXPECT_TRUE(exec.Has("ws"));
        EXPECT_FALSE(exec.Has("anytls"));
    }

} // namespace
