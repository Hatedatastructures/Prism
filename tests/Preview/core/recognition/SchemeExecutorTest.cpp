/**
 * @file SchemeExecutorTest.cpp
 * @brief 伪装方案执行器注册表验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>

#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Recognition = Preview::Recognition;
    using Preview::SharedTransmission;
    using Preview::Transmission;
    using Recognition::SchemeExecutor;

    struct FakeTransmission final : Transmission
    {
        explicit FakeTransmission(Net::any_io_executor Executor) : Ex_(Executor) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Ex_; }
        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec) -> Net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec) -> Net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        void Close() override {}
        void Cancel() override {}
        Net::any_io_executor Ex_;
    };

    class Decorator final : public Transmission
    {
    public:
        explicit Decorator(SharedTransmission Inner) : Inner_(std::move(Inner)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Inner_->Executor(); }
        [[nodiscard]] auto async_read_some(std::span<std::byte> b, std::error_code &ec) -> Net::awaitable<std::size_t> override { co_return co_await Inner_->async_read_some(b, ec); }
        [[nodiscard]] auto async_write_some(std::span<const std::byte> b, std::error_code &ec) -> Net::awaitable<std::size_t> override { co_return co_await Inner_->async_write_some(b, ec); }
        void Close() override { Inner_->Close(); }
        void Cancel() override { Inner_->Cancel(); }
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
