/**
 * @file SchemeExecutorTest.cpp
 * @brief 伪装方案执行器注册表验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>

#include <preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <preview/Transport/Transmission.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace Preview;
    using namespace Preview::Recognition;

    struct fake_tx final : Transmission
    {
        explicit fake_tx(net::any_io_executor ex) : Ex_(ex) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Ex_; }
        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        void Close() override {}
        void Cancel() override {}
        net::any_io_executor Ex_;
    };

    class decorator final : public Transmission
    {
    public:
        explicit decorator(SharedTransmission Inner) : Inner_(std::move(Inner)) {}
        [[nodiscard]] auto Executor() const -> ExecutorType override { return Inner_->Executor(); }
        [[nodiscard]] auto async_read_some(std::span<std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override { co_return co_await Inner_->async_read_some(b, ec); }
        [[nodiscard]] auto async_write_some(std::span<const std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override { co_return co_await Inner_->async_write_some(b, ec); }
        void Close() override { Inner_->Close(); }
        void Cancel() override { Inner_->Cancel(); }
        [[nodiscard]] auto NextLayer() noexcept -> Transmission* override { return Inner_.get(); }
        bool wrapped{true};
    private:
        SharedTransmission Inner_;
    };

    auto run_coro(net::io_context &ioc, auto coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e){ ep=e; ioc.stop(); });
        ioc.run();
        if (ep) std::rethrow_exception(ep);
    }

    TEST(SchemeExecutor, RegisterAndExecute)
    {
        net::io_context ioc;
        SchemeExecutor exec;
        bool called = false;
        exec.RegisterScheme("anytls", [&](SharedTransmission Inbound) -> net::awaitable<SharedTransmission>
        {
            called = true;
            co_return std::make_shared<decorator>(std::move(Inbound));
        });
        EXPECT_TRUE(exec.Has("anytls"));
        EXPECT_EQ(exec.Size(), 1u);
        EXPECT_FALSE(exec.RegisterScheme("anytls", [](SharedTransmission in) -> net::awaitable<SharedTransmission> { co_return in; }));

        bool wrapped = false;
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto Inner = std::make_shared<fake_tx>(ioc.get_executor());
            auto out = co_await exec.Execute("anytls", Inner);
            auto dec = std::dynamic_pointer_cast<decorator>(out);
            wrapped = dec && dec->wrapped;
        });
        EXPECT_TRUE(called);
        EXPECT_TRUE(wrapped);
    }

    TEST(SchemeExecutor, EmptySchemePassthrough)
    {
        net::io_context ioc;
        SchemeExecutor exec;
        exec.RegisterScheme("reality", [](SharedTransmission in) -> net::awaitable<SharedTransmission> { co_return in; });
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto Inner = std::make_shared<fake_tx>(ioc.get_executor());
            auto out = co_await exec.Execute("", Inner);
            EXPECT_EQ(out.get(), Inner.get());
            auto out2 = co_await exec.Execute("unknown", Inner);
            EXPECT_EQ(out2.get(), Inner.get());
        });
    }

    TEST(SchemeExecutor, MultipleSchemes)
    {
        SchemeExecutor exec;
        exec.RegisterScheme("shadowtls", [](SharedTransmission in) -> net::awaitable<SharedTransmission> { co_return in; });
        exec.RegisterScheme("restls", [](SharedTransmission in) -> net::awaitable<SharedTransmission> { co_return in; });
        exec.RegisterScheme("ws", [](SharedTransmission in) -> net::awaitable<SharedTransmission> { co_return in; });
        EXPECT_EQ(exec.Size(), 3u);
        EXPECT_TRUE(exec.Has("shadowtls"));
        EXPECT_TRUE(exec.Has("restls"));
        EXPECT_TRUE(exec.Has("ws"));
        EXPECT_FALSE(exec.Has("anytls"));
    }

} // namespace
