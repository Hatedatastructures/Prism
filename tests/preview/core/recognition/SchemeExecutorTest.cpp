/**
 * @file SchemeExecutorTest.cpp
 * @brief 伪装方案执行器注册表验证
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <memory>

#include <common/core/recognition/scheme_executor.hpp>
#include <common/core/transmission.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace preview;
    using namespace preview::recognition;

    struct fake_tx final : transmission
    {
        explicit fake_tx(net::any_io_executor ex) : ex_(ex) {}
        [[nodiscard]] auto executor() const -> executor_type override { return ex_; }
        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec) -> net::awaitable<std::size_t> override { ec.clear(); co_return 0; }
        void close() override {}
        void cancel() override {}
        net::any_io_executor ex_;
    };

    class decorator final : public transmission
    {
    public:
        explicit decorator(shared_transmission inner) : inner_(std::move(inner)) {}
        [[nodiscard]] auto executor() const -> executor_type override { return inner_->executor(); }
        [[nodiscard]] auto async_read_some(std::span<std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override { co_return co_await inner_->async_read_some(b, ec); }
        [[nodiscard]] auto async_write_some(std::span<const std::byte> b, std::error_code &ec) -> net::awaitable<std::size_t> override { co_return co_await inner_->async_write_some(b, ec); }
        void close() override { inner_->close(); }
        void cancel() override { inner_->cancel(); }
        [[nodiscard]] auto next_layer() noexcept -> transmission* override { return inner_.get(); }
        bool wrapped{true};
    private:
        shared_transmission inner_;
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
        scheme_executor exec;
        bool called = false;
        exec.register_scheme("anytls", [&](shared_transmission inbound) -> net::awaitable<shared_transmission>
        {
            called = true;
            co_return std::make_shared<decorator>(std::move(inbound));
        });
        EXPECT_TRUE(exec.has("anytls"));
        EXPECT_EQ(exec.size(), 1u);
        EXPECT_FALSE(exec.register_scheme("anytls", [](shared_transmission in) -> net::awaitable<shared_transmission> { co_return in; }));

        bool wrapped = false;
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto inner = std::make_shared<fake_tx>(ioc.get_executor());
            auto out = co_await exec.execute("anytls", inner);
            auto dec = std::dynamic_pointer_cast<decorator>(out);
            wrapped = dec && dec->wrapped;
        });
        EXPECT_TRUE(called);
        EXPECT_TRUE(wrapped);
    }

    TEST(SchemeExecutor, EmptySchemePassthrough)
    {
        net::io_context ioc;
        scheme_executor exec;
        exec.register_scheme("reality", [](shared_transmission in) -> net::awaitable<shared_transmission> { co_return in; });
        run_coro(ioc, [&]() -> net::awaitable<void>
        {
            auto inner = std::make_shared<fake_tx>(ioc.get_executor());
            auto out = co_await exec.execute("", inner);
            EXPECT_EQ(out.get(), inner.get());
            auto out2 = co_await exec.execute("unknown", inner);
            EXPECT_EQ(out2.get(), inner.get());
        });
    }

    TEST(SchemeExecutor, MultipleSchemes)
    {
        scheme_executor exec;
        exec.register_scheme("shadowtls", [](shared_transmission in) -> net::awaitable<shared_transmission> { co_return in; });
        exec.register_scheme("restls", [](shared_transmission in) -> net::awaitable<shared_transmission> { co_return in; });
        exec.register_scheme("ws", [](shared_transmission in) -> net::awaitable<shared_transmission> { co_return in; });
        EXPECT_EQ(exec.size(), 3u);
        EXPECT_TRUE(exec.has("shadowtls"));
        EXPECT_TRUE(exec.has("restls"));
        EXPECT_TRUE(exec.has("ws"));
        EXPECT_FALSE(exec.has("anytls"));
    }

} // namespace
