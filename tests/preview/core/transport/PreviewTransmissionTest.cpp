/**
 * @file PreviewTransmissionTest.cpp
 * @brief preview 传输抽象测试（core/transmission.hpp）
 * @details 覆盖 transmission 虚接口：
 * 1. 叶子实现纯虚方法
 * 2. async_read_some/async_write_some 协程读写
 * 3. async_read/async_write 组合操作（分块/EOF/错误）
 * 4. transport_type 委托
 * 5. 装饰器链 next_layer/lowest_layer
 * 6. shared_transmission 生命周期
 * 7. transmission_like 概念
 */

#include <gtest/gtest.h>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>

#include <common/core/transmission.hpp>

namespace
{

    namespace net = boost::asio;

    /// 叶子传输：仅实现纯虚方法
    class leaf_transmission final : public preview::transmission
    {
    public:
        using preview::transmission::async_read_some;
        using preview::transmission::async_write_some;

        explicit leaf_transmission(net::any_io_executor ex) : ex_(std::move(ex))
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
            closed_ = true;
        }

        auto cancel() -> void override
        {
            canceled_ = true;
        }

        [[nodiscard]] auto is_open() const -> bool override
        {
            return !closed_;
        }

        [[nodiscard]] auto closed() const -> bool
        {
            return closed_;
        }

        [[nodiscard]] auto canceled() const -> bool
        {
            return canceled_;
        }

    private:
        net::any_io_executor ex_;
        bool closed_{false};
        bool canceled_{false};
    };

    /// 装饰器：包装内层传输，委托读写并暴露 next_layer
    class decorator final : public preview::transmission
    {
    public:
        using preview::transmission::async_read_some;
        using preview::transmission::async_write_some;

        explicit decorator(preview::shared_transmission inner) : inner_(std::move(inner))
        {
        }

        auto executor() const -> executor_type override
        {
            return inner_->executor();
        }

        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->async_read_some(buffer, ec);
        }

        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->async_write_some(buffer, ec);
        }

        auto close() -> void override
        {
            inner_->close();
        }

        auto cancel() -> void override
        {
            inner_->cancel();
        }

        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return inner_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return inner_.get();
        }

    private:
        preview::shared_transmission inner_;
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

    TEST(PreviewTransmission, LeafReadWrite)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::byte, 16> buf{};
            std::error_code ec;
            const auto n = co_await leaf->async_read_some(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 16U);

            const auto w = co_await leaf->async_write_some(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(w, 16U); });
    }

    TEST(PreviewTransmission, AsyncReadCombined)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::byte, 32> buf{};
            std::error_code ec;
            const auto n = co_await leaf->async_read(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 32U); });
    }

    TEST(PreviewTransmission, AsyncWriteCombined)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::byte, 32> buf{};
            std::error_code ec;
            const auto n = co_await leaf->async_write(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 32U); });
    }

    TEST(PreviewTransmission, TransportTypeDelegate)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        // 叶子默认 tcp
        EXPECT_EQ(leaf->transport_type(), preview::transmission::type::tcp);

        // 装饰器委托到底层
        auto dec = std::make_shared<decorator>(leaf);
        EXPECT_EQ(dec->transport_type(), preview::transmission::type::tcp);
    }

    TEST(PreviewTransmission, DecoratorChain)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        auto dec = std::make_shared<decorator>(leaf);

        // next_layer 导航
        EXPECT_EQ(dec->next_layer(), leaf.get());

        // lowest_layer 直达链底
        EXPECT_EQ(dec->lowest_layer<leaf_transmission>(), leaf.get());
        EXPECT_EQ(dec->lowest_layer<decorator>(), nullptr);

        // 读写经装饰器委托
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::byte, 8> buf{};
            std::error_code ec;
            const auto n = co_await dec->async_read_some(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 8U); });
    }

    TEST(PreviewTransmission, CloseCancel)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        EXPECT_TRUE(leaf->is_open());

        leaf->cancel();
        EXPECT_TRUE(leaf->canceled());

        leaf->close();
        EXPECT_FALSE(leaf->is_open());
        EXPECT_TRUE(leaf->closed());
    }

    TEST(PreviewTransmission, SharedPtrLifecycle)
    {
        net::io_context ioc;
        preview::shared_transmission t = std::make_shared<leaf_transmission>(ioc.get_executor());
        ASSERT_NE(t, nullptr);
        EXPECT_EQ(t.use_count(), 1L);
    }

    TEST(PreviewTransmission, ReleaseDefault)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        // 基类默认 release 返回空
        const auto released = leaf->release();
        EXPECT_EQ(released, nullptr);
    }

    TEST(PreviewTransmission, Concept)
    {
        static_assert(preview::transmission_like<preview::transmission>);
        static_assert(preview::transmission_like<leaf_transmission>);
        static_assert(preview::transmission_like<decorator>);
    }

} // namespace