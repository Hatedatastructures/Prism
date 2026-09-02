/**
 * @file PreviewTransmissionTest.cpp
 * @brief Preview 传输抽象测试（preview/Transport/Transmission.hpp）
 * @details 覆盖 Transmission 虚接口：
 * 1. 叶子实现纯虚方法
 * 2. async_read_some/async_write_some 协程读写
 * 3. AsyncRead/AsyncWrite 组合操作（分块/EOF/错误）
 * 4. TransportType 委托
 * 5. 装饰器链 NextLayer/lowest_layer
 * 6. SharedTransmission 生命周期
 * 7. TransmissionLike 概念
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

#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace net = boost::asio;

    /// 叶子传输：仅实现纯虚方法
    class leaf_transmission final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit leaf_transmission(net::any_io_executor ex) : Ex_(std::move(ex))
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
            if (ReadOverreport_)
            {
                co_return Buffer.size() + 1;
            }
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
            Closed_ = true;
        }

        auto Cancel() -> void override
        {
            Canceled_ = true;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return !Closed_;
        }

        [[nodiscard]] auto closed() const -> bool
        {
            return Closed_;
        }

        [[nodiscard]] auto canceled() const -> bool
        {
            return Canceled_;
        }

        void set_read_overreport(const bool Value)
        {
            ReadOverreport_ = Value;
        }

    private:
        net::any_io_executor Ex_;
        bool Closed_{false};
        bool Canceled_{false};
        bool ReadOverreport_{false};
    };

    /// 装饰器：包装内层传输，委托读写并暴露 NextLayer
    class decorator final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit decorator(Preview::SharedTransmission Inner) : Inner_(std::move(Inner))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_read_some(Buffer, ec);
        }

        auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_write_some(Buffer, ec);
        }

        auto Close() -> void override
        {
            Inner_->Close();
        }

        auto Cancel() -> void override
        {
            Inner_->Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return Inner_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return Inner_.get();
        }

    private:
        Preview::SharedTransmission Inner_;
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
            const auto n = co_await leaf->AsyncRead(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 32U); });
    }

    TEST(PreviewTransmission, AsyncReadRejectsOverreportedProgress)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        leaf->set_read_overreport(true);
        std::size_t done = 0;
        std::error_code ec;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
                     std::array<std::byte, 8> buf{};
                     done = co_await leaf->AsyncRead(buf, ec);
                 });

        EXPECT_EQ(done, 0U);
        EXPECT_EQ(ec, Preview::make_error_code(Preview::Error::BrokenPipe));
    }

    TEST(PreviewTransmission, AsyncWriteCombined)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::byte, 32> buf{};
            std::error_code ec;
            const auto n = co_await leaf->AsyncWrite(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 32U); });
    }

    TEST(PreviewTransmission, AsyncWriteRejectsOverreportedProgress)
    {
        net::io_context ioc;
        auto transport = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        transport->OverreportWrite = true;
        std::size_t done = 0;
        std::error_code ec;

        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
                     const std::array<std::byte, 8> buf{};
                     done = co_await transport->AsyncWrite(buf, ec);
                 });

        EXPECT_EQ(done, 0U);
        EXPECT_EQ(ec, Preview::make_error_code(Preview::Error::BrokenPipe));
        EXPECT_TRUE(transport->Written.empty());
    }

    TEST(PreviewTransmission, TransportTypeDelegate)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        // 叶子默认 Tcp
        EXPECT_EQ(leaf->TransportType(), Preview::Transmission::Type::Tcp);

        // 装饰器委托到底层
        auto dec = std::make_shared<decorator>(leaf);
        EXPECT_EQ(dec->TransportType(), Preview::Transmission::Type::Tcp);
    }

    TEST(PreviewTransmission, DecoratorChain)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        auto dec = std::make_shared<decorator>(leaf);

        // NextLayer 导航
        EXPECT_EQ(dec->NextLayer(), leaf.get());

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
        EXPECT_TRUE(leaf->IsOpen());

        leaf->Cancel();
        EXPECT_TRUE(leaf->canceled());

        leaf->Close();
        EXPECT_FALSE(leaf->IsOpen());
        EXPECT_TRUE(leaf->closed());
    }

    TEST(PreviewTransmission, SharedPtrLifecycle)
    {
        net::io_context ioc;
        Preview::SharedTransmission t = std::make_shared<leaf_transmission>(ioc.get_executor());
        ASSERT_NE(t, nullptr);
        EXPECT_EQ(t.use_count(), 1L);
    }

    TEST(PreviewTransmission, ReleaseDefault)
    {
        net::io_context ioc;
        auto leaf = std::make_shared<leaf_transmission>(ioc.get_executor());
        // 基类默认 Release 返回空
        const auto released = leaf->Release();
        EXPECT_EQ(released, nullptr);
    }

    TEST(PreviewTransmission, Concept)
    {
        static_assert(Preview::TransmissionLike<Preview::Transmission>);
        static_assert(Preview::TransmissionLike<leaf_transmission>);
        static_assert(Preview::TransmissionLike<decorator>);
    }

} // namespace
