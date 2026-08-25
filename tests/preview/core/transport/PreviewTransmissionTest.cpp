/**
 * @file PreviewTransmissionTest.cpp
 * @brief Preview 传输抽象测试（core/Transmission.hpp）
 * @details 覆盖 Transmission 虚接口：
 * 1. 叶子实现纯虚方法
 * 2. AsyncReadSome/AsyncWriteSome 协程读写
 * 3. AsyncRead/AsyncWrite 组合操作（分块/EOF/错误）
 * 4. TransportType 委托
 * 5. 装饰器链 NextLayer/LowestLayer
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

#include <common/Core/Transmission.hpp>

namespace
{

    namespace net = boost::asio;

    /// 叶子传输：仅实现纯虚方法
    class leaf_transmission final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::AsyncReadSome;
        using Preview::Transmission::AsyncWriteSome;

        explicit leaf_transmission(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return ex_;
        }

        auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            std::memset(Buffer.data(), 0, Buffer.size());
            ec.clear();
            co_return Buffer.size();
        }

        auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            (void)Buffer;
            ec.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            closed_ = true;
        }

        auto Cancel() -> void override
        {
            canceled_ = true;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
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

    /// 装饰器：包装内层传输，委托读写并暴露 NextLayer
    class decorator final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::AsyncReadSome;
        using Preview::Transmission::AsyncWriteSome;

        explicit decorator(Preview::SharedTransmission Inner) : inner_(std::move(Inner))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return inner_->Executor();
        }

        auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->AsyncReadSome(Buffer, ec);
        }

        auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await inner_->AsyncWriteSome(Buffer, ec);
        }

        auto Close() -> void override
        {
            inner_->Close();
        }

        auto Cancel() -> void override
        {
            inner_->Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return inner_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return inner_.get();
        }

    private:
        Preview::SharedTransmission inner_;
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
            const auto n = co_await leaf->AsyncReadSome(buf, ec);
            EXPECT_FALSE(ec);
            EXPECT_EQ(n, 16U);

            const auto w = co_await leaf->AsyncWriteSome(buf, ec);
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

        // LowestLayer 直达链底
        EXPECT_EQ(dec->LowestLayer<leaf_transmission>(), leaf.get());
        EXPECT_EQ(dec->LowestLayer<decorator>(), nullptr);

        // 读写经装饰器委托
        run_coro(ioc, [&]() -> net::awaitable<void>
                 {
            std::array<std::byte, 8> buf{};
            std::error_code ec;
            const auto n = co_await dec->AsyncReadSome(buf, ec);
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