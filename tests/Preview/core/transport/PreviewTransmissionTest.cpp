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

#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;

    /// 叶子传输：仅实现纯虚方法
    class LeafTransmission final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit LeafTransmission(Net::any_io_executor Ex) : Ex_(std::move(Ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> Net::awaitable<std::size_t> override
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
            -> Net::awaitable<std::size_t> override
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

        [[nodiscard]] auto Closed() const -> bool
        {
            return Closed_;
        }

        [[nodiscard]] auto Canceled() const -> bool
        {
            return Canceled_;
        }

        void SetReadOverreport(const bool Value)
        {
            ReadOverreport_ = Value;
        }

    private:
        Net::any_io_executor Ex_;
        bool Closed_{false};
        bool Canceled_{false};
        bool ReadOverreport_{false};
    };

    /// 装饰器：包装内层传输，委托读写并暴露 NextLayer
    class Decorator final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit Decorator(Preview::SharedTransmission Inner) : Inner_(std::move(Inner))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> Net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_read_some(Buffer, ec);
        }

        auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> Net::awaitable<std::size_t> override
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
    template <typename Operation>
    static auto RunCoro(Net::io_context &Ioc, Operation &&OperationFactory) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::forward<Operation>(OperationFactory)(), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(PreviewTransmission, LeafReadWrite)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
            std::array<std::byte, 16> Buffer{};
            std::error_code ErrorCode;
            const auto Count = co_await Leaf->async_read_some(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(Count, 16U);

            const auto Written = co_await Leaf->async_write_some(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(Written, 16U); });
    }

    TEST(PreviewTransmission, AsyncReadCombined)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
            std::array<std::byte, 32> Buffer{};
            std::error_code ErrorCode;
            const auto Count = co_await Leaf->AsyncRead(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(Count, 32U); });
    }

    TEST(PreviewTransmission, AsyncReadRejectsOverreportedProgress)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        Leaf->SetReadOverreport(true);
        std::size_t Done = 0;
        std::error_code ErrorCode;

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
                     std::array<std::byte, 8> Buffer{};
                     Done = co_await Leaf->AsyncRead(Buffer, ErrorCode);
                 });

        EXPECT_EQ(Done, 0U);
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::BrokenPipe));
    }

    TEST(PreviewTransmission, AsyncWriteCombined)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
            std::array<std::byte, 32> Buffer{};
            std::error_code ErrorCode;
            const auto Count = co_await Leaf->AsyncWrite(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(Count, 32U); });
    }

    TEST(PreviewTransmission, AsyncWriteRejectsOverreportedProgress)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->OverreportWrite = true;
        std::size_t Done = 0;
        std::error_code ErrorCode;

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
                     const std::array<std::byte, 8> Buffer{};
                     Done = co_await Transport->AsyncWrite(Buffer, ErrorCode);
                 });

        EXPECT_EQ(Done, 0U);
        EXPECT_EQ(ErrorCode, Preview::make_error_code(Preview::Error::BrokenPipe));
        EXPECT_TRUE(Transport->Written.empty());
    }

    TEST(PreviewTransmission, TransportTypeDelegate)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        // 叶子默认 Tcp
        EXPECT_EQ(Leaf->TransportType(), Preview::Transmission::Type::Tcp);

        // 装饰器委托到底层
        auto Decorated = std::make_shared<Decorator>(Leaf);
        EXPECT_EQ(Decorated->TransportType(), Preview::Transmission::Type::Tcp);
    }

    TEST(PreviewTransmission, DecoratorChain)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        auto Decorated = std::make_shared<Decorator>(Leaf);

        // NextLayer 导航
        EXPECT_EQ(Decorated->NextLayer(), Leaf.get());

        // lowest_layer 直达链底
        EXPECT_EQ(Decorated->lowest_layer<LeafTransmission>(), Leaf.get());
        EXPECT_EQ(Decorated->lowest_layer<Decorator>(), nullptr);

        // 读写经装饰器委托
        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
            std::array<std::byte, 8> Buffer{};
            std::error_code ErrorCode;
            const auto Count = co_await Decorated->async_read_some(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(Count, 8U); });
    }

    TEST(PreviewTransmission, CloseCancel)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        EXPECT_TRUE(Leaf->IsOpen());

        Leaf->Cancel();
        EXPECT_TRUE(Leaf->Canceled());

        Leaf->Close();
        EXPECT_FALSE(Leaf->IsOpen());
        EXPECT_TRUE(Leaf->Closed());
    }

    TEST(PreviewTransmission, SharedPtrLifecycle)
    {
        Net::io_context Ioc;
        Preview::SharedTransmission Transmission = std::make_shared<LeafTransmission>(Ioc.get_executor());
        ASSERT_NE(Transmission, nullptr);
        EXPECT_EQ(Transmission.use_count(), 1L);
    }

    TEST(PreviewTransmission, ReleaseDefault)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        // 基类默认 Release 返回空
        const auto Released = Leaf->Release();
        EXPECT_EQ(Released, nullptr);
    }

    TEST(PreviewTransmission, Concept)
    {
        static_assert(Preview::TransmissionLike<Preview::Transmission>);
        static_assert(Preview::TransmissionLike<LeafTransmission>);
        static_assert(Preview::TransmissionLike<Decorator>);
    }

} // namespace
