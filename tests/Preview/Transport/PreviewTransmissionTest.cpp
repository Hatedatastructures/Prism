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
        explicit LeafTransmission(Net::any_io_executor Ex) : Preview::Transmission(Ex), Ex_(std::move(Ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            std::memset(Buffer.data(), 0, Buffer.size());
            OperationFailure.clear();
            if (ReadOverreport_)
            {
                { std::move(Handler)(Preview::IoResult{Buffer.size() + 1, Preview::Fault::FromNative(OperationFailure)}); return; }
            }
            { std::move(Handler)(Preview::IoResult{Buffer.size(), Preview::Fault::FromNative(OperationFailure)}); return; }
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            std::error_code OperationFailure;
            (void)Buffer;
            OperationFailure.clear();
            { std::move(Handler)(Preview::IoResult{Buffer.size(), Preview::Fault::FromNative(OperationFailure)}); return; }
        }

        auto OnClose() -> ControlResult override
        {
            Closed_ = true;

            return {};
        }

        auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;

            return {};
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

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
    };

    /// 装饰器：包装内层传输，委托读写并暴露 NextLayer
    class Decorator final : public Preview::Transmission
    {
    public:
        explicit Decorator(Preview::SharedTransmission Inner) : Preview::Transmission(Inner->Executor()), Inner_(std::move(Inner))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->WriteSome(Buffer, std::move(Handler));
        }

        auto OnClose() -> ControlResult override
        {
            return Inner_->Close();

            return {};
        }

        auto OnCancel() -> ControlResult override
        {
            return Inner_->Cancel();

            return {};
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

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Preview::Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
    };

    /// 运行协程（co_spawn + ioc.Run 模式）
    template <typename Operation>
    static auto RunCoro(Net::io_context &Ioc, Operation &&OperationFactory) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::forward<Operation>(OperationFactory)(), [&](std::exception_ptr Error)
                      { Exception = Error; });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /**
     * @brief 验证叶子 Transmission 的异步读写基础操作。
     * @param Leaf 叶子传输 owner。
     * @return 完成读写字节和错误码断言的异步操作。
     */
    auto RunLeafReadWrite(const std::shared_ptr<LeafTransmission> &Leaf)
        -> Net::awaitable<void>
    {
        std::array<std::byte, 16> Buffer{};
        Preview::Fault::Failure ErrorCode;
        const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Leaf->ReadSome(Buffer));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Count, 16U);

        const auto Written = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Leaf->WriteSome(Buffer));
        EXPECT_TRUE(ErrorCode.Succeeded());
        EXPECT_EQ(Written, 16U);
    }

    TEST(PreviewTransmission, LeafReadWrite)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());

        RunCoro(Ioc, [Leaf]() -> Net::awaitable<void>
                 { return RunLeafReadWrite(Leaf); });
    }

    TEST(PreviewTransmission, AsyncReadCombined)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
            std::array<std::byte, 32> Buffer{};
            Preview::Fault::Failure ErrorCode;
            const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Leaf->ReadExact(Buffer));
            EXPECT_TRUE(ErrorCode.Succeeded());
            EXPECT_EQ(Count, 32U); });
    }

    TEST(PreviewTransmission, AsyncReadRejectsOverreportedProgress)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        Leaf->SetReadOverreport(true);
        std::size_t Done = 0;
        Preview::Fault::Failure ErrorCode;

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
                     std::array<std::byte, 8> Buffer{};
                     Done = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Leaf->ReadExact(Buffer));
                 });

        EXPECT_EQ(Done, 0U);
        EXPECT_EQ(ErrorCode.Code, Preview::Fault::Code::InvalidArgument);
    }

    TEST(PreviewTransmission, AsyncWriteCombined)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
            std::array<std::byte, 32> Buffer{};
            Preview::Fault::Failure ErrorCode;
            const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Leaf->WriteExact(Buffer));
            EXPECT_TRUE(ErrorCode.Succeeded());
            EXPECT_EQ(Count, 32U); });
    }

    TEST(PreviewTransmission, AsyncWriteRejectsOverreportedProgress)
    {
        Net::io_context Ioc;
        auto Transport = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Transport->OverreportWrite = true;
        std::size_t Done = 0;
        Preview::Fault::Failure ErrorCode;

        RunCoro(Ioc, [&]() -> Net::awaitable<void>
                 {
                     const std::array<std::byte, 8> Buffer{};
                     Done = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Transport->WriteExact(Buffer));
                 });

        EXPECT_EQ(Done, 0U);
        EXPECT_EQ(ErrorCode.Code, Preview::Fault::Code::InvalidArgument);
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
            Preview::Fault::Failure ErrorCode;
            const auto Count = ([&](Preview::IoResult Result) { ErrorCode = Result.Failure; return Result.Bytes; })(co_await Decorated->ReadSome(Buffer));
            EXPECT_TRUE(ErrorCode.Succeeded());
            EXPECT_EQ(Count, 8U); });
    }

    TEST(PreviewTransmission, CloseCancel)
    {
        Net::io_context Ioc;
        auto Leaf = std::make_shared<LeafTransmission>(Ioc.get_executor());
        EXPECT_TRUE(Leaf->IsOpen());

        (void)Leaf->Cancel(); Ioc.run();
        EXPECT_TRUE(Leaf->Canceled());

        Ioc.restart(); (void)Leaf->Close(); Ioc.run();
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
