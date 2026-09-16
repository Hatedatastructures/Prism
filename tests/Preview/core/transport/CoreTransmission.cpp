/**
 * @file CoreTransmission.cpp
 * @brief preview/Transport/Transmission.hpp 单元测试
 * @details 覆盖 Preview::Transmission 传输抽象接口：
 * 1. 内存 mock（可配置读/写行为）验证全部纯虚方法：async_read_some、
 *    async_write_some、Close、Cancel、Executor
 * 2. 组合操作 AsyncRead/AsyncWrite 的正常、分块、EOF、错误分支
 * 3. completion-handler 桥接路径（co_spawn + ToEc 错误映射三分支）
 * 4. 装饰器链：TransportType 委托、NextLayer 默认、lowest_layer 转型
 * 5. Release() 默认与覆写、TransmissionLike 概念
 */

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Preview = ::Preview;
    namespace Net = boost::asio;

    /// 叶子传输：仅实现纯虚方法，不覆写任何默认实现（测基类默认分支）
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

        bool Closed_{false};
        bool Canceled_{false};

    private:
        Net::any_io_executor Ex_;
    };

    /// 装饰器 mock：可配置读/写行为，支持 Inner 链与 Release 所有权转移
    class MockTransmission : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit MockTransmission(Net::any_io_executor Ex, Preview::Transmission *Inner = nullptr)
            : Ex_(std::move(Ex)), Inner_(Inner)
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> Net::awaitable<std::size_t> override
        {
            if (read_err_)
            {
                ec = *read_err_;
                co_return 0;
            }
            if (read_buf_.empty())
            {
                ec.clear();
                co_return 0; // EOF
            }
            const auto n = std::min(Buffer.size(), std::min(read_buf_.size(), read_max_));
            std::memcpy(Buffer.data(), read_buf_.data(), n);
            read_buf_.erase(read_buf_.begin(), read_buf_.begin() + static_cast<std::ptrdiff_t>(n));
            ec.clear();
            co_return n;
        }

        auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> Net::awaitable<std::size_t> override
        {
            if (write_err_)
            {
                ec = *write_err_;
                co_return 0;
            }
            if (write_zero_)
            {
                ec.clear();
                co_return 0;
            }
            const auto n = std::min(Buffer.size(), write_max_);
            written_ += n;
            ec.clear();
            co_return n;
        }

        auto Close() -> void override
        {
            Closed_ = true;
        }

        auto Cancel() -> void override
        {
            Canceled_ = true;
        }

        auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Inner_;
        }

        auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return Inner_;
        }

        auto Release() -> std::shared_ptr<Preview::Transmission> override
        {
            auto r = std::move(Released_);
            Released_.reset();
            return r;
        }

        /// 配置：设置预读数据
        auto SetReadData(std::vector<std::byte> Data) -> void
        {
            read_buf_ = std::move(Data);
        }

        /// 配置：设置单次最大读取字节数（0 = 无限）
        auto SetReadMax(std::size_t Maximum) -> void
        {
            read_max_ = Maximum;
        }

        /// 配置：设置读错误（覆盖 EOF 行为）
        auto SetReadError(std::error_code Error) -> void
        {
            read_err_ = Error;
        }

        /// 配置：设置单次最大写入字节数（0 = 无限）
        auto SetWriteMax(std::size_t Maximum) -> void
        {
            write_max_ = Maximum;
        }

        /// 配置：写返回 0（模拟 broken pipe）
        auto SetWriteZero(bool Enabled) -> void
        {
            write_zero_ = Enabled;
        }

        /// 配置：设置写错误
        auto SetWriteError(std::error_code Error) -> void
        {
            write_err_ = Error;
        }

        /// 配置：设置 Release() 转移的底层传输
        auto SetRelease(std::shared_ptr<Preview::Transmission> Transmission) -> void
        {
            Released_ = std::move(Transmission);
        }

        std::size_t written_{0};
        bool Closed_{false};
        bool Canceled_{false};

    private:
        Net::any_io_executor Ex_;
        Preview::Transmission *Inner_{nullptr};
        std::vector<std::byte> read_buf_;
        std::optional<std::error_code> read_err_;
        std::size_t read_max_{SIZE_MAX};
        std::size_t write_max_{SIZE_MAX};
        bool write_zero_{false};
        std::optional<std::error_code> write_err_;
        std::shared_ptr<Preview::Transmission> Released_;
    };

    /// UDP 装饰器：覆写 TransportType 返回 udp
    class UdpDecorator final : public MockTransmission
    {
    public:
        using MockTransmission::MockTransmission;

        auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }
    };

    /// 非 final 中间类：仅实现纯虚方法，不覆写默认实现（阻止 devirtualize 内联）
    class IntermediateTransmission : public Preview::Transmission
    {
    public:
        explicit IntermediateTransmission(Net::any_io_executor Ex) : Ex_(std::move(Ex))
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
        }

        auto Cancel() -> void override
        {
        }

    private:
        Net::any_io_executor Ex_;
    };

    class ThrowingTransmission final : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit ThrowingTransmission(Net::any_io_executor Ex) : Ex_(std::move(Ex))
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto async_read_some(std::span<std::byte>, std::error_code &)
            -> Net::awaitable<std::size_t> override
        {
            throw std::runtime_error("read failure");
        }

        auto async_write_some(std::span<const std::byte>, std::error_code &)
            -> Net::awaitable<std::size_t> override
        {
            throw std::runtime_error("write failure");
        }

        void Close() override
        {
        }

        void Cancel() override
        {
        }

    private:
        Net::any_io_executor Ex_;
    };

    TEST(CoreTransmission, ConceptSatisfied)
    {
        // 基类与 mock 均满足 TransmissionLike 概念
        static_assert(Preview::TransmissionLike<Preview::Transmission>);
        static_assert(Preview::TransmissionLike<LeafTransmission>);
        static_assert(Preview::TransmissionLike<MockTransmission>);
    }

    TEST(CoreTransmission, TransportTypeLeaf)
    {
        // 叶子：NextLayer() 为空 → 默认返回 Tcp
        Net::io_context ioc;
        LeafTransmission t(ioc.get_executor());
        EXPECT_EQ(t.TransportType(), Preview::Transmission::Type::Tcp);
    }

    TEST(CoreTransmission, TransportTypeDelegate)
    {
        // 装饰器链：委托给底层传输获取真实类型
        Net::io_context ioc;
        UdpDecorator leaf(ioc.get_executor());
        MockTransmission mid(ioc.get_executor(), &leaf);
        MockTransmission top(ioc.get_executor(), &mid);

        EXPECT_EQ(leaf.TransportType(), Preview::Transmission::Type::Udp);
        EXPECT_EQ(mid.TransportType(), Preview::Transmission::Type::Udp);
        EXPECT_EQ(top.TransportType(), Preview::Transmission::Type::Udp);
    }

    TEST(CoreTransmission, get_executor)
    {
        Net::io_context ioc;
        LeafTransmission t(ioc.get_executor());
        // get_executor() 兼容 Asio Executor 概念，委托 Executor()
        EXPECT_EQ(t.get_executor(), ioc.get_executor());
    }

    TEST(CoreTransmission, NextLayerDefault)
    {
        // 基类默认实现：叶子节点返回 nullptr（const 与非 const 版本）
        Net::io_context ioc;
        LeafTransmission t(ioc.get_executor());
        EXPECT_EQ(t.NextLayer(), nullptr);
        const auto &ct = t;
        EXPECT_EQ(ct.NextLayer(), nullptr);
    }

    TEST(CoreTransmission, LowestLayerSuccess)
    {
        // 沿装饰器链导航到链底并转型成功
        Net::io_context ioc;
        auto c = std::make_unique<MockTransmission>(ioc.get_executor());
        auto b = std::make_unique<MockTransmission>(ioc.get_executor(), c.get());
        auto a = std::make_unique<MockTransmission>(ioc.get_executor(), b.get());

        EXPECT_EQ(a->lowest_layer<MockTransmission>(), c.get());
        EXPECT_EQ(a->lowest_layer<Preview::Transmission>(), c.get());

        // const 版本
        const auto *ca = a.get();
        EXPECT_EQ(ca->lowest_layer<MockTransmission>(), c.get());
        EXPECT_EQ(ca->lowest_layer<Preview::Transmission>(), c.get());
    }

    TEST(CoreTransmission, LowestLayerTypeMiss)
    {
        // dynamic_cast 失败 → 返回 nullptr
        Net::io_context ioc;
        auto c = std::make_unique<MockTransmission>(ioc.get_executor());
        auto a = std::make_unique<MockTransmission>(ioc.get_executor(), c.get());

        EXPECT_EQ(a->lowest_layer<UdpDecorator>(), nullptr);
        const auto *ca = a.get();
        EXPECT_EQ(ca->lowest_layer<UdpDecorator>(), nullptr);
    }

    TEST(CoreTransmission, ReleaseDefault)
    {
        // 基类默认实现：返回空共享指针（经基类引用虚调用，确保入口计数）
        Net::io_context ioc;
        IntermediateTransmission t(ioc.get_executor());
        Preview::Transmission &ref = t;
        auto got = ref.Release();
        EXPECT_EQ(got, nullptr);
    }

    TEST(CoreTransmission, ReleaseOverride)
    {
        // 覆写路径：转移底层传输所有权
        Net::io_context ioc;
        auto Inner = std::make_shared<MockTransmission>(ioc.get_executor());
        MockTransmission t(ioc.get_executor());
        t.SetRelease(Inner);

        auto got = t.Release();
        EXPECT_EQ(got.get(), Inner.get());
        // 第二次调用：已转移，返回空
        auto again = t.Release();
        EXPECT_EQ(again, nullptr);
    }

    TEST(CoreTransmission, CloseCancel)
    {
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.Close();
        EXPECT_TRUE(t.Closed_);
        t.Cancel();
        EXPECT_TRUE(t.Canceled_);
    }

    TEST(CoreTransmission, AsyncReadFull)
    {
        // 单轮读满
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetReadData({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_FALSE(ec);
        for (std::size_t i = 0; i < 8; ++i)
        {
            EXPECT_EQ(buf[i], static_cast<std::byte>(i + 1));
        }
    }

    TEST(CoreTransmission, AsyncReadChunked)
    {
        // 分块读取：多次 async_read_some 直至读满
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetReadData({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
        t.SetReadMax(3);
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncReadEof)
    {
        // 数据耗尽（EOF）：提前返回已读字节数
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetReadData({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}});
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 4);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncReadError)
    {
        // 读取错误：立即返回，不循环
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetReadError(std::make_error_code(std::errc::io_error));
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, std::make_error_code(std::errc::io_error));
    }

    TEST(CoreTransmission, AsyncWriteFull)
    {
        // 单轮写满
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_EQ(t.written_, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncWriteChunked)
    {
        // 分块写入：多次 async_write_some 直至写满
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetWriteMax(3);
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_EQ(t.written_, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncWriteError)
    {
        // 写入错误：立即返回
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetWriteError(std::make_error_code(std::errc::io_error));
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, std::make_error_code(std::errc::io_error));
    }

    TEST(CoreTransmission, AsyncWriteBrokenPipe)
    {
        // 对端关闭：写返回 0 → 映射为 broken_pipe
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        t.SetWriteZero(true);
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        Net::co_spawn(
            ioc.get_executor(),
            [&]() -> Net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            Net::detached);
        ioc.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, Preview::make_error_code(Preview::Error::BrokenPipe));
    }

    TEST(CoreTransmission, HandlerReadSuccess)
    {
        // completion-handler 桥接：成功路径（ToEc 空错误分支）
        Net::io_context ioc;
        auto t = std::make_shared<MockTransmission>(ioc.get_executor());
        t->SetReadData({std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}});
        std::byte buf[8]{};
        boost::system::error_code got_ec{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        std::size_t got_n = 0;

        t->async_read_some(buf, [&](boost::system::error_code ec, std::size_t n)
                           {
                               got_ec = ec;
                               got_n = n;
                           });
        ioc.run();

        EXPECT_FALSE(got_ec);
        EXPECT_EQ(got_n, 5);
    }

    TEST(CoreTransmission, HandlerWriteSuccess)
    {
        // completion-handler 桥接：写入成功路径
        Net::io_context ioc;
        auto t = std::make_shared<MockTransmission>(ioc.get_executor());
        const std::byte buf[3]{};
        boost::system::error_code got_ec{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        std::size_t got_n = 0;

        t->async_write_some(buf, [&](boost::system::error_code ec, std::size_t n)
                            {
                                got_ec = ec;
                                got_n = n;
                            });
        ioc.run();

        EXPECT_FALSE(got_ec);
        EXPECT_EQ(got_n, 3);
        EXPECT_EQ(t->written_, 3);
    }

    TEST(CoreTransmission, HandlerReadErrorProtocol)
    {
        // completion-handler 桥接：Preview 协议错误 → boost 侧保留协议分类
        Net::io_context ioc;
        auto t = std::make_shared<MockTransmission>(ioc.get_executor());
        t->SetReadError(
            static_cast<std::error_code>(Preview::make_error_code(Preview::Error::NeedMore)));
        std::byte buf[8]{};
        boost::system::error_code got_ec;
        std::size_t got_n = 999;

        t->async_read_some(buf, [&](boost::system::error_code ec, std::size_t n)
                           {
                               got_ec = ec;
                               got_n = n;
                           });
        ioc.run();

        EXPECT_EQ(got_n, 0);
        EXPECT_TRUE(got_ec);
        EXPECT_EQ(std::string_view(got_ec.category().name()), "prism.protocol");
        EXPECT_EQ(got_ec.value(), static_cast<int>(Preview::Error::NeedMore));
    }

    TEST(CoreTransmission, HandlerWriteErrorGeneric)
    {
        // completion-handler 桥接：非协议错误 → boost 侧归入 generic 分类
        Net::io_context ioc;
        auto t = std::make_shared<MockTransmission>(ioc.get_executor());
        t->SetWriteError(std::make_error_code(std::errc::io_error));
        const std::byte buf[8]{};
        boost::system::error_code got_ec;
        std::size_t got_n = 999;

        t->async_write_some(buf, [&](boost::system::error_code ec, std::size_t n)
                            {
                                got_ec = ec;
                                got_n = n;
                            });
        ioc.run();

        EXPECT_EQ(got_n, 0);
        EXPECT_TRUE(got_ec);
        EXPECT_EQ(std::string_view(got_ec.category().name()), "generic");
        EXPECT_EQ(got_ec.value(), static_cast<int>(std::errc::io_error));
    }

    TEST(CoreTransmission, CompletionHandlerReportsReadException)
    {
        Net::io_context ioc;
        auto Transport = std::make_shared<ThrowingTransmission>(ioc.get_executor());
        std::array<std::byte, 4> Buffer{};
        bool Called = false;
        boost::system::error_code Error;
        std::size_t Bytes = 1;

        Transport->async_read_some(
            Buffer,
            [&](boost::system::error_code Ec, const std::size_t N)
            {
                Called = true;
                Error = Ec;
                Bytes = N;
            });
        ioc.run();

        EXPECT_TRUE(Called);
        EXPECT_EQ(Error, boost::system::errc::make_error_code(boost::system::errc::io_error));
        EXPECT_EQ(Bytes, 0U);
    }

    TEST(CoreTransmission, CompletionHandlerReportsWriteException)
    {
        Net::io_context ioc;
        auto Transport = std::make_shared<ThrowingTransmission>(ioc.get_executor());
        const std::array<std::byte, 4> Buffer{};
        bool Called = false;
        boost::system::error_code Error;
        std::size_t Bytes = 1;

        Transport->async_write_some(
            Buffer,
            [&](boost::system::error_code Ec, const std::size_t N)
            {
                Called = true;
                Error = Ec;
                Bytes = N;
            });
        ioc.run();

        EXPECT_TRUE(Called);
        EXPECT_EQ(Error, boost::system::errc::make_error_code(boost::system::errc::io_error));
        EXPECT_EQ(Bytes, 0U);
    }

    TEST(CoreTransmission, CompletionHandlerRejectsStackOwnedTransport)
    {
        Net::io_context ioc;
        MockTransmission t(ioc.get_executor());
        bool called = false;
        t.async_read_some(std::span<std::byte>{},
                          [&](boost::system::error_code ec, std::size_t n)
                          {
                              called = true;
                              EXPECT_EQ(n, 0u);
                              EXPECT_EQ(ec, boost::system::errc::make_error_code(
                                                 boost::system::errc::not_supported));
                          });
        ioc.run();
        EXPECT_TRUE(called);
    }
} // namespace
