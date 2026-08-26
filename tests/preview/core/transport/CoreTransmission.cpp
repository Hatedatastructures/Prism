/**
 * @file CoreTransmission.cpp
 * @brief tests/common/Core/Transmission.hpp 单元测试
 * @details 覆盖 Preview::Transmission 传输抽象接口：
 * 1. 内存 mock（可配置读/写行为）验证全部纯虚方法：async_read_some、
 *    async_write_some、Close、Cancel、Executor
 * 2. 组合操作 AsyncRead/AsyncWrite 的正常、分块、EOF、错误分支
 * 3. completion-handler 桥接路径（co_spawn + ToEc 错误映射三分支）
 * 4. 装饰器链：TransportType 委托、NextLayer 默认、lowest_layer 转型
 * 5. Release() 默认与覆写、TransmissionLike 概念
 */

#include <common/Core/Error.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Preview = ::Preview;
    namespace net = boost::asio;

    /// 叶子传输：仅实现纯虚方法，不覆写任何默认实现（测基类默认分支）
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

        bool Closed_{false};
        bool Canceled_{false};

    private:
        net::any_io_executor Ex_;
    };

    /// 装饰器 mock：可配置读/写行为，支持 Inner 链与 Release 所有权转移
    class mock_transmission : public Preview::Transmission
    {
    public:
        using Preview::Transmission::async_read_some;
        using Preview::Transmission::async_write_some;

        explicit mock_transmission(net::any_io_executor ex, Preview::Transmission *Inner = nullptr)
            : Ex_(std::move(ex)), Inner_(Inner)
        {
        }

        auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
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
            -> net::awaitable<std::size_t> override
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
        auto set_read_data(std::vector<std::byte> Data) -> void
        {
            read_buf_ = std::move(Data);
        }

        /// 配置：设置单次最大读取字节数（0 = 无限）
        auto set_read_max(std::size_t n) -> void
        {
            read_max_ = n;
        }

        /// 配置：设置读错误（覆盖 EOF 行为）
        auto SetReadError(std::error_code ec) -> void
        {
            read_err_ = ec;
        }

        /// 配置：设置单次最大写入字节数（0 = 无限）
        auto set_write_max(std::size_t n) -> void
        {
            write_max_ = n;
        }

        /// 配置：写返回 0（模拟 broken pipe）
        auto set_write_zero(bool on) -> void
        {
            write_zero_ = on;
        }

        /// 配置：设置写错误
        auto SetWriteError(std::error_code ec) -> void
        {
            write_err_ = ec;
        }

        /// 配置：设置 Release() 转移的底层传输
        auto set_release(std::shared_ptr<Preview::Transmission> t) -> void
        {
            Released_ = std::move(t);
        }

        std::size_t written_{0};
        bool Closed_{false};
        bool Canceled_{false};

    private:
        net::any_io_executor Ex_;
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
    class udp_decorator final : public mock_transmission
    {
    public:
        using mock_transmission::mock_transmission;

        auto TransportType() const noexcept -> Type override
        {
            return Type::Udp;
        }
    };

    /// 非 final 中间类：仅实现纯虚方法，不覆写默认实现（阻止 devirtualize 内联）
    class intermediate_transmission : public Preview::Transmission
    {
    public:
        explicit intermediate_transmission(net::any_io_executor ex) : Ex_(std::move(ex))
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
        }

        auto Cancel() -> void override
        {
        }

    private:
        net::any_io_executor Ex_;
    };

    TEST(CoreTransmission, ConceptSatisfied)
    {
        // 基类与 mock 均满足 TransmissionLike 概念
        static_assert(Preview::TransmissionLike<Preview::Transmission>);
        static_assert(Preview::TransmissionLike<leaf_transmission>);
        static_assert(Preview::TransmissionLike<mock_transmission>);
    }

    TEST(CoreTransmission, TransportTypeLeaf)
    {
        // 叶子：NextLayer() 为空 → 默认返回 Tcp
        net::io_context ioc;
        leaf_transmission t(ioc.get_executor());
        EXPECT_EQ(t.TransportType(), Preview::Transmission::Type::Tcp);
    }

    TEST(CoreTransmission, TransportTypeDelegate)
    {
        // 装饰器链：委托给底层传输获取真实类型
        net::io_context ioc;
        udp_decorator leaf(ioc.get_executor());
        mock_transmission mid(ioc.get_executor(), &leaf);
        mock_transmission top(ioc.get_executor(), &mid);

        EXPECT_EQ(leaf.TransportType(), Preview::Transmission::Type::Udp);
        EXPECT_EQ(mid.TransportType(), Preview::Transmission::Type::Udp);
        EXPECT_EQ(top.TransportType(), Preview::Transmission::Type::Udp);
    }

    TEST(CoreTransmission, get_executor)
    {
        net::io_context ioc;
        leaf_transmission t(ioc.get_executor());
        // get_executor() 兼容 Asio Executor 概念，委托 Executor()
        EXPECT_EQ(t.get_executor(), ioc.get_executor());
    }

    TEST(CoreTransmission, NextLayerDefault)
    {
        // 基类默认实现：叶子节点返回 nullptr（const 与非 const 版本）
        net::io_context ioc;
        leaf_transmission t(ioc.get_executor());
        EXPECT_EQ(t.NextLayer(), nullptr);
        const auto &ct = t;
        EXPECT_EQ(ct.NextLayer(), nullptr);
    }

    TEST(CoreTransmission, LowestLayerSuccess)
    {
        // 沿装饰器链导航到链底并转型成功
        net::io_context ioc;
        auto c = std::make_unique<mock_transmission>(ioc.get_executor());
        auto b = std::make_unique<mock_transmission>(ioc.get_executor(), c.get());
        auto a = std::make_unique<mock_transmission>(ioc.get_executor(), b.get());

        EXPECT_EQ(a->lowest_layer<mock_transmission>(), c.get());
        EXPECT_EQ(a->lowest_layer<Preview::Transmission>(), c.get());

        // const 版本
        const auto *ca = a.get();
        EXPECT_EQ(ca->lowest_layer<mock_transmission>(), c.get());
        EXPECT_EQ(ca->lowest_layer<Preview::Transmission>(), c.get());
    }

    TEST(CoreTransmission, LowestLayerTypeMiss)
    {
        // dynamic_cast 失败 → 返回 nullptr
        net::io_context ioc;
        auto c = std::make_unique<mock_transmission>(ioc.get_executor());
        auto a = std::make_unique<mock_transmission>(ioc.get_executor(), c.get());

        EXPECT_EQ(a->lowest_layer<udp_decorator>(), nullptr);
        const auto *ca = a.get();
        EXPECT_EQ(ca->lowest_layer<udp_decorator>(), nullptr);
    }

    TEST(CoreTransmission, ReleaseDefault)
    {
        // 基类默认实现：返回空共享指针（经基类引用虚调用，确保入口计数）
        net::io_context ioc;
        intermediate_transmission t(ioc.get_executor());
        Preview::Transmission &ref = t;
        auto got = ref.Release();
        EXPECT_EQ(got, nullptr);
    }

    TEST(CoreTransmission, ReleaseOverride)
    {
        // 覆写路径：转移底层传输所有权
        net::io_context ioc;
        auto Inner = std::make_shared<mock_transmission>(ioc.get_executor());
        mock_transmission t(ioc.get_executor());
        t.set_release(Inner);

        auto got = t.Release();
        EXPECT_EQ(got.get(), Inner.get());
        // 第二次调用：已转移，返回空
        auto again = t.Release();
        EXPECT_EQ(again, nullptr);
    }

    TEST(CoreTransmission, CloseCancel)
    {
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.Close();
        EXPECT_TRUE(t.Closed_);
        t.Cancel();
        EXPECT_TRUE(t.Canceled_);
    }

    TEST(CoreTransmission, AsyncReadFull)
    {
        // 单轮读满
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_read_data({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            net::detached);
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
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_read_data({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                         std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}});
        t.set_read_max(3);
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncReadEof)
    {
        // 数据耗尽（EOF）：提前返回已读字节数
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_read_data({std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}});
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 4);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncReadError)
    {
        // 读取错误：立即返回，不循环
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.SetReadError(std::make_error_code(std::errc::io_error));
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncRead(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, std::make_error_code(std::errc::io_error));
    }

    TEST(CoreTransmission, AsyncWriteFull)
    {
        // 单轮写满
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_EQ(t.written_, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncWriteChunked)
    {
        // 分块写入：多次 async_write_some 直至写满
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_write_max(3);
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 8);
        EXPECT_EQ(t.written_, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncWriteError)
    {
        // 写入错误：立即返回
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.SetWriteError(std::make_error_code(std::errc::io_error));
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, std::make_error_code(std::errc::io_error));
    }

    TEST(CoreTransmission, AsyncWriteBrokenPipe)
    {
        // 对端关闭：写返回 0 → 映射为 broken_pipe
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_write_zero(true);
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t Done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                Done = co_await t.AsyncWrite(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(Done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, Preview::make_error_code(Preview::Error::BrokenPipe));
    }

    TEST(CoreTransmission, HandlerReadSuccess)
    {
        // completion-handler 桥接：成功路径（ToEc 空错误分支）
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_read_data({std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}});
        std::byte buf[8]{};
        boost::system::error_code got_ec{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        std::size_t got_n = 0;

        t.async_read_some(buf, [&](boost::system::error_code ec, std::size_t n)
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
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        const std::byte buf[3]{};
        boost::system::error_code got_ec{static_cast<int>(boost::system::errc::invalid_argument), boost::system::generic_category()};
        std::size_t got_n = 0;

        t.async_write_some(buf, [&](boost::system::error_code ec, std::size_t n)
                            {
                                got_ec = ec;
                                got_n = n;
                            });
        ioc.run();

        EXPECT_FALSE(got_ec);
        EXPECT_EQ(got_n, 3);
        EXPECT_EQ(t.written_, 3);
    }

    TEST(CoreTransmission, HandlerReadErrorProtocol)
    {
        // completion-handler 桥接：Preview 协议错误 → boost 侧保留协议分类
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.SetReadError(
            static_cast<std::error_code>(Preview::make_error_code(Preview::Error::NeedMore)));
        std::byte buf[8]{};
        boost::system::error_code got_ec;
        std::size_t got_n = 999;

        t.async_read_some(buf, [&](boost::system::error_code ec, std::size_t n)
                           {
                               got_ec = ec;
                               got_n = n;
                           });
        ioc.run();

        EXPECT_EQ(got_n, 0);
        EXPECT_TRUE(got_ec);
        EXPECT_EQ(std::string_view(got_ec.category().name()), "preview.protocol");
        EXPECT_EQ(got_ec.value(), static_cast<int>(Preview::Error::NeedMore));
    }

    TEST(CoreTransmission, HandlerWriteErrorGeneric)
    {
        // completion-handler 桥接：非协议错误 → boost 侧归入 generic 分类
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.SetWriteError(std::make_error_code(std::errc::io_error));
        const std::byte buf[8]{};
        boost::system::error_code got_ec;
        std::size_t got_n = 999;

        t.async_write_some(buf, [&](boost::system::error_code ec, std::size_t n)
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
} // namespace
