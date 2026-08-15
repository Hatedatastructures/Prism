/**
 * @file CoreTransmission.cpp
 * @brief tests/common/core/transmission.hpp 单元测试
 * @details 覆盖 psmtest::transmission 传输抽象接口：
 * 1. 内存 mock（可配置读/写行为）验证全部纯虚方法：async_read_some、
 *    async_write_some、close、cancel、executor
 * 2. 组合操作 async_read/async_write 的正常、分块、EOF、错误分支
 * 3. completion-handler 桥接路径（co_spawn + to_ec 错误映射三分支）
 * 4. 装饰器链：transport_type 委托、next_layer 默认、lowest_layer 转型
 * 5. release() 默认与覆写、transmission_like 概念
 */

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>

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
    namespace psmtest = ::psmtest;
    namespace net = boost::asio;

    /// 叶子传输：仅实现纯虚方法，不覆写任何默认实现（测基类默认分支）
    class leaf_transmission final : public psmtest::transmission
    {
    public:
        using psmtest::transmission::async_read_some;
        using psmtest::transmission::async_write_some;

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

        bool closed_{false};
        bool canceled_{false};

    private:
        net::any_io_executor ex_;
    };

    /// 装饰器 mock：可配置读/写行为，支持 inner 链与 release 所有权转移
    class mock_transmission : public psmtest::transmission
    {
    public:
        using psmtest::transmission::async_read_some;
        using psmtest::transmission::async_write_some;

        explicit mock_transmission(net::any_io_executor ex, psmtest::transmission *inner = nullptr)
            : ex_(std::move(ex)), inner_(inner)
        {
        }

        auto executor() const -> executor_type override
        {
            return ex_;
        }

        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
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
            const auto n = std::min(buffer.size(), std::min(read_buf_.size(), read_max_));
            std::memcpy(buffer.data(), read_buf_.data(), n);
            read_buf_.erase(read_buf_.begin(), read_buf_.begin() + static_cast<std::ptrdiff_t>(n));
            ec.clear();
            co_return n;
        }

        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
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
            const auto n = std::min(buffer.size(), write_max_);
            written_ += n;
            ec.clear();
            co_return n;
        }

        auto close() -> void override
        {
            closed_ = true;
        }

        auto cancel() -> void override
        {
            canceled_ = true;
        }

        auto next_layer() noexcept -> psmtest::transmission * override
        {
            return inner_;
        }

        auto next_layer() const noexcept -> const psmtest::transmission * override
        {
            return inner_;
        }

        auto release() -> std::shared_ptr<psmtest::transmission> override
        {
            auto r = std::move(released_);
            released_.reset();
            return r;
        }

        /// 配置：设置预读数据
        auto set_read_data(std::vector<std::byte> data) -> void
        {
            read_buf_ = std::move(data);
        }

        /// 配置：设置单次最大读取字节数（0 = 无限）
        auto set_read_max(std::size_t n) -> void
        {
            read_max_ = n;
        }

        /// 配置：设置读错误（覆盖 EOF 行为）
        auto set_read_error(std::error_code ec) -> void
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
        auto set_write_error(std::error_code ec) -> void
        {
            write_err_ = ec;
        }

        /// 配置：设置 release() 转移的底层传输
        auto set_release(std::shared_ptr<psmtest::transmission> t) -> void
        {
            released_ = std::move(t);
        }

        std::size_t written_{0};
        bool closed_{false};
        bool canceled_{false};

    private:
        net::any_io_executor ex_;
        psmtest::transmission *inner_{nullptr};
        std::vector<std::byte> read_buf_;
        std::optional<std::error_code> read_err_;
        std::size_t read_max_{SIZE_MAX};
        std::size_t write_max_{SIZE_MAX};
        bool write_zero_{false};
        std::optional<std::error_code> write_err_;
        std::shared_ptr<psmtest::transmission> released_;
    };

    /// UDP 装饰器：覆写 transport_type 返回 udp
    class udp_decorator final : public mock_transmission
    {
    public:
        using mock_transmission::mock_transmission;

        auto transport_type() const noexcept -> type override
        {
            return type::udp;
        }
    };

    /// 非 final 中间类：仅实现纯虚方法，不覆写默认实现（阻止 devirtualize 内联）
    class intermediate_transmission : public psmtest::transmission
    {
    public:
        explicit intermediate_transmission(net::any_io_executor ex) : ex_(std::move(ex))
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
        }

        auto cancel() -> void override
        {
        }

    private:
        net::any_io_executor ex_;
    };

    TEST(CoreTransmission, ConceptSatisfied)
    {
        // 基类与 mock 均满足 transmission_like 概念
        static_assert(psmtest::transmission_like<psmtest::transmission>);
        static_assert(psmtest::transmission_like<leaf_transmission>);
        static_assert(psmtest::transmission_like<mock_transmission>);
    }

    TEST(CoreTransmission, TransportTypeLeaf)
    {
        // 叶子：next_layer() 为空 → 默认返回 tcp
        net::io_context ioc;
        leaf_transmission t(ioc.get_executor());
        EXPECT_EQ(t.transport_type(), psmtest::transmission::type::tcp);
    }

    TEST(CoreTransmission, TransportTypeDelegate)
    {
        // 装饰器链：委托给底层传输获取真实类型
        net::io_context ioc;
        udp_decorator leaf(ioc.get_executor());
        mock_transmission mid(ioc.get_executor(), &leaf);
        mock_transmission top(ioc.get_executor(), &mid);

        EXPECT_EQ(leaf.transport_type(), psmtest::transmission::type::udp);
        EXPECT_EQ(mid.transport_type(), psmtest::transmission::type::udp);
        EXPECT_EQ(top.transport_type(), psmtest::transmission::type::udp);
    }

    TEST(CoreTransmission, GetExecutor)
    {
        net::io_context ioc;
        leaf_transmission t(ioc.get_executor());
        // get_executor() 兼容 Asio executor 概念，委托 executor()
        EXPECT_EQ(t.get_executor(), ioc.get_executor());
    }

    TEST(CoreTransmission, NextLayerDefault)
    {
        // 基类默认实现：叶子节点返回 nullptr（const 与非 const 版本）
        net::io_context ioc;
        leaf_transmission t(ioc.get_executor());
        EXPECT_EQ(t.next_layer(), nullptr);
        const auto &ct = t;
        EXPECT_EQ(ct.next_layer(), nullptr);
    }

    TEST(CoreTransmission, LowestLayerSuccess)
    {
        // 沿装饰器链导航到链底并转型成功
        net::io_context ioc;
        auto c = std::make_unique<mock_transmission>(ioc.get_executor());
        auto b = std::make_unique<mock_transmission>(ioc.get_executor(), c.get());
        auto a = std::make_unique<mock_transmission>(ioc.get_executor(), b.get());

        EXPECT_EQ(a->lowest_layer<mock_transmission>(), c.get());
        EXPECT_EQ(a->lowest_layer<psmtest::transmission>(), c.get());

        // const 版本
        const auto *ca = a.get();
        EXPECT_EQ(ca->lowest_layer<mock_transmission>(), c.get());
        EXPECT_EQ(ca->lowest_layer<psmtest::transmission>(), c.get());
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
        psmtest::transmission &ref = t;
        auto got = ref.release();
        EXPECT_EQ(got, nullptr);
    }

    TEST(CoreTransmission, ReleaseOverride)
    {
        // 覆写路径：转移底层传输所有权
        net::io_context ioc;
        auto inner = std::make_shared<mock_transmission>(ioc.get_executor());
        mock_transmission t(ioc.get_executor());
        t.set_release(inner);

        auto got = t.release();
        EXPECT_EQ(got.get(), inner.get());
        // 第二次调用：已转移，返回空
        auto again = t.release();
        EXPECT_EQ(again, nullptr);
    }

    TEST(CoreTransmission, CloseCancel)
    {
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.close();
        EXPECT_TRUE(t.closed_);
        t.cancel();
        EXPECT_TRUE(t.canceled_);
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
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_read(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 8);
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
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_read(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 8);
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
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_read(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 4);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncReadError)
    {
        // 读取错误：立即返回，不循环
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_read_error(std::make_error_code(std::errc::io_error));
        std::byte buf[8]{};
        std::error_code ec;
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_read(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 0);
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
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_write(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 8);
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
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_write(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 8);
        EXPECT_EQ(t.written_, 8);
        EXPECT_FALSE(ec);
    }

    TEST(CoreTransmission, AsyncWriteError)
    {
        // 写入错误：立即返回
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_write_error(std::make_error_code(std::errc::io_error));
        const std::byte buf[8]{};
        std::error_code ec;
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_write(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 0);
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
        std::size_t done = 0;

        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                done = co_await t.async_write(buf, ec);
            },
            net::detached);
        ioc.run();

        EXPECT_EQ(done, 0);
        EXPECT_TRUE(ec);
        EXPECT_EQ(ec, psmtest::make_error_code(psmtest::error::broken_pipe));
    }

    TEST(CoreTransmission, HandlerReadSuccess)
    {
        // completion-handler 桥接：成功路径（to_ec 空错误分支）
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
        // completion-handler 桥接：psmtest 协议错误 → boost 侧保留协议分类
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_read_error(
            static_cast<std::error_code>(psmtest::make_error_code(psmtest::error::need_more)));
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
        EXPECT_EQ(std::string_view(got_ec.category().name()), "psmtest.protocol");
        EXPECT_EQ(got_ec.value(), static_cast<int>(psmtest::error::need_more));
    }

    TEST(CoreTransmission, HandlerWriteErrorGeneric)
    {
        // completion-handler 桥接：非协议错误 → boost 侧归入 generic 分类
        net::io_context ioc;
        mock_transmission t(ioc.get_executor());
        t.set_write_error(std::make_error_code(std::errc::io_error));
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
