/**
 * @file OwnershipAudit.cpp
 * @brief tests/common 资源所有权与内存安全审计复现测试
 * @details 对审计发现的缺陷逐一复现（修复前崩溃/泄漏，修复后通过）：
 * - VmessChunkStreamEndBlock：vmess ChunkStream::Decrypt 处理结束块时
 *   Consumed(18) - 34 无符号下溢 → string::assign 越界读
 * - PadMaxRangeNoDivZero：PadTransport RngNextU16 区间溢出 → 除零 UB
 * - MuxSessionCycleLeak：底层断开后 Session ↔ StreamHandle 循环引用泄漏
 * - TaskRegistryDanglingOwner：registry 析构后 token 访问悬垂 Owner_
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <common/Core/Coroutine/Registry.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transport/Pad.hpp>
#include <common/Protocols/Mux/Smux/Smux.hpp>
#include <common/Protocols/Vmess/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;

    /**
     * @brief 协程内让出一次调度（驱动 detached 帧循环推进）
     */
    auto make_tick(net::any_io_executor ex) -> net::awaitable<void>
    {
        net::steady_timer timer(ex);
        timer.expires_after(std::chrono::milliseconds(1));
        co_await timer.async_wait(net::use_awaitable);
    }

    /**
     * @brief 内存写入端 fake 传输（Preview::Transport 体系）
     * @details PadTransport 仅测试填充逻辑，写入直接落内存。
     */
    class fake_sink final : public Preview::Transmission
    {
    public:
        explicit fake_sink(net::any_io_executor ex) : Ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            Ec.clear();
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buf, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            Ec.clear();
            written_.insert(written_.end(), buf.begin(), buf.end());
            co_return buf.size();
        }

        void Close() override
        {
        }

        void Cancel() override
        {
        }

        std::vector<std::byte> written_; ///< 捕获的写入字节

    private:
        net::any_io_executor Ex_;
    };

    /**
     * @brief 验证 vmess ChunkStream::Decrypt 结束块边界
     * @details 结束块（长度 0）时 Open() 返回 Consumed = 18，修复前
     * Consumed - 18 - 16 无符号下溢为 SIZE_MAX，string::assign 越界读
     * 导致段错误。修复后明文为空串。
     */
    TEST(OwnershipAudit, VmessChunkStreamEndBlock)
    {
        Preview::Vmess::ChunkStream cs;
        std::array<std::uint8_t, 16> key{};
        key[0] = 0x11;
        std::array<std::uint8_t, 16> iv{};
        iv[0] = 0x22;
        cs.Init(key, iv);

        // 先加密一个数据块推进 Nonce，再加密结束块
        const std::array<std::uint8_t, 3> payload{0xAA, 0xBB, 0xCC};
        std::string wire1;
        cs.Encrypt(payload, wire1);
        std::string wire2;
        cs.Encrypt({}, wire2); // 结束块

        std::string plain1;
        const auto r1 = cs.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(wire1.data()),
                                          wire1.size()),
            plain1);
        EXPECT_FALSE(r1.Ec);
        EXPECT_EQ(plain1.size(), 3u);

        // 结束块：修复前此处越界读崩溃
        std::string plain2("sentinel");
        const auto r2 = cs.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(wire2.data()),
                                          wire2.size()),
            plain2);
        EXPECT_FALSE(r2.Ec);
        EXPECT_TRUE(plain2.empty());
        EXPECT_EQ(r2.Consumed, 18u);
    }

    /**
     * @brief 验证 PadTransport 满区间填充不除零
     * @details 配置区间 0-65535 时，修复前 range = 65536 截断为 uint16 0，
     * raw % 0 除零 UB。修复后以 uint32 计算区间。
     */
    TEST(OwnershipAudit, PadMaxRangeNoDivZero)
    {
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());

        Preview::Transport::PadConfig cfg;
        cfg.PadTargets = "0-65535";
        Preview::Transport::PadTransport pad(sink, cfg);

        std::array<std::byte, 1> buf{std::byte{0x42}};
        std::error_code Ec;
        std::size_t n = 0;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                n = co_await pad.async_write_some(buf, Ec);
            },
            net::detached);
        ioc.run();

        EXPECT_FALSE(Ec);
        EXPECT_EQ(n, 1u);
        EXPECT_GE(sink->written_.size(), 1u);
    }

    /**
     * @brief 验证 mux 会话底层断开后无循环引用泄漏
     * @details 对端关闭 → 帧循环读到 EOF 退出 → Teardown 清空流表。
     * 修复前 Streams_ 中残余 StreamHandle 与 Session 互相持有
     * shared_ptr，外部引用全部释放后对象仍存活（泄漏）。
     */
    TEST(OwnershipAudit, MuxSessionCycleLeak)
    {
        net::io_context ioc;
        std::exception_ptr ep;
        std::weak_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> weak;
        bool connected = false;
        bool opened = false;

        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                auto [a, b] = Preview::MakeMemoryPair(ioc.get_executor());
                auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
                auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

                Preview::Mux::Client<Preview::Mux::Smux::Codec> Client;
                connected = Client.Connect(sa);
                auto Stream = co_await Client.OpenStream();
                opened = Stream != nullptr;
                weak = Client.Session();

                // 释放外部流句柄引用（仅流表持有）
                Stream.reset();

                // 对端关闭 → 客户端帧循环读到 EOF → Teardown
                sb->Close();
                co_await make_tick(ioc.get_executor());
            },
            [&](std::exception_ptr e)
            {
                ep = e;
                ioc.stop();
            });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }

        EXPECT_TRUE(connected);
        EXPECT_TRUE(opened);
        // 修复前：Session ↔ StreamHandle 循环引用 → weak 未过期（泄漏）
        // 修复后：Teardown 清空流表 → Session 析构
        EXPECT_TRUE(weak.expired());
    }

    /**
     * @brief 验证 TaskToken 在注册表析构后不访问悬垂 Owner_
     * @details CancelAndWait + 析构后，token 仍被 co_spawn completion
     * handler 持有；ioc.run() 驱动协程完成后 completion 触发 token
     * 析构。修复前 Release() 访问已析构的 Owner_（UAF），修复后
     * Detach() 已将 Owner_ 置空。
     */
    TEST(OwnershipAudit, TaskRegistryDanglingOwner)
    {
        auto ioc = std::make_unique<net::io_context>();
        {
            Preview::Coroutine::TaskRegistry reg(*ioc);
            reg.SpawnTracked(
                "dangling-owner", [ioc_ptr = ioc.get()]() -> net::awaitable<void>
                {
                    net::steady_timer timer(ioc_ptr->get_executor());
                    timer.expires_after(std::chrono::milliseconds(20));
                    co_await timer.async_wait(net::use_awaitable);
                });
            (void)reg.CancelAndWait();
        } // registry 析构；token 仍被 completion handler 持有

        // 驱动协程完成 → completion → token 析构 → 修复前访问悬垂 Owner_
        ioc->run();
        ioc.reset();
    }

} // namespace
