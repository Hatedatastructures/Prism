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

#include <preview/Foundation/Utility/Coroutine/Registry.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Pad.hpp>
#include <preview/Protocols/Mux/Smux/Smux.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Preview::Mux;
    namespace Vmess = Preview::Vmess;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /**
     * @brief 协程内让出一次调度（驱动 detached 帧循环推进）
     */
    auto MakeTick(Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        Net::steady_timer Timer(Executor);
        Timer.expires_after(std::chrono::milliseconds(1));
        co_await Timer.async_wait(Net::use_awaitable);
    }

    /**
     * @brief 内存写入端 fake 传输（Preview::Transport 体系）
     * @details PadTransport 仅测试填充逻辑，写入直接落内存。
     */
    class FakeSink final : public Preview::Transmission
    {
    public:
        explicit FakeSink(Net::any_io_executor Executor) : Ex_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &Ec)
            -> Net::awaitable<std::size_t> override
        {
            Ec.clear();
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> Net::awaitable<std::size_t> override
        {
            Ec.clear();
            Written_.insert(Written_.end(), Buffer.begin(), Buffer.end());
            co_return Buffer.size();
        }

        void Close() override
        {
        }

        void Cancel() override
        {
        }

        std::vector<std::byte> Written_; ///< 捕获的写入字节

    private:
        Net::any_io_executor Ex_;
    };

    /**
     * @brief 验证 vmess ChunkStream::Decrypt 结束块边界
     * @details 结束块（长度 0）时 Open() 返回 Consumed = 18，修复前
     * Consumed - 18 - 16 无符号下溢为 SIZE_MAX，string::assign 越界读
     * 导致段错误。修复后明文为空串。
     */
    TEST(OwnershipAudit, VmessChunkStreamEndBlock)
    {
        Preview::Vmess::ChunkStream ChunkStream;
        std::array<std::uint8_t, 16> Key{};
        Key[0] = 0x11;
        std::array<std::uint8_t, 16> Iv{};
        Iv[0] = 0x22;
        ChunkStream.Init(Key, Iv);

        // 先加密一个数据块推进 Nonce，再加密结束块
        const std::array<std::uint8_t, 3> Payload{0xAA, 0xBB, 0xCC};
        std::string Wire1;
        ChunkStream.Encrypt(Payload, Wire1);
        std::string Wire2;
        ChunkStream.Encrypt({}, Wire2); // 结束块

        std::string Plain1;
        const auto Result1 = ChunkStream.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Wire1.data()),
                                          Wire1.size()),
            Plain1);
        EXPECT_FALSE(Result1.Ec);
        EXPECT_EQ(Plain1.size(), 3u);

        // 结束块：修复前此处越界读崩溃
        std::string Plain2("sentinel");
        const auto Result2 = ChunkStream.Decrypt(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Wire2.data()),
                                          Wire2.size()),
            Plain2);
        EXPECT_FALSE(Result2.Ec);
        EXPECT_TRUE(Plain2.empty());
        EXPECT_EQ(Result2.Consumed, 18u);
    }

    /**
     * @brief 验证 PadTransport 满区间填充不除零
     * @details 配置区间 0-65535 时，修复前 range = 65536 截断为 uint16 0，
     * raw % 0 除零 UB。修复后以 uint32 计算区间。
     */
    TEST(OwnershipAudit, PadMaxRangeNoDivZero)
    {
        Net::io_context IoContext;
        auto Sink = std::make_shared<FakeSink>(IoContext.get_executor());

        Preview::Transport::PadConfig Config;
        Config.PadTargets = "0-65535";
        Preview::Transport::PadTransport Pad(Sink, Config);

        std::array<std::byte, 1> Buffer{std::byte{0x42}};
        std::error_code Ec;
        std::size_t BytesWritten = 0;
        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                BytesWritten = co_await Pad.async_write_some(Buffer, Ec);
            },
            Net::detached);
        IoContext.run();

        EXPECT_FALSE(Ec);
        EXPECT_EQ(BytesWritten, 1u);
        EXPECT_GE(Sink->Written_.size(), 1u);
    }

    /**
     * @brief 验证 mux 会话底层断开后无循环引用泄漏
     * @details 对端关闭 → 帧循环读到 EOF 退出 → Teardown 清空流表。
     * 修复前 Streams_ 中残余 StreamHandle 与 Session 互相持有
     * shared_ptr，外部引用全部释放后对象仍存活（泄漏）。
     */
    TEST(OwnershipAudit, MuxSessionCycleLeak)
    {
        Net::io_context IoContext;
        std::exception_ptr Exception;
        std::weak_ptr<Preview::Mux::Session<Preview::Mux::Smux::Codec>> WeakSession;
        bool Connected = false;
        bool Opened = false;

        Net::co_spawn(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto [ClientMemoryValue, ServerMemoryValue] = Preview::MakeMemoryPair(IoContext.get_executor());
                auto ClientMemory = std::make_shared<Preview::MemoryStream>(std::move(ClientMemoryValue));
                auto ServerMemory = std::make_shared<Preview::MemoryStream>(std::move(ServerMemoryValue));

                Preview::Mux::Client<Preview::Mux::Smux::Codec> Client;
                Connected = Client.Connect(ClientMemory);
                auto Stream = co_await Client.OpenStream();
                Opened = Stream != nullptr;
                WeakSession = Client.Session();

                // 释放外部流句柄引用（仅流表持有）
                Stream.reset();

                // 对端关闭 → 客户端帧循环读到 EOF → Teardown
                ServerMemory->Close();
                co_await MakeTick(IoContext.get_executor());
            },
            [&](std::exception_ptr ErrorValue)
            {
                Exception = ErrorValue;
                IoContext.stop();
            });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }

        EXPECT_TRUE(Connected);
        EXPECT_TRUE(Opened);
        // 修复前：Session ↔ StreamHandle 循环引用 → WeakSession 未过期（泄漏）
        // 修复后：Teardown 清空流表 → Session 析构
        EXPECT_TRUE(WeakSession.expired());
    }

    /**
     * @brief 验证 TaskToken 在注册表析构后不访问悬垂 Owner_
     * @details Cancel() + 析构后，token 仍被 co_spawn completion
     * handler 持有；IoContext.run() 驱动协程完成后 completion 触发 token
     * 析构。修复前 Release() 访问已析构的 Owner_（UAF），修复后
     * Detach() 已将 Owner_ 置空。
     */
    TEST(OwnershipAudit, TaskRegistryDanglingOwner)
    {
        auto IoContext = std::make_unique<Net::io_context>();
        {
            Preview::Coroutine::TaskRegistry Registry(*IoContext);
            Registry.SpawnTracked(
                "dangling-owner", [IoContextPointer = IoContext.get()]() -> Net::awaitable<void>
                {
                    Net::steady_timer Timer(IoContextPointer->get_executor());
                    Timer.expires_after(std::chrono::milliseconds(20));
                    co_await Timer.async_wait(Net::use_awaitable);
                });
            Registry.Cancel();
        } // registry 析构；token 仍被 completion handler 持有

        // 驱动协程完成 → completion → token 析构 → 修复前访问悬垂 Owner_
        IoContext->run();
        IoContext.reset();
    }

} // namespace
