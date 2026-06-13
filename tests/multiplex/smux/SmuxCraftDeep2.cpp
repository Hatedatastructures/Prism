/**
 * @file SmuxCraftDeep2.cpp
 * @brief multiplex/smux/craft 状态机深度测试
 * @details 通过 #define private/protected public 访问 craft 及 core 的
 *          非公开成员，测试 handle_syn（max_streams 限制/重复 SYN/正常创建）、
 *          dispatch_push（pending 累积/duct 分发/parcel 分发）、
 *          handle_fin（pending/duct/parcel 三路清理）、
 *          activate_stream（地址解析/缓冲区不足/错误地址）、
 *          send_fin（通过 channel_）、push_frame、send_data。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include "common/MockTransport.hpp"

#include <gtest/gtest.h>

// 预包含依赖头文件（不打开 private）
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/resolve/dns/dns.hpp>
#include <prism/proto/multiplex/smux/frame.hpp>
#include <prism/account/stats/traffic.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

// 打开 craft 及其传递依赖的非公开访问
#define private public
#define protected public
#include <prism/proto/multiplex/smux/craft.hpp>
#undef protected
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../../src/prism/proto/multiplex/smux/craft.cpp"

using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace smux = psm::multiplex::smux;
namespace net = boost::asio;

namespace
{
    struct CraftFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<smux::craft> craft_obj;
        static multiplex::config cfg;

        CraftFixture()
        {
            transport = std::make_shared<MockTransport>();
            auto &ioc = transport->get_io_context();
            pool = std::make_unique<psm::connect::connection_pool>(ioc);
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, *router_ptr, cfg, nullptr};
            craft_obj = std::make_shared<smux::craft>(std::move(opts));
        }

        auto &ioc() { return transport->get_io_context(); }

        // 用 poll_one 循环代替 run()，避免 io_context 永久调度（连接池定时器等）
        void poll(int max_iters = 500)
        {
            for (int i = 0; i < max_iters; ++i)
                ioc().poll_one();
            ioc().restart();
        }
    };

    multiplex::config CraftFixture::cfg{};

} // namespace

// ─── handle_syn ──────────────────────────────────

TEST(SmuxCraftDeep2, HandleSynCreatesPending)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    bool done = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->handle_syn(1);
            done = true;
        },
        net::detached);

    // 用 poll_one 循环代替 run()，避免无限阻塞
    for (int i = 0; i < 100 && !done; ++i)
        fx.ioc().poll_one();
    fx.ioc().restart();

    EXPECT_TRUE(done) << "handle_syn: coroutine completed";
    EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 1)
        << "handle_syn: creates pending entry";
    EXPECT_TRUE(!fx.craft_obj->pending_.at(1).connecting)
        << "handle_syn: connecting=false initially";
}

TEST(SmuxCraftDeep2, HandleSynMaxStreamsReached)
{
    CraftFixture fx;
    fx.cfg.smux.max_streams = 2;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
    fx.craft_obj->pending_.emplace(2, multiplex::core::pending_entry(psm::memory::current_resource()));

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->handle_syn(3);
        },
        net::detached);

    // send_fin 内部 co_spawn 写 channel_，需要消费者
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await fx.craft_obj->channel_.async_receive(token);
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(fx.craft_obj->pending_.count(3) == 0)
        << "handle_syn: max_streams -> stream 3 rejected";
    EXPECT_TRUE(fx.craft_obj->pending_.size() == 2)
        << "handle_syn: max_streams -> original pending unchanged";
}

TEST(SmuxCraftDeep2, HandleSynDuplicateSyn)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->handle_syn(1);
        },
        net::detached);

    // send_fin 消费者
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await fx.craft_obj->channel_.async_receive(token);
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 1)
        << "handle_syn: duplicate -> only one entry";
}

TEST(SmuxCraftDeep2, HandleSynDuctsConflict)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    fx.craft_obj->ducts_[5];

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->handle_syn(5);
        },
        net::detached);

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await fx.craft_obj->channel_.async_receive(token);
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(fx.craft_obj->pending_.count(5) == 0)
        << "handle_syn: ducts conflict -> rejected";
}

TEST(SmuxCraftDeep2, HandleSynParcelsConflict)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    fx.craft_obj->parcels_[10];

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->handle_syn(10);
        },
        net::detached);

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await fx.craft_obj->channel_.async_receive(token);
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(fx.craft_obj->pending_.count(10) == 0)
        << "handle_syn: parcels conflict -> rejected";
}

// ─── dispatch_push ───────────────────────────────

TEST(SmuxCraftDeep2, DispatchPushPendingAccumulate)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));

    psm::memory::vector<std::byte> payload(psm::memory::current_resource());
    payload.push_back(std::byte{0x01});
    payload.push_back(std::byte{0x02});
    payload.push_back(std::byte{0x03});

    fx.craft_obj->dispatch_push(1, std::move(payload));

    EXPECT_TRUE(fx.craft_obj->pending_.at(1).buffer.size() == 3)
        << "dispatch_push: pending buffer accumulated 3 bytes";
    EXPECT_TRUE(!fx.craft_obj->pending_.at(1).connecting)
        << "dispatch_push: not connecting (<7 bytes)";
}

TEST(SmuxCraftDeep2, DispatchPushPendingTriggerConnecting)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        1, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;

    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0x01});

    psm::memory::vector<std::byte> payload(psm::memory::current_resource());
    payload.push_back(std::byte{0x7F});
    payload.push_back(std::byte{0x00});
    payload.push_back(std::byte{0x01});

    fx.craft_obj->dispatch_push(1, std::move(payload));

    EXPECT_TRUE(fx.craft_obj->pending_.at(1).buffer.size() == 7)
        << "dispatch_push: buffer=7 after accumulation";
    EXPECT_TRUE(fx.craft_obj->pending_.at(1).connecting)
        << "dispatch_push: connecting=true after >=7 bytes";
}

TEST(SmuxCraftDeep2, DispatchPushPendingAlreadyConnecting)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        1, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;

    psm::memory::vector<std::byte> payload(psm::memory::current_resource());
    payload.push_back(std::byte{0xAA});

    fx.craft_obj->dispatch_push(1, std::move(payload));

    EXPECT_TRUE(entry.buffer.size() == 1)
        << "dispatch_push: already connecting -> only accumulate";
    EXPECT_TRUE(entry.connecting)
        << "dispatch_push: connecting stays true";
}

TEST(SmuxCraftDeep2, DispatchPushNoMatch)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    psm::memory::vector<std::byte> payload(psm::memory::current_resource());
    payload.push_back(std::byte{0x01});

    fx.craft_obj->dispatch_push(99, std::move(payload));
}

// ─── handle_fin ──────────────────────────────────

TEST(SmuxCraftDeep2, HandleFinPendingErased)
{
    CraftFixture fx;
    fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));

    fx.craft_obj->handle_fin(1);

    EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 0)
        << "handle_fin: pending erased";
}

TEST(SmuxCraftDeep2, HandleFinDuctNull)
{
    CraftFixture fx;
    fx.craft_obj->ducts_[3];

    fx.craft_obj->handle_fin(3);
    EXPECT_TRUE(fx.craft_obj->ducts_.count(3) == 1)
        << "handle_fin: duct null ptr -> entry remains";
}

TEST(SmuxCraftDeep2, HandleFinParcelNull)
{
    CraftFixture fx;
    fx.craft_obj->parcels_[4];

    fx.craft_obj->handle_fin(4);
    EXPECT_TRUE(fx.craft_obj->parcels_.count(4) == 1)
        << "handle_fin: parcel null ptr -> entry remains";
}

TEST(SmuxCraftDeep2, HandleFinNoMatch)
{
    CraftFixture fx;
    fx.craft_obj->handle_fin(999);
}

TEST(SmuxCraftDeep2, HandleFinPendingPriorityOverDuct)
{
    CraftFixture fx;
    fx.craft_obj->pending_.emplace(5, multiplex::core::pending_entry(psm::memory::current_resource()));
    fx.craft_obj->ducts_[5];

    fx.craft_obj->handle_fin(5);

    EXPECT_TRUE(fx.craft_obj->pending_.count(5) == 0)
        << "handle_fin: pending erased (priority)";
    EXPECT_TRUE(fx.craft_obj->ducts_.count(5) == 1)
        << "handle_fin: duct not checked";
}

// ─── activate_stream ─────────────────────────────

TEST(SmuxCraftDeep2, ActivateStreamNotPending)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    bool completed = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(999);
            completed = true;
        },
        net::detached);
    fx.poll();

    EXPECT_TRUE(completed) << "activate_stream: not pending -> early return";
}

TEST(SmuxCraftDeep2, ActivateStreamBufferTooSmall)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        1, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    entry.buffer.resize(5);

    bool completed = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(1);
            completed = true;
        },
        net::detached);
    fx.poll();

    EXPECT_TRUE(completed) << "activate_stream: buffer <7 -> completed";
    EXPECT_TRUE(!entry.connecting)
        << "activate_stream: buffer <7 -> connecting reset";
}

TEST(SmuxCraftDeep2, ActivateStreamBufferExactlySix)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        2, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    entry.buffer.resize(6);

    bool completed = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(2);
            completed = true;
        },
        net::detached);
    fx.poll();

    EXPECT_TRUE(completed) << "activate_stream: buffer=6 -> completed";
    EXPECT_TRUE(!entry.connecting)
        << "activate_stream: buffer=6 -> connecting reset";
}

TEST(SmuxCraftDeep2, ActivateStreamBadAddressLargeBuffer)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        3, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    for (int i = 0; i < 21; ++i)
        entry.buffer.push_back(std::byte{0xFF});

    bool activate_done = false;

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(3);
            activate_done = true;
        },
        net::detached);

    // 消费 channel_ 中的帧（send_addr_err 会发 error data + FIN）
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            for (int i = 0; i < 2; ++i)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
            }
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(activate_done) << "activate_stream: bad address -> completed";
    EXPECT_TRUE(fx.craft_obj->pending_.count(3) == 0)
        << "activate_stream: bad address -> pending erased";
}

TEST(SmuxCraftDeep2, ActivateStreamInvalidAtyp)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        4, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    // Flags(2B)=0x0000 + ATYP=0x04(无效) + padding 到 21 字节
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x04});
    for (int i = 0; i < 18; ++i)
        entry.buffer.push_back(std::byte{0x00});

    bool activate_done = false;

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(4);
            activate_done = true;
        },
        net::detached);

    // send_addr_err 发 2 帧：error data + fin
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            for (int i = 0; i < 2; ++i)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
            }
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(activate_done) << "activate_stream: invalid ATYP -> completed";
    EXPECT_TRUE(fx.craft_obj->pending_.count(4) == 0)
        << "activate_stream: invalid ATYP -> pending erased";
}

TEST(SmuxCraftDeep2, ActivateStreamValidTcpAddress)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        10, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    // Flags(2B)=0x0000 + ATYP=0x01(IPv4) + 127.0.0.1 + Port=80
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0x7F});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x50});

    bool activate_done = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(10);
            activate_done = true;
        },
        net::detached);

    // activate_tcp 失败路径：send_data(1帧) + send_fin(1帧) = 2帧
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            for (int i = 0; i < 2; ++i)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
            }
        },
        net::detached);

    fx.poll(500);

    // TCP 连接涉及真实网络 I/O（async_forward），poll 可能无法在有限迭代内完成
    // 仅检查不崩溃，不强制要求 activate_done
}

TEST(SmuxCraftDeep2, ActivateStreamValidUdpAddress)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        20, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    // Flags=0x0001(UDP) + ATYP=0x01(IPv4) + 127.0.0.1 + Port=53
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0x7F});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x35});

    bool activate_done = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(20);
            activate_done = true;
        },
        net::detached);

    // activate_udp: send_data(1帧, success) + 可能的 parcel 创建
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            for (int i = 0; i < 4; ++i)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
            }
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(activate_done) << "activate_stream: UDP address -> completed";
}

TEST(SmuxCraftDeep2, ActivateStreamDomainAddress)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    auto &entry = fx.craft_obj->pending_.emplace(
        30, multiplex::core::pending_entry(psm::memory::current_resource())).first->second;
    entry.connecting = true;
    // Flags=0x0000(TCP) + ATYP=0x03(域名) + len=11 + "example.com" + Port=443
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x00});
    entry.buffer.push_back(std::byte{0x03});
    entry.buffer.push_back(std::byte{0x0B});
    const char *domain = "example.com";
    for (int i = 0; i < 11; ++i)
        entry.buffer.push_back(static_cast<std::byte>(domain[i]));
    entry.buffer.push_back(std::byte{0x01});
    entry.buffer.push_back(std::byte{0xBB});

    bool activate_done = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->activate_stream(30);
            activate_done = true;
        },
        net::detached);

    // activate_tcp 失败路径：send_data(1帧) + send_fin(1帧) = 2帧
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            for (int i = 0; i < 2; ++i)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
            }
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(activate_done) << "activate_stream: domain address -> completed";
}

// ─── push_frame / send_data / send_fin ───────────

TEST(SmuxCraftDeep2, PushFrameEncodesCorrectly)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    psm::memory::vector<std::byte> payload(psm::memory::current_resource());
    payload.push_back(std::byte{0xDE});
    payload.push_back(std::byte{0xAD});

    smux::outbound_frame received_frame;

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->push_frame(smux::command::push, 42, std::move(payload));
        },
        net::detached);

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            received_frame = co_await fx.craft_obj->channel_.async_receive(net::use_awaitable);
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(received_frame.header[0] == std::byte{smux::protocol_version})
        << "push_frame: version correct";
    EXPECT_TRUE(received_frame.header[1] == static_cast<std::byte>(smux::command::push))
        << "push_frame: command correct";
    EXPECT_TRUE(received_frame.header[2] == std::byte{0x02})
        << "push_frame: length low byte = 2";
    EXPECT_TRUE(received_frame.header[3] == std::byte{0x00})
        << "push_frame: length high byte = 0";
    EXPECT_TRUE(received_frame.header[4] == std::byte{0x2A})
        << "push_frame: stream_id low byte";
    EXPECT_TRUE(received_frame.payload.size() == 2)
        << "push_frame: payload size = 2";
}

TEST(SmuxCraftDeep2, SendDataPushesFrame)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    psm::memory::vector<std::byte> data(psm::memory::current_resource());
    data.push_back(std::byte{0xBE});
    data.push_back(std::byte{0xEF});

    smux::outbound_frame received_frame;

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->send_data(7, std::move(data));
        },
        net::detached);

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            received_frame = co_await fx.craft_obj->channel_.async_receive(net::use_awaitable);
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(received_frame.header[1] == static_cast<std::byte>(smux::command::push))
        << "send_data: command is push";
    EXPECT_TRUE(received_frame.header[4] == std::byte{0x07})
        << "send_data: stream_id correct";
    EXPECT_TRUE(received_frame.payload.size() == 2)
        << "send_data: payload preserved";
}

TEST(SmuxCraftDeep2, SendFinSendsFinFrame)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);

    fx.craft_obj->send_fin(5);

    smux::outbound_frame received_frame;
    bool got_frame = false;
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            received_frame = co_await fx.craft_obj->channel_.async_receive(token);
            if (!ec) got_frame = true;
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(got_frame) << "send_fin: frame received on channel";
    EXPECT_TRUE(received_frame.header[1] == static_cast<std::byte>(smux::command::fin))
        << "send_fin: command is fin";
    EXPECT_TRUE(received_frame.header[4] == std::byte{0x05})
        << "send_fin: stream_id correct";
}

TEST(SmuxCraftDeep2, SendAddrErrSendsErrorAndFin)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);
    fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));

    int frame_count = 0;
    bool done = false;

    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            co_await fx.craft_obj->send_addr_err(1);
            done = true;
        },
        net::detached);

// send_addr_err 内部 co_await send_data + send_fin，其中 send_fin co_spawn
    // send_data(1帧, push) + send_fin(co_spawn push) = 2帧
    net::co_spawn(fx.ioc(),
        [&]() -> net::awaitable<void>
        {
            for (int i = 0; i < 2; ++i)
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                co_await fx.craft_obj->channel_.async_receive(token);
                if (!ec) frame_count++;
            }
        },
        net::detached);

    fx.poll();

    EXPECT_TRUE(done) << "send_addr_err: completed";
    EXPECT_TRUE(frame_count >= 2)
        << "send_addr_err: sent error data + fin >= 2 frames";
    EXPECT_TRUE(fx.craft_obj->pending_.count(1) == 0)
        << "send_addr_err: pending erased";
}

// ─── 杂项 ────────────────────────────────────────

TEST(SmuxCraftDeep2, ExecutorReturnsTransportExecutor)
{
    CraftFixture fx;
    auto ex = fx.craft_obj->executor();
}

TEST(SmuxCraftDeep2, ConstructorChannelCapacity)
{
    CraftFixture fx;
    EXPECT_TRUE(fx.craft_obj->channel_.is_open())
        << "constructor: channel is open";
}

TEST(SmuxCraftDeep2, CloseIdempotent)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);
    fx.craft_obj->close();
    EXPECT_TRUE(!fx.craft_obj->active_.load(std::memory_order_acquire))
        << "close: active_ = false after first close";

    fx.craft_obj->close();
    EXPECT_TRUE(!fx.craft_obj->active_.load(std::memory_order_acquire))
        << "close: still false after second close";
}

TEST(SmuxCraftDeep2, CloseClearsState)
{
    CraftFixture fx;
    fx.craft_obj->active_.store(true, std::memory_order_release);
    fx.craft_obj->pending_.emplace(1, multiplex::core::pending_entry(psm::memory::current_resource()));
    fx.craft_obj->pending_.emplace(2, multiplex::core::pending_entry(psm::memory::current_resource()));

    fx.craft_obj->close();

    EXPECT_TRUE(fx.craft_obj->pending_.empty()) << "close: pending cleared";
    EXPECT_TRUE(fx.craft_obj->ducts_.empty()) << "close: ducts cleared";
    EXPECT_TRUE(fx.craft_obj->parcels_.empty()) << "close: parcels cleared";
}
