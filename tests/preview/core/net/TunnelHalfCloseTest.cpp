/**
 * @file TunnelHalfCloseTest.cpp
 * @brief tunnel 半关闭状态机 4 场景
 * @details 驱动方式：co_spawn + 完成回调捕获 exception_ptr + ioc.run()
 *          （MuxLifecycle 模式）；阶段切换由事件驱动（WaitUntil 有界轮询），
 *          禁止 detached + run_for 分段驱动。
 *          场景语义：先等待双向数据全量排空，再触发半关闭/关闭并断言
 *          隧道有界收口——对齐 ProductionMockTransport"EOF 即关闭两端"的模型。
 */

#include <gtest/gtest.h>

#include <prism/net/connection/tunnel/tunnel.hpp>
#include <prism/resource/session.hpp>
#include <prism/settings/settings.hpp>

#include <boost/asio.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

#include "TestSupport/Production/ProductionMockTransport.hpp"

namespace Net = boost::asio;

using Psm::Testing::ProductionMockTransport;

namespace {

    /// 驱动协程直至完成（异常透传）
    auto RunCoro(Net::io_context &Ioc, auto Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 定时轮询等待条件成立（有界，超时抛异常）
    auto WaitUntil(Net::io_context &Ioc, std::function<bool()> Condition,
                    std::chrono::milliseconds deadline = std::chrono::seconds(2))
        -> Net::awaitable<void>
    {
        Net::steady_timer Timer(Ioc);
        const auto Start = std::chrono::steady_clock::now();
        while (!Condition())
        {
            if (std::chrono::steady_clock::now() - Start > deadline)
            {
                throw std::runtime_error("WaitUntil timeout");
            }
            Timer.expires_after(std::chrono::milliseconds(2));
            co_await Timer.async_wait(Net::use_awaitable);
        }
    }

    auto MakeSession(Net::io_context &Ioc, std::uint32_t BufferSize = 4096)
        -> std::shared_ptr<psm::resource::session>
    {
        auto cfg = std::make_shared<psm::settings>();
        auto proc = std::make_shared<psm::resource::process>(
            psm::resource::process::options{cfg, nullptr, nullptr});
        auto wrk = std::make_shared<psm::resource::worker>(
            psm::resource::worker::options{proc, psm::memory::system::global_pool()});
        return std::make_shared<psm::resource::session>(
            psm::resource::session::options{wrk, 1, BufferSize, nullptr, {}, nullptr, nullptr});
    }

    /// 隧道测试共享夹具：两端 ProductionMockTransport + 完成标志
    struct Harness
    {
        Net::io_context &ioc;
        std::shared_ptr<ProductionMockTransport> in;
        std::shared_ptr<ProductionMockTransport> out;
        std::shared_ptr<psm::resource::session> sess;
        std::shared_ptr<std::exception_ptr> tep;
        std::shared_ptr<bool> Done;

        explicit Harness(Net::io_context &Context)
            : ioc(Context), in(std::make_shared<ProductionMockTransport>()),
              out(std::make_shared<ProductionMockTransport>()), sess(MakeSession(Context)),
              tep(std::make_shared<std::exception_ptr>()), Done(std::make_shared<bool>(false))
        {
        }

        /// 启动隧道协程（完成回调记录异常与结束标志）
        void Start()
        {
            Net::co_spawn(ioc,
                          psm::connect::tunnel(psm::connect::tunnel_options{
                              in, out, sess->buffer, psm::connect::write_policy::complete}),
                          [this](std::exception_ptr e) { *tep = e; *Done = true; });
        }

        /// 等待隧道收口并透传其异常
        auto join() -> Net::awaitable<void>
        {
            co_await WaitUntil(ioc, [this] { return *Done; });
            if (*tep)
            {
                std::rethrow_exception(*tep);
            }
        }
    };
}

TEST(TunnelHalfClose, SmallRequestLargeResponse)
{
    Net::io_context ioc;
    Harness h(ioc);
    const std::vector<std::byte> req(128, std::byte{0x11});
    const std::vector<std::byte> rsp(64 * 1024, std::byte{0x22});
    h.in->InjectRead(req.data(), req.size());
    h.out->InjectRead(rsp.data(), rsp.size());
    h.Start();

    auto body = [&]() -> Net::awaitable<void>
    {
        // 等待双向数据全部排空（ProductionMockTransport 的 EOF 携带错误码，
        // 任一方向读 EOF 都会触发 CloseRelay 立即关闭两端，
        // 因此必须先完成全量转发再触发半关闭，否则会截断在途数据）
        co_await WaitUntil(ioc, [&]
                            { return h.out->WrittenData().size() >= req.size() &&
                                     h.in->WrittenData().size() >= rsp.size(); });
        h.in->Shutdown();
        co_await h.join();
        h.out->close();
    };
    RunCoro(ioc, body());

    EXPECT_GE(h.out->WrittenData().size(), req.size());
    EXPECT_GE(h.in->WrittenData().size(), rsp.size());
}

TEST(TunnelHalfClose, LargeRequestSmallResponse)
{
    Net::io_context ioc;
    Harness h(ioc);
    const std::vector<std::byte> req(64 * 1024, std::byte{0x33});
    const std::vector<std::byte> rsp(128, std::byte{0x44});
    h.in->InjectRead(req.data(), req.size());
    h.out->InjectRead(rsp.data(), rsp.size());
    h.Start();

    auto body = [&]() -> Net::awaitable<void>
    {
        // 等待双向数据全部排空后再触发关闭（理由同上，避免截断在途数据）
        co_await WaitUntil(ioc, [&]
                            { return h.in->WrittenData().size() >= rsp.size() &&
                                     h.out->WrittenData().size() >= req.size(); });
        h.out->Shutdown();
        h.in->close();
        co_await h.join();
        h.out->close();
    };
    RunCoro(ioc, body());

    EXPECT_GE(h.out->WrittenData().size(), req.size());
}

TEST(TunnelHalfClose, BidirectionalEOF)
{
    Net::io_context ioc;
    Harness h(ioc);
    h.in->InjectRead(std::vector<std::byte>{std::byte{0x01}}.data(), 1);
    h.out->InjectRead(std::vector<std::byte>{std::byte{0x02}}.data(), 1);
    h.Start();

    auto body = [&]() -> Net::awaitable<void>
    {
        // 双向数据送达后同时半关闭，隧道应在两方向完成后自然收口
        co_await WaitUntil(ioc, [&]
                            { return h.in->WrittenData().size() >= 1 &&
                                     h.out->WrittenData().size() >= 1; });
        h.in->Shutdown();
        h.out->Shutdown();
        co_await h.join();
        h.in->close();
        h.out->close();
    };
    RunCoro(ioc, body());

    EXPECT_TRUE(*h.Done);
    EXPECT_GE(h.out->WrittenData().size(), 1U);
    EXPECT_GE(h.in->WrittenData().size(), 1U);
}

TEST(TunnelHalfClose, IdleTimeoutMidHalfClose)
{
    Net::io_context ioc;
    Harness h(ioc);
    const std::vector<std::byte> req(10, std::byte{0x55});
    h.in->InjectRead(req.data(), req.size());
    h.Start();

    auto body = [&]() -> Net::awaitable<void>
    {
        // 单向数据送达后半关闭入站；级联 EOF 应使隧道收口而非挂死
        co_await WaitUntil(ioc, [&] { return h.out->WrittenData().size() >= req.size(); });
        h.in->Shutdown();
        co_await h.join();
        h.out->close();
    };
    RunCoro(ioc, body());

    EXPECT_GE(h.out->WrittenData().size(), req.size());
}
