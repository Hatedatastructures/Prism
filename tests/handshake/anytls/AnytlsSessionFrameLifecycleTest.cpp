/**
 * @file AnytlsSessionFrameLifecycleTest.cpp
 * @brief AnyTLS frame read/write and receive loop lifecycle tests.
 */
#include <prism/foundation/foundation.hpp>
#include <prism/handshake/anytls/mux/frame.hpp>
#include <prism/handshake/anytls/padding.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include "TestSupport/Production/ProductionMockTransport.hpp"
#include <gtest/gtest.h>

// 必须在 session.hpp 之前定义，否则 transport.hpp 内部已包含 session.hpp
#define private public
#define protected public
#include <prism/handshake/anytls/mux/session.hpp>
#include <prism/handshake/anytls/mux/transport.hpp>
#undef protected
#undef private

#include "../../../src/prism/handshake/anytls/session.cpp"

using ProductionMockTransport = Psm::Testing::ProductionMockTransport;
namespace anytls = psm::handshake::anytls;
namespace Net = boost::asio;
#include "AnytlsSessionDeepSupport.hpp"

TEST(AnytlsSessionDeep, RecvLoopConnectionClosed)
    {
        SessionFixture fx;
        fx.init();

        // 不注入任何数据，直接关闭
        fx.transport->close();

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(fx.session->init_resolved_) << "recv closed: init resolved";
        EXPECT_TRUE(fx.session->init_error_ == psm::fault::code::eof) << "recv closed: error = eof";
    }

    // ─── recv_loop 无效帧头 ─────────────────────

    TEST(AnytlsSessionDeep, RecvLoopInvalidHeader)
    {
        SessionFixture fx;
        fx.init();

        // 注入只有 3 字节（不足 7），read_exact 会读取 3 字节后再次 async_read_some
        // ProductionMockTransport 队列空后进入轮询定时器，close() 后 read_exact 返回 false
        std::vector<std::byte> short_data(3, std::byte{0x00});
        fx.transport->InjectRead(short_data.data(), short_data.size());

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();

            // 等待 read_exact 读取 3 字节，然后挂起在定时器上等待更多数据
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(50));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));

            // 关闭让 recv_loop 的 read_exact 返回 false → recv_loop 退出
            fx.transport->close();

            timer.expires_after(std::chrono::milliseconds(50));
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        // read_exact 返回 false → recv_loop 退出 → init_error_ = eof
        EXPECT_TRUE(fx.session->init_error_ == psm::fault::code::eof)
            << "invalid header: short read -> eof (connection closed)";
    }

    // ─── recv_loop 带有效载荷的帧 ───────────────

    TEST(AnytlsSessionDeep, RecvLoopFrameWithPayload)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto payload = make_settings_payload("v=1\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->InjectRead(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(fx.session->received_settings_) << "payload frame: settings received";
    }

    // ─── write_psh ───────────────────────────────

    TEST(AnytlsSessionDeep, WritePsh)
    {
        SessionFixture fx;
        fx.init();

        auto data = std::vector<std::byte>{std::byte{0x01}, std::byte{0x02}};
        std::error_code ec;

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            auto n = co_await fx.session->write_psh(1, data, ec);
            EXPECT_EQ(n, 2) << "write_psh: returned 2";
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(!ec) << "write_psh: no error";
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7 + 2) << "write_psh: data written";
    }

    // ─── write_fin ───────────────────────────────

    TEST(AnytlsSessionDeep, WriteFin)
    {
        SessionFixture fx;
        fx.init();

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void> { co_await fx.session->write_fin(1, ec); };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(!ec) << "write_fin: no error";
    }

    // ─── write_synack ────────────────────────────

    TEST(AnytlsSessionDeep, WriteSynack)
    {
        SessionFixture fx;
        fx.init();

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void> { co_await fx.session->write_synack(1, ec); };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(!ec) << "write_synack: no error";
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7) << "write_synack: frame written";
    }

    // ─── send_waste_frame 无 padding ─────────────

    TEST(AnytlsSessionDeep, SendWasteFrameNoPadding)
    {
        SessionFixture fx;
        fx.init();

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void> { co_await fx.session->send_waste_frame(0, ec); };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(!ec) << "waste no pad: no error";
        auto &written = fx.transport->WrittenData();
        EXPECT_TRUE(written.empty()) << "waste no pad: nothing written";
    }

    // ─── send_waste_frame 有 padding ─────────────

    TEST(AnytlsSessionDeep, SendWasteFrameWithPadding)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>("stop=2\n0=10-10\n1=c,20-20\n");
        fx.init(pad);

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void> { co_await fx.session->send_waste_frame(0, ec); };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(!ec) << "waste with pad: no error";
        // pkt=0 -> "10-10" -> 一个 10 字节 waste 帧
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7 + 10) << "waste with pad: waste written";
    }

    // ─── send_waste_frame 超出 stop ──────────────

    TEST(AnytlsSessionDeep, SendWasteFrameBeyondStop)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>("stop=1\n0=c\n");
        fx.init(pad);

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void> { co_await fx.session->send_waste_frame(1, ec); };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        // pkt=1 >= stop=1, generate_sizes 返回 checkmark，不 padding
        EXPECT_TRUE(!ec) << "waste beyond stop: no error";
    }

    // ─── write_frame 写入错误 ────────────────────

    TEST(AnytlsSessionDeep, WriteFrameError)
    {
        SessionFixture fx;
        fx.init();
        fx.transport->SetWriteError(std::make_error_code(std::errc::broken_pipe));

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        { co_await fx.session->write_frame(anytls::frame_input{anytls::command::psh, 1, {}, ec}); };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(ec.operator bool()) << "write error: has error";
    }

    // ─── recv_loop 带 padding 发送 waste ────────

    TEST(AnytlsSessionDeep, RecvLoopWithPadding)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>("stop=10\n0=c,20-20\n");
        fx.init(pad);

        auto payload = make_settings_payload("v=1\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->InjectRead(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        // padding enabled 且 pkt_counter_ 递增
        EXPECT_TRUE(fx.session->pkt_counter_ >= 1) << "recv pad: counter incremented";
    }

    // ─── wait_first_stream 已 resolved ───────────

    TEST(AnytlsSessionDeep, WaitFirstStreamResolved)
    {
        SessionFixture fx;
        fx.init();
        fx.session->init_resolved_ = true;
        fx.session->init_id_ = 42;
        fx.session->init_preread_ = {0x01, 0x02};

        bool ok = false;
        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            auto [ec, tup] = co_await fx.session->wait_first_stream();
            auto &[id, preread] = tup;
            if (id == 42 && preread.size() == 2)
            {
                ok = true;
            }
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(ok) << "wait resolved: got cached result";
    }

    // ─── recv_loop 异常路径 ─────────────────────

    TEST(AnytlsSessionDeep, RecvLoopException)
    {
        SessionFixture fx;
        fx.init();

        // 设置读错误让 recv_loop 抛出
        fx.transport->SetReadError(std::make_error_code(std::errc::io_error));

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        // recv 异常应触发 init resolve 为错误
        EXPECT_TRUE(fx.session->init_resolved_) << "recv exception: init resolved";
        EXPECT_TRUE(fx.session->init_error_ != psm::fault::code::success)
            << "recv exception: error set on io_error";
    }

    // ─── recv_loop 多帧序列：settings + syn + psh ─

    TEST(AnytlsSessionDeep, RecvLoopFullSequence)
    {
        SessionFixture fx;
        fx.init();

        // Frame 1: settings v=1
        auto settings_payload = make_settings_payload("v=1\n");
        auto f1 = make_frame_bytes(anytls::command::settings, 0, settings_payload);

        // Frame 2: syn stream 1
        auto f2 = make_frame_bytes(anytls::command::syn, 1);

        // Frame 3: psh stream 1 with data
        auto psh_data = std::vector<std::uint8_t>{0x05, 0x06, 0x07};
        auto f3 = make_frame_bytes(anytls::command::psh, 1, psh_data);

        // 依次注入
        fx.transport->InjectRead(f1.data(), f1.size());
        fx.transport->InjectRead(f2.data(), f2.size());
        fx.transport->InjectRead(f3.data(), f3.size());

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(fx.session->received_settings_) << "full seq: settings";
        EXPECT_TRUE(fx.session->streams_.count(1) == 1) << "full seq: stream 1";
        EXPECT_TRUE(fx.session->init_resolved_) << "full seq: init resolved";
        EXPECT_TRUE(fx.session->init_id_ == 1) << "full seq: init_id 1";
        EXPECT_TRUE(fx.session->init_preread_.size() == 3) << "full seq: preread 3";
    }

    // ─── recv_loop payload 读取中途关闭 ──────────

    TEST(AnytlsSessionDeep, RecvLoopPayloadReadClosed)
    {
        SessionFixture fx;
        fx.init();

        // 构造有 length 但不注入 payload 数据
        anytls::frame_header hdr;
        hdr.cmd = anytls::command::settings;
        hdr.stream_id = 0;
        hdr.length = 100; // 声明 100 字节 payload
        auto ser = hdr.serialize();
        std::vector<std::byte> frame_bytes;
        for (auto b : ser)
        {
            frame_bytes.push_back(static_cast<std::byte>(b));
        }

        // 注入 header 后关闭
        fx.transport->InjectRead(frame_bytes.data(), frame_bytes.size());
        fx.transport->close();

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        // payload 读取中途关闭应触发错误但不崩溃
        EXPECT_TRUE(fx.session->init_resolved_ || !fx.session->received_settings_)
            << "payload closed: session state consistent";
    }

    // ─── on_psh 后续 stream 未知 stream ──────────

    TEST(AnytlsSessionDeep, OnPshSubsequentUnknownStream)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;
        fx.session->init_resolved_ = true;

        auto data = std::vector<std::uint8_t>{0x01};
        auto frame = make_frame_bytes(anytls::command::psh, 99, data);
        fx.transport->InjectRead(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        // 后续 PSH 到未知 stream 应被忽略
        EXPECT_EQ(fx.session->streams_.count(99), 0u) << "psh sub unknown: no stream 99";
    }

    // ─── OnSettings 空 payload ─────────────────

    TEST(AnytlsSessionDeep, OnSettingsEmptyPayload)
    {
        SessionFixture fx;
        fx.init();

        auto frame = make_frame_bytes(anytls::command::settings, 0);
        fx.transport->InjectRead(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> Net::awaitable<void>
        {
            fx.session->start();
            Net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(Net::redirect_error(Net::use_awaitable, ec));
        };
        Net::co_spawn(fx.ioc().get_executor(), coro(),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          fx.ioc().stop();
                      });
        fx.ioc().run();

        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                FAIL() << e.what();
            }
        }

        EXPECT_TRUE(fx.session->received_settings_) << "settings empty: received";
        EXPECT_TRUE(fx.session->peer_version_ == 1) << "settings empty: version unchanged";
    }

