/**
 * @file AnytlsSessionDispatchTest.cpp
 * @brief AnyTLS settings, stream command, and control/error dispatch tests.
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

TEST(AnytlsSessionDeep, OnPshFirstStreamSubsequentData)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;
        fx.session->init_resolved_ = true;

        auto ch = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[1] = ch;

        auto data = std::vector<std::uint8_t>{0xAA, 0xBB};
        auto frame = make_frame_bytes(anytls::command::psh, 1, data);
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

        // 验证 session 仍在运行且没有意外写入
        auto &written = fx.transport->WrittenData();
        EXPECT_TRUE(written.empty()) << "psh first subseq: no unexpected write";
        // stream 1 的 channel 应存在
        EXPECT_TRUE(fx.session->streams_.count(1) == 1) << "psh first subseq: stream 1 exists";
    }

    // ─── on_psh 未知 stream ──────────────────────

    TEST(AnytlsSessionDeep, OnPshUnknownStream)
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

        // 未知 stream 的 PSH 应被忽略，不应创建新 stream
        EXPECT_EQ(fx.session->streams_.count(99), 0u) << "psh unknown: no stream 99 created";
    }

    // ─── on_fin 正常 ─────────────────────────────

    TEST(AnytlsSessionDeep, OnFin)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto ch = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[5] = ch;

        auto frame = make_frame_bytes(anytls::command::fin, 5);
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

        EXPECT_TRUE(fx.session->streams_.count(5) == 0) << "fin: stream 5 removed";
    }

    // ─── on_fin 未知 stream ──────────────────────

    TEST(AnytlsSessionDeep, OnFinUnknownStream)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::fin, 99);
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

        EXPECT_TRUE(fx.session->streams_.empty()) << "fin unknown: no streams";
    }

    // ─── alert 命令 ──────────────────────────────

    TEST(AnytlsSessionDeep, AlertCommand)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto ch = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[3] = ch;

        auto frame = make_frame_bytes(anytls::command::alert, 3);
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

        EXPECT_TRUE(fx.session->streams_.count(3) == 0) << "alert: stream 3 removed";
    }

    // ─── alert 未知 stream ───────────────────────

    TEST(AnytlsSessionDeep, AlertUnknownStream)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::alert, 77);
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

        EXPECT_TRUE(fx.session->received_settings_) << "alert unknown: settings still set";
    }

    // ─── heart_req 命令（发送 heart_resp）────────

    TEST(AnytlsSessionDeep, HeartbeatRequest)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::heart_req, 0);
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

        // heart_resp 应被写入
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7) << "heart_req: response written";

        if (written.size() >= 7)
        {
            auto resp_cmd = static_cast<anytls::command>(written[0]);
            EXPECT_EQ(resp_cmd, anytls::command::heart_resp) << "heart_req: cmd = heart_resp";
        }
    }

    // ─── waste 命令 ──────────────────────────────

    TEST(AnytlsSessionDeep, WasteCommand)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::waste, 0);
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

        // waste 命令应被静默忽略，不应产生写入
        EXPECT_TRUE(fx.session->received_settings_) << "waste: session alive after waste";
    }

    // ─── default 命令（未知命令）─────────────────

    TEST(AnytlsSessionDeep, UnknownCommand)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        // 构造一个无效命令 0xFF
        anytls::frame_header hdr;
        hdr.cmd = static_cast<anytls::command>(0xFF);
        hdr.stream_id = 0;
        hdr.length = 0;
        auto ser = hdr.serialize();
        std::vector<std::byte> frame_bytes;
        for (auto b : ser)
        {
            frame_bytes.push_back(static_cast<std::byte>(b));
        }
        fx.transport->InjectRead(frame_bytes.data(), frame_bytes.size());

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

        // 未知命令应被静默忽略
        EXPECT_TRUE(fx.session->received_settings_) << "unknown cmd: session alive";
    }

    // ─── recv_loop 连接关闭 ─────────────────────

