/**
 * @file AnytlsSessionDeep.cpp
 * @brief anytls/session.cpp 深度测试 — 全分支覆盖
 * @details 通过 #define private public 访问 private 成员，使用 ProductionMockTransport
 *          注入帧数据测试 recv_loop/dispatch_frame 各命令分支：
 *          constructor、close、get_stream_channel、
 *          OnSettings（v1/v2/padding-md5 匹配/不匹配）、
 *          on_syn（正常/无 settings/zero stream_id/第一/后续 stream）、
 *          on_psh（第一 stream 首包/后续/后续 stream 首 PSH/未知 stream）、
 *          on_fin、alert、heart_req、waste、default、
 *          read_exact、write_frame、send_waste_frame、
 *          write_psh、write_fin、write_synack、
 *          recv_loop 异常路径、wait_first_stream。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 *          所有涉及 start() 的测试均使用 co_spawn + ioc.run() 模式。
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

TEST(AnytlsSessionDeep, ConstructorAndClose)
    {
        SessionFixture fx;
        fx.init();

        EXPECT_TRUE(!fx.session->closed_) << "constructor: not closed";
        EXPECT_TRUE(!fx.session->init_resolved_) << "constructor: init not resolved";
        EXPECT_TRUE(fx.session->init_id_ == 0) << "constructor: init_id 0";
        EXPECT_TRUE(fx.session->peer_version_ == 1) << "constructor: default version 1";
        EXPECT_TRUE(!fx.session->received_settings_) << "constructor: no settings";
        EXPECT_TRUE(fx.session->streams_.empty()) << "constructor: no streams";

        auto ch = fx.session->get_stream_channel(42);
        EXPECT_EQ(ch, nullptr) << "get_stream_channel: empty -> nullptr";

        fx.session->close();
        EXPECT_TRUE(fx.session->closed_) << "close: closed_ set";
        EXPECT_TRUE(fx.session->init_resolved_) << "close: init resolved";
        EXPECT_TRUE(fx.session->init_error_ == psm::fault::code::eof) << "close: error = eof";

        // 幂等 close
        fx.session->close();
        EXPECT_TRUE(fx.session->closed_) << "close: idempotent";
    }
    // ─── get_stream_channel 有 stream ──────────────

    TEST(AnytlsSessionDeep, GetStreamChannelAfterSyn)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        // 手动注入一个 stream channel
        auto ch = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[1] = ch;

        auto found = fx.session->get_stream_channel(1);
        EXPECT_NE(found, nullptr) << "get_channel: stream 1 found";
        EXPECT_EQ(found.get(), ch.get()) << "get_channel: same channel";

        auto missing = fx.session->get_stream_channel(99);
        EXPECT_EQ(missing, nullptr) << "get_channel: missing -> nullptr";
    }
    // ─── OnSettings v1 ───────────────────────────

    TEST(AnytlsSessionDeep, OnSettingsV1)
    {
        SessionFixture fx;
        fx.init();

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

        EXPECT_TRUE(fx.session->received_settings_) << "settings v1: received";
        EXPECT_TRUE(fx.session->peer_version_ == 1) << "settings v1: version 1";
    }
    // ─── OnSettings v2（发送 server_settings）────

    TEST(AnytlsSessionDeep, OnSettingsV2)
    {
        SessionFixture fx;
        fx.init();

        auto payload = make_settings_payload("v=2\npadding-md5=abc\n");
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

        EXPECT_TRUE(fx.session->peer_version_ == 2) << "settings v2: version 2";

        // v2 会写 server_settings 帧，检查 WrittenData
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7) << "settings v2: server_settings written";
    }

    // ─── OnSettings v2 + padding mismatch ────────

    TEST(AnytlsSessionDeep, OnSettingsV2PaddingMismatch)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>("stop=1\n0=c,30-30\n");
        fx.init(pad);

        // padding 的 md5 不匹配 "abc"
        auto payload = make_settings_payload("v=2\npadding-md5=abc\n");
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

        EXPECT_TRUE(fx.session->peer_version_ == 2) << "pad mismatch: version 2";

        // 应该写了 update_padding 帧 + server_settings 帧
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 14) << "pad mismatch: frames written";
    }

    // ─── OnSettings v2 + padding match ───────────

    TEST(AnytlsSessionDeep, OnSettingsV2PaddingMatch)
    {
        SessionFixture fx;
        auto scheme = std::string_view("stop=1\n0=c,30-30\n");
        auto pad = std::make_shared<anytls::padding_factory>(scheme);
        fx.init(pad);

        // 发送匹配的 md5
        auto payload = make_settings_payload(std::string("v=2\npadding-md5=") + std::string(pad->md5) + "\n");
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

        EXPECT_TRUE(fx.session->peer_version_ == 2) << "pad match: version 2";

        // 匹配时不发送 update_padding，只发 server_settings
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7) << "pad match: server_settings written";
    }

    // ─── on_syn 正常路径 ──────────────────────────

    TEST(AnytlsSessionDeep, OnSynNormal)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::syn, 1);
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

        EXPECT_TRUE(fx.session->streams_.count(1) == 1) << "syn: stream 1 created";
        EXPECT_TRUE(fx.session->init_id_ == 1) << "syn: init_id = 1";
        EXPECT_TRUE(fx.session->pending_syns_.empty()) << "syn: first stream not pending";
    }

    // ─── on_syn 后续 stream ───────────────────────

    TEST(AnytlsSessionDeep, OnSynSubsequent)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;

        auto frame = make_frame_bytes(anytls::command::syn, 2);
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

        EXPECT_TRUE(fx.session->streams_.count(2) == 1) << "syn sub: stream 2 created";
        EXPECT_TRUE(fx.session->pending_syns_.count(2) == 1) << "syn sub: stream 2 pending";
    }

    // ─── on_syn 无 settings → 忽略 ───────────────

    TEST(AnytlsSessionDeep, OnSynNoSettings)
    {
        SessionFixture fx;
        fx.init();
        // received_settings_ = false (default)

        auto frame = make_frame_bytes(anytls::command::syn, 1);
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

        EXPECT_TRUE(fx.session->streams_.empty()) << "syn no settings: ignored";
    }

    // ─── on_syn stream_id=0 → 忽略 ───────────────

    TEST(AnytlsSessionDeep, OnSynZeroStreamId)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::syn, 0);
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

        EXPECT_TRUE(fx.session->streams_.empty()) << "syn zero: ignored";
    }

    // ─── on_psh 第一 stream 首包（preread）───────

    TEST(AnytlsSessionDeep, OnPshFirstStreamPreread)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;

        // 创建 stream channel
        auto ch = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[1] = ch;

        auto data = std::vector<std::uint8_t>{0x01, 0x02, 0x03};
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

        EXPECT_TRUE(fx.session->init_resolved_) << "psh preread: init resolved";
        EXPECT_TRUE(fx.session->init_id_ == 1) << "psh preread: init_id 1";
        EXPECT_TRUE(fx.session->init_preread_.size() == 3) << "psh preread: 3 bytes";
    }

    // ─── on_psh 后续 stream 首 PSH（触发 callback）──

    TEST(AnytlsSessionDeep, OnPshSubsequentStreamCallback)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;
        fx.session->init_resolved_ = true;
        fx.session->peer_version_ = 1;

        auto ch2 = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[2] = ch2;
        fx.session->pending_syns_.insert(2);

        auto data = std::vector<std::uint8_t>{0x04, 0x05};
        auto frame = make_frame_bytes(anytls::command::psh, 2, data);
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

        EXPECT_TRUE(fx.callback_called) << "psh sub callback: called";
        EXPECT_EQ(fx.cb_stream_id, 2) << "psh sub callback: stream_id 2";
        EXPECT_EQ(fx.cb_preread.size(), 2) << "psh sub callback: preread 2 bytes";
        EXPECT_TRUE(fx.session->pending_syns_.count(2) == 0) << "psh sub callback: pending removed";
    }

    // ─── on_psh 后续 stream v2（发送 synack）─────

    TEST(AnytlsSessionDeep, OnPshSubsequentStreamV2Synack)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;
        fx.session->init_resolved_ = true;
        fx.session->peer_version_ = 2;

        auto ch2 = std::make_shared<anytls::anytls_session::channel_type>(fx.transport->GetIoContext(), 64);
        fx.session->streams_[2] = ch2;
        fx.session->pending_syns_.insert(2);

        auto data = std::vector<std::uint8_t>{0x01};
        auto frame = make_frame_bytes(anytls::command::psh, 2, data);
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

        // v2 会发送 synack 帧
        auto &written = fx.transport->WrittenData();
        EXPECT_GE(written.size(), 7) << "psh v2 synack: frame written";
    }
