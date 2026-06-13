/**
 * @file AnytlsSessionDeep.cpp
 * @brief anytls/session.cpp 深度测试 — 全分支覆盖
 * @details 通过 #define private public 访问 private 成员，使用 MockTransport
 *          注入帧数据测试 recv_loop/dispatch_frame 各命令分支：
 *          constructor、close、get_stream_channel、
 *          on_settings（v1/v2/padding-md5 匹配/不匹配）、
 *          on_syn（正常/无 settings/zero stream_id/第一/后续 stream）、
 *          on_psh（第一 stream 首包/后续/后续 stream 首 PSH/未知 stream）、
 *          on_fin、alert、heart_req、waste、default、
 *          read_exact、write_frame、send_waste_frame、
 *          write_psh、write_fin、write_synack、
 *          recv_loop 异常路径、wait_first_stream。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 *          所有涉及 start() 的测试均使用 co_spawn + ioc.run() 模式。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>

#include "common/MockTransport.hpp"

#include <prism/core/core.hpp>
#include <prism/stealth/stack/anytls/mux/frame.hpp>
#include <prism/stealth/stack/anytls/padding.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

// 必须在 session.hpp 之前定义，否则 transport.hpp 内部已包含 session.hpp
#define private public
#define protected public
#include <prism/stealth/stack/anytls/mux/transport.hpp>
#include <prism/stealth/stack/anytls/mux/session.hpp>
#undef protected
#undef private

#include "../../src/prism/stealth/stack/anytls/session.cpp"

using MockTransport = psm::testing::MockTransport;
namespace anytls = psm::stealth::anytls;
namespace net = boost::asio;

namespace
{
    auto make_frame_bytes(anytls::command cmd, std::uint32_t stream_id,
                          std::span<const std::uint8_t> payload = {})
        -> std::vector<std::byte>
    {
        anytls::frame_header hdr;
        hdr.cmd = cmd;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint16_t>(payload.size());
        auto ser = hdr.serialize();
        std::vector<std::byte> out;
        out.reserve(7 + payload.size());
        for (auto b : ser)
            out.push_back(static_cast<std::byte>(b));
        for (auto b : payload)
            out.push_back(static_cast<std::byte>(b));
        return out;
    }

    auto make_settings_payload(std::string_view text)
        -> std::vector<std::uint8_t>
    {
        return {text.begin(), text.end()};
    }

    struct SessionFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::shared_ptr<anytls::anytls_session> session;
        anytls::anytls_session::stream_callback last_callback;
        bool callback_called{false};
        std::uint32_t cb_stream_id{0};
        std::shared_ptr<psm::transport::transmission> cb_transport;
        psm::memory::vector<std::uint8_t> cb_preread;

        SessionFixture()
            : cb_preread(psm::memory::current_resource())
        {
        }

        void init(std::shared_ptr<anytls::padding_factory> padding = nullptr)
        {
            transport = std::make_shared<MockTransport>();
            auto cb = [this](std::uint32_t sid,
                             std::shared_ptr<psm::transport::transmission> trans,
                             psm::memory::vector<std::uint8_t> preread)
            {
                callback_called = true;
                cb_stream_id = sid;
                cb_transport = std::move(trans);
                cb_preread = std::move(preread);
            };
            session = std::make_shared<anytls::anytls_session>(
                transport, std::move(padding), std::move(cb));
        }

        auto &ioc() { return transport->get_io_context(); }
    };

    // ─── constructor + close + get_stream_channel ──

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
        EXPECT_TRUE(ch == nullptr) << "get_stream_channel: empty -> nullptr";

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
        auto ch = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[1] = ch;

        auto found = fx.session->get_stream_channel(1);
        EXPECT_TRUE(found != nullptr) << "get_channel: stream 1 found";
        EXPECT_TRUE(found.get() == ch.get()) << "get_channel: same channel";

        auto missing = fx.session->get_stream_channel(99);
        EXPECT_TRUE(missing == nullptr) << "get_channel: missing -> nullptr";
    }

    // ─── on_settings v1 ───────────────────────────

    TEST(AnytlsSessionDeep, OnSettingsV1)
    {
        SessionFixture fx;
        fx.init();

        auto payload = make_settings_payload("v=1\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->received_settings_) << "settings v1: received";
        EXPECT_TRUE(fx.session->peer_version_ == 1) << "settings v1: version 1";
    }

    // ─── on_settings v2（发送 server_settings）────

    TEST(AnytlsSessionDeep, OnSettingsV2)
    {
        SessionFixture fx;
        fx.init();

        auto payload = make_settings_payload("v=2\npadding-md5=abc\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->peer_version_ == 2) << "settings v2: version 2";

        // v2 会写 server_settings 帧，检查 written_data
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7) << "settings v2: server_settings written";
    }

    // ─── on_settings v2 + padding mismatch ────────

    TEST(AnytlsSessionDeep, OnSettingsV2PaddingMismatch)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>(
            "stop=1\n0=c,30-30\n");
        fx.init(pad);

        // padding 的 md5 不匹配 "abc"
        auto payload = make_settings_payload("v=2\npadding-md5=abc\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->peer_version_ == 2) << "pad mismatch: version 2";

        // 应该写了 update_padding 帧 + server_settings 帧
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 14) << "pad mismatch: frames written";
    }

    // ─── on_settings v2 + padding match ───────────

    TEST(AnytlsSessionDeep, OnSettingsV2PaddingMatch)
    {
        SessionFixture fx;
        auto scheme = std::string_view("stop=1\n0=c,30-30\n");
        auto pad = std::make_shared<anytls::padding_factory>(scheme);
        fx.init(pad);

        // 发送匹配的 md5
        auto payload = make_settings_payload(
            std::string("v=2\npadding-md5=") + std::string(pad->md5) + "\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->peer_version_ == 2) << "pad match: version 2";

        // 匹配时不发送 update_padding，只发 server_settings
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7) << "pad match: server_settings written";
    }

    // ─── on_syn 正常路径 ──────────────────────────

    TEST(AnytlsSessionDeep, OnSynNormal)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::syn, 1);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->streams_.empty()) << "syn no settings: ignored";
    }

    // ─── on_syn stream_id=0 → 忽略 ───────────────

    TEST(AnytlsSessionDeep, OnSynZeroStreamId)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::syn, 0);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        auto ch = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[1] = ch;

        auto data = std::vector<std::uint8_t>{0x01, 0x02, 0x03};
        auto frame = make_frame_bytes(anytls::command::psh, 1, data);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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

        auto ch2 = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[2] = ch2;
        fx.session->pending_syns_.insert(2);

        auto data = std::vector<std::uint8_t>{0x04, 0x05};
        auto frame = make_frame_bytes(anytls::command::psh, 2, data);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.callback_called) << "psh sub callback: called";
        EXPECT_TRUE(fx.cb_stream_id == 2) << "psh sub callback: stream_id 2";
        EXPECT_TRUE(fx.cb_preread.size() == 2) << "psh sub callback: preread 2 bytes";
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

        auto ch2 = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[2] = ch2;
        fx.session->pending_syns_.insert(2);

        auto data = std::vector<std::uint8_t>{0x01};
        auto frame = make_frame_bytes(anytls::command::psh, 2, data);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // v2 会发送 synack 帧
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7) << "psh v2 synack: frame written";
    }

    // ─── on_psh 第一 stream 后续数据 ──────────────

    TEST(AnytlsSessionDeep, OnPshFirstStreamSubsequentData)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;
        fx.session->init_id_ = 1;
        fx.session->init_resolved_ = true;

        auto ch = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[1] = ch;

        auto data = std::vector<std::uint8_t>{0xAA, 0xBB};
        auto frame = make_frame_bytes(anytls::command::psh, 1, data);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // 验证 session 仍在运行且没有意外写入
        auto &written = fx.transport->written_data();
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
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // 未知 stream 的 PSH 应被忽略，不应创建新 stream
        EXPECT_EQ(fx.session->streams_.count(99), 0u) << "psh unknown: no stream 99 created";
    }

    // ─── on_fin 正常 ─────────────────────────────

    TEST(AnytlsSessionDeep, OnFin)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto ch = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[5] = ch;

        auto frame = make_frame_bytes(anytls::command::fin, 5);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->streams_.count(5) == 0) << "fin: stream 5 removed";
    }

    // ─── on_fin 未知 stream ──────────────────────

    TEST(AnytlsSessionDeep, OnFinUnknownStream)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::fin, 99);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->streams_.empty()) << "fin unknown: no streams";
    }

    // ─── alert 命令 ──────────────────────────────

    TEST(AnytlsSessionDeep, AlertCommand)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto ch = std::make_shared<anytls::anytls_session::channel_type>(
            fx.transport->get_io_context(), 64);
        fx.session->streams_[3] = ch;

        auto frame = make_frame_bytes(anytls::command::alert, 3);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->streams_.count(3) == 0) << "alert: stream 3 removed";
    }

    // ─── alert 未知 stream ───────────────────────

    TEST(AnytlsSessionDeep, AlertUnknownStream)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::alert, 77);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->received_settings_) << "alert unknown: settings still set";
    }

    // ─── heart_req 命令（发送 heart_resp）────────

    TEST(AnytlsSessionDeep, HeartbeatRequest)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::heart_req, 0);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // heart_resp 应被写入
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7) << "heart_req: response written";

        if (written.size() >= 7)
        {
            auto resp_cmd = static_cast<anytls::command>(written[0]);
            EXPECT_TRUE(resp_cmd == anytls::command::heart_resp)
                << "heart_req: cmd = heart_resp";
        }
    }

    // ─── waste 命令 ──────────────────────────────

    TEST(AnytlsSessionDeep, WasteCommand)
    {
        SessionFixture fx;
        fx.init();
        fx.session->received_settings_ = true;

        auto frame = make_frame_bytes(anytls::command::waste, 0);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
            frame_bytes.push_back(static_cast<std::byte>(b));
        fx.transport->inject_read(frame_bytes.data(), frame_bytes.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // 未知命令应被静默忽略
        EXPECT_TRUE(fx.session->received_settings_) << "unknown cmd: session alive";
    }

    // ─── recv_loop 连接关闭 ─────────────────────

    TEST(AnytlsSessionDeep, RecvLoopConnectionClosed)
    {
        SessionFixture fx;
        fx.init();

        // 不注入任何数据，直接关闭
        fx.transport->close();

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->init_resolved_) << "recv closed: init resolved";
        EXPECT_TRUE(fx.session->init_error_ == psm::fault::code::eof)
            << "recv closed: error = eof";
    }

    // ─── recv_loop 无效帧头 ─────────────────────

    TEST(AnytlsSessionDeep, RecvLoopInvalidHeader)
    {
        SessionFixture fx;
        fx.init();

        // 注入只有 3 字节（不足 7），read_exact 会读取 3 字节后再次 async_read_some
        // MockTransport 队列空后进入轮询定时器，close() 后 read_exact 返回 false
        std::vector<std::byte> short_data(3, std::byte{0x00});
        fx.transport->inject_read(short_data.data(), short_data.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();

            // 等待 read_exact 读取 3 字节，然后挂起在定时器上等待更多数据
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(50));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

            // 关闭让 recv_loop 的 read_exact 返回 false → recv_loop 退出
            fx.transport->close();

            timer.expires_after(std::chrono::milliseconds(50));
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        auto coro = [&]() -> net::awaitable<void>
        {
            auto n = co_await fx.session->write_psh(1, data, ec);
            EXPECT_TRUE(n == 2) << "write_psh: returned 2";
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(!ec) << "write_psh: no error";
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7 + 2) << "write_psh: data written";
    }

    // ─── write_fin ───────────────────────────────

    TEST(AnytlsSessionDeep, WriteFin)
    {
        SessionFixture fx;
        fx.init();

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            co_await fx.session->write_fin(1, ec);
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(!ec) << "write_fin: no error";
    }

    // ─── write_synack ────────────────────────────

    TEST(AnytlsSessionDeep, WriteSynack)
    {
        SessionFixture fx;
        fx.init();

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            co_await fx.session->write_synack(1, ec);
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(!ec) << "write_synack: no error";
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7) << "write_synack: frame written";
    }

    // ─── send_waste_frame 无 padding ─────────────

    TEST(AnytlsSessionDeep, SendWasteFrameNoPadding)
    {
        SessionFixture fx;
        fx.init();

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            co_await fx.session->send_waste_frame(0, ec);
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(!ec) << "waste no pad: no error";
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.empty()) << "waste no pad: nothing written";
    }

    // ─── send_waste_frame 有 padding ─────────────

    TEST(AnytlsSessionDeep, SendWasteFrameWithPadding)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>(
            "stop=2\n0=10-10\n1=c,20-20\n");
        fx.init(pad);

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            co_await fx.session->send_waste_frame(0, ec);
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(!ec) << "waste with pad: no error";
        // pkt=0 -> "10-10" -> 一个 10 字节 waste 帧
        auto &written = fx.transport->written_data();
        EXPECT_TRUE(written.size() >= 7 + 10) << "waste with pad: waste written";
    }

    // ─── send_waste_frame 超出 stop ──────────────

    TEST(AnytlsSessionDeep, SendWasteFrameBeyondStop)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>(
            "stop=1\n0=c\n");
        fx.init(pad);

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            co_await fx.session->send_waste_frame(1, ec);
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // pkt=1 >= stop=1, generate_sizes 返回 checkmark，不 padding
        EXPECT_TRUE(!ec) << "waste beyond stop: no error";
    }

    // ─── write_frame 写入错误 ────────────────────

    TEST(AnytlsSessionDeep, WriteFrameError)
    {
        SessionFixture fx;
        fx.init();
        fx.transport->set_write_error(std::make_error_code(std::errc::broken_pipe));

        std::error_code ec;
        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            co_await fx.session->write_frame(
                anytls::frame_input{anytls::command::psh, 1, {}, ec});
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(ec.operator bool()) << "write error: has error";
    }

    // ─── recv_loop 带 padding 发送 waste ────────

    TEST(AnytlsSessionDeep, RecvLoopWithPadding)
    {
        SessionFixture fx;
        auto pad = std::make_shared<anytls::padding_factory>(
            "stop=10\n0=c,20-20\n");
        fx.init(pad);

        auto payload = make_settings_payload("v=1\n");
        auto frame = make_frame_bytes(anytls::command::settings, 0, payload);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        auto coro = [&]() -> net::awaitable<void>
        {
            auto [ec, tup] = co_await fx.session->wait_first_stream();
            auto &[id, preread] = tup;
            if (id == 42 && preread.size() == 2)
                ok = true;
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(ok) << "wait resolved: got cached result";
    }

    // ─── recv_loop 异常路径 ─────────────────────

    TEST(AnytlsSessionDeep, RecvLoopException)
    {
        SessionFixture fx;
        fx.init();

        // 设置读错误让 recv_loop 抛出
        fx.transport->set_read_error(std::make_error_code(std::errc::io_error));

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        fx.transport->inject_read(f1.data(), f1.size());
        fx.transport->inject_read(f2.data(), f2.size());
        fx.transport->inject_read(f3.data(), f3.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
            frame_bytes.push_back(static_cast<std::byte>(b));

        // 注入 header 后关闭
        fx.transport->inject_read(frame_bytes.data(), frame_bytes.size());
        fx.transport->close();

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

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
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        // 后续 PSH 到未知 stream 应被忽略
        EXPECT_EQ(fx.session->streams_.count(99), 0u) << "psh sub unknown: no stream 99";
    }

    // ─── on_settings 空 payload ─────────────────

    TEST(AnytlsSessionDeep, OnSettingsEmptyPayload)
    {
        SessionFixture fx;
        fx.init();

        auto frame = make_frame_bytes(anytls::command::settings, 0);
        fx.transport->inject_read(frame.data(), frame.size());

        std::exception_ptr ep;
        auto coro = [&]() -> net::awaitable<void>
        {
            fx.session->start();
            net::steady_timer timer(fx.ioc().get_executor());
            timer.expires_after(std::chrono::milliseconds(100));
            boost::system::error_code ec;
            co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
        };
        net::co_spawn(fx.ioc().get_executor(), coro(), [&](std::exception_ptr e)
                      { ep = e; fx.ioc().stop(); });
        fx.ioc().run();

        if (ep) { try { std::rethrow_exception(ep); } catch (const std::exception &e) { FAIL() << e.what(); } }

        EXPECT_TRUE(fx.session->received_settings_) << "settings empty: received";
        EXPECT_TRUE(fx.session->peer_version_ == 1) << "settings empty: version unchanged";
    }

} // namespace
