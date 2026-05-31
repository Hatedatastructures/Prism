/**
 * @file H2muxCraftDeep2.cpp
 * @brief multiplex/h2mux/craft nghttp2 回调 + handle_connect + init_nghttp2 深度测试
 * @details 通过 #define private/protected public 访问 craft 的非公开成员，
 *          直接调用 init_nghttp2、handle_connect、respond_connect，
 *          以及 nghttp2 静态回调 on_begin_headers、on_header、on_frame_recv、
 *          on_data、on_stream_close。使用手动构造的 nghttp2_frame 结构测试回调逻辑。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"
#include "common/MockTransport.hpp"

// 打开 craft 及其传递依赖的非公开访问
#define private public
#define protected public
#include <prism/connect/pool/pool.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/stats/traffic.hpp>
#undef protected
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/multiplex/h2mux/craft.cpp"

using psm::testing::TestRunner;
using MockTransport = psm::testing::MockTransport;
namespace multiplex = psm::multiplex;
namespace h2mux = psm::multiplex::h2mux;
namespace net = boost::asio;

namespace
{
    static multiplex::config g_cfg{};

    static auto make_resolver() -> h2mux::address_resolver
    {
        return [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
        {
            h2mux::stream_info info;
            info.host = "127.0.0.1";
            info.port = 80;
            info.type = h2mux::stream_type::tcp;
            info.valid = true;
            return info;
        };
    }

    static auto make_invalid_resolver() -> h2mux::address_resolver
    {
        return [](std::int32_t, const h2mux::h2_headers &) -> h2mux::stream_info
        {
            h2mux::stream_info info;
            info.valid = false;
            return info;
        };
    }

    struct CraftFixture
    {
        std::shared_ptr<MockTransport> transport;
        std::unique_ptr<net::io_context> ioc;
        std::unique_ptr<psm::connect::connection_pool> pool;
        std::unique_ptr<psm::connect::router> router_ptr;
        std::shared_ptr<h2mux::craft> craft_obj;

        CraftFixture()
        {
            transport = std::make_shared<MockTransport>();
            ioc = std::make_unique<net::io_context>(1);
            pool = std::make_unique<psm::connect::connection_pool>(*ioc);
            psm::resolve::dns::config dns_cfg;
            psm::connect::router_options ropts{*pool, *ioc, dns_cfg};
            router_ptr = std::make_unique<psm::connect::router>(std::move(ropts));
            multiplex::core_options opts{transport, *router_ptr, g_cfg, nullptr};
            h2mux::craft_init init{*router_ptr, g_cfg, make_resolver()};
            craft_obj = std::make_shared<h2mux::craft>(std::move(opts), std::move(init));
        }
    };

    // ─── init_nghttp2 ─────────────────────────────

    void TestInitNghttp2Success(TestRunner &runner)
    {
        CraftFixture fx;
        auto rc = fx.craft_obj->init_nghttp2();
        runner.Check(rc == 0, "init_nghttp2: returns 0");
        runner.Check(fx.craft_obj->session_ != nullptr, "init_nghttp2: session not null");
    }

    // ─── respond_connect（需要 init_nghttp2）─────

    void TestRespondConnect200(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();
        auto rc = fx.craft_obj->respond_connect(1, 200);
        runner.Check(rc == 0, "respond_connect: 200 -> 0");
    }

    void TestRespondConnect407(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();
        auto rc = fx.craft_obj->respond_connect(1, 407);
        runner.Check(rc == 0, "respond_connect: 407 -> 0");
    }

    void TestRespondConnectOtherStatus(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();
        auto rc = fx.craft_obj->respond_connect(1, 500);
        runner.Check(rc == 0, "respond_connect: 500 -> 0 (default 407)");
    }

    // ─── handle_connect ───────────────────────────

    void TestHandleConnectNotFound(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->handle_connect(999);
        runner.Check(true, "handle_connect: not found -> no crash");
    }

    void TestHandleConnectFirstConnect(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        fx.craft_obj->h2_pending_[1] = std::move(entry);
        runner.Check(!fx.craft_obj->connect_resolved_, "handle_connect: not resolved before");

        fx.craft_obj->handle_connect(1);
        runner.Check(fx.craft_obj->connect_resolved_, "handle_connect: first -> resolved");
        runner.Check(!fx.craft_obj->h2_pending_[1].connecting, "handle_connect: first -> not connecting");
    }

    void TestHandleConnectInvalidInfo(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->resolver_ = make_invalid_resolver();

        h2mux::h2_pending_entry entry;
        fx.craft_obj->h2_pending_[2] = std::move(entry);

        fx.craft_obj->handle_connect(2);
        runner.Check(!fx.craft_obj->connect_resolved_, "handle_connect: invalid -> not resolved");
        runner.Check(!fx.craft_obj->h2_pending_[2].connecting, "handle_connect: invalid -> not connecting");
    }

    void TestHandleConnectFirstConnectPreservesHeaders(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.authority = "example.com:443";
        entry.headers.host = "example.com";
        entry.headers.stream_id = 3;
        fx.craft_obj->h2_pending_[3] = std::move(entry);

        fx.craft_obj->handle_connect(3);
        runner.Check(fx.craft_obj->connect_resolved_, "handle_connect: resolved with headers");
        runner.Check(fx.craft_obj->first_connect_.authority == "example.com:443",
                     "handle_connect: first_connect authority preserved");
    }

    // ─── on_begin_headers ─────────────────────────

    void TestOnBeginHeadersConnect(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 1;
        frame.headers.cat = NGHTTP2_HCAT_REQUEST;

        const char *name_str = ":method";
        const char *value_str = "CONNECT";
        auto *nv_name = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(name_str));
        auto *nv_value = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(value_str));
        nghttp2_nv nv[] = {{nv_name, nv_value, 7, 7, NGHTTP2_NV_FLAG_NONE}};
        frame.headers.nva = nv;
        frame.headers.nvlen = 1;

        auto rc = h2mux::craft::on_begin_headers(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_begin_headers: CONNECT returns 0");
        runner.Check(fx.craft_obj->h2_pending_.count(1) == 1, "on_begin_headers: pending created");
    }

    void TestOnBeginHeadersNonConnect(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 2;
        frame.headers.cat = NGHTTP2_HCAT_REQUEST;

        const char *name_str = ":method";
        const char *value_str = "GET";
        auto *nv_name = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(name_str));
        auto *nv_value = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(value_str));
        nghttp2_nv nv[] = {{nv_name, nv_value, 7, 3, NGHTTP2_NV_FLAG_NONE}};
        frame.headers.nva = nv;
        frame.headers.nvlen = 1;

        auto rc = h2mux::craft::on_begin_headers(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_begin_headers: GET returns 0");
        runner.Check(fx.craft_obj->h2_pending_.empty(), "on_begin_headers: GET -> no pending");
    }

    void TestOnBeginHeadersNonHeadersFrame(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_DATA;
        frame.hd.stream_id = 3;

        auto rc = h2mux::craft::on_begin_headers(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_begin_headers: DATA frame -> 0");
        runner.Check(fx.craft_obj->h2_pending_.empty(), "on_begin_headers: non-HEADERS -> no pending");
    }

    void TestOnBeginHeadersNonRequest(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 4;
        frame.headers.cat = NGHTTP2_HCAT_RESPONSE;

        auto rc = h2mux::craft::on_begin_headers(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_begin_headers: RESPONSE cat -> 0");
        runner.Check(fx.craft_obj->h2_pending_.empty(), "on_begin_headers: non-REQUEST -> no pending");
    }

    // ─── on_header ────────────────────────────────

    void TestOnHeaderAuthority(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 1;
        fx.craft_obj->h2_pending_[1] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 1;

        const char *name = ":authority";
        const char *value = "example.com:443";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 10, hvalue, 15, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: :authority -> 0");
        runner.Check(fx.craft_obj->h2_pending_[1].headers.authority == "example.com:443",
                     "on_header: authority set");
    }

    void TestOnHeaderHost(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 2;
        fx.craft_obj->h2_pending_[2] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 2;

        const char *name = "host";
        const char *value = "example.com";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 4, hvalue, 11, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: host -> 0");
        runner.Check(fx.craft_obj->h2_pending_[2].headers.host == "example.com",
                     "on_header: host set");
    }

    void TestOnHeaderHostCapitalized(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 3;
        fx.craft_obj->h2_pending_[3] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 3;

        const char *name = "Host";
        const char *value = "test.local";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 4, hvalue, 10, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: Host -> 0");
        runner.Check(fx.craft_obj->h2_pending_[3].headers.host == "test.local",
                     "on_header: Host set");
    }

    void TestOnHeaderUserAgent(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 4;
        fx.craft_obj->h2_pending_[4] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 4;

        const char *name = "user-agent";
        const char *value = "TestClient/1.0";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 10, hvalue, 14, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: user-agent -> 0");
        runner.Check(fx.craft_obj->h2_pending_[4].headers.user_agent == "TestClient/1.0",
                     "on_header: user_agent set");
    }

    void TestOnHeaderProxyAuth(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 5;
        fx.craft_obj->h2_pending_[5] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 5;

        const char *name = "proxy-authorization";
        const char *value = "Basic dGVzdDp0ZXN0";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 19, hvalue, 18, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: proxy-auth -> 0");
        runner.Check(fx.craft_obj->h2_pending_[5].headers.proxy_auth == "Basic dGVzdDp0ZXN0",
                     "on_header: proxy_auth set");
    }

    void TestOnHeaderUnknown(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 6;
        fx.craft_obj->h2_pending_[6] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 6;

        const char *name = "x-custom";
        const char *value = "value";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 8, hvalue, 5, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: unknown -> 0");
        runner.Check(fx.craft_obj->h2_pending_[6].headers.authority.empty(), "on_header: unknown -> no fields");
    }

    void TestOnHeaderNotInPending(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.stream_id = 99;

        const char *name = ":authority";
        const char *value = "test.com";
        auto *hname = reinterpret_cast<const std::uint8_t *>(name);
        auto *hvalue = reinterpret_cast<const std::uint8_t *>(value);

        auto rc = h2mux::craft::on_header(nullptr, &frame, hname, 9, hvalue, 8, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_header: not in pending -> 0");
    }

    // ─── on_frame_recv ────────────────────────────

    void TestOnFrameRecvNonHeaders(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_DATA;

        auto rc = h2mux::craft::on_frame_recv(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_frame_recv: DATA -> 0");
    }

    void TestOnFrameRecvNonRequest(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_HEADERS;
        frame.headers.cat = NGHTTP2_HCAT_HEADERS;

        auto rc = h2mux::craft::on_frame_recv(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_frame_recv: trailing headers -> 0");
    }

    void TestOnFrameRecvNotInPending(TestRunner &runner)
    {
        CraftFixture fx;
        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 99;
        frame.headers.cat = NGHTTP2_HCAT_REQUEST;

        auto rc = h2mux::craft::on_frame_recv(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_frame_recv: not in pending -> 0");
    }

    void TestOnFrameRecvTriggersConnect(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 7;
        fx.craft_obj->h2_pending_[7] = std::move(entry);

        nghttp2_frame frame;
        std::memset(&frame, 0, sizeof(frame));
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 7;
        frame.headers.cat = NGHTTP2_HCAT_REQUEST;

        auto rc = h2mux::craft::on_frame_recv(nullptr, &frame, fx.craft_obj.get());
        runner.Check(rc == 0, "on_frame_recv: triggers handle_connect -> 0");
        runner.Check(fx.craft_obj->connect_resolved_, "on_frame_recv: resolved after connect");
    }

    // ─── on_data ──────────────────────────────────

    void TestOnDataPendingStream(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();

        h2mux::h2_pending_entry entry;
        fx.craft_obj->h2_pending_[3] = std::move(entry);

        std::uint8_t data[] = {0x01, 0x02, 0x03};
        auto rc = h2mux::craft::on_data(nullptr, 0, 3, data, 3, fx.craft_obj.get());
        runner.Check(rc == 0, "on_data: pending stream -> 0");
    }

    void TestOnDataDuctNullPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();

        fx.craft_obj->ducts_[5]; // null shared_ptr

        std::uint8_t data[] = {0x01, 0x02};
        auto rc = h2mux::craft::on_data(nullptr, 0, 5, data, 2, fx.craft_obj.get());
        runner.Check(rc == 0, "on_data: duct null -> 0 (falls to RST)");
    }

    void TestOnDataParcelNullPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();

        fx.craft_obj->parcels_[7]; // null shared_ptr

        std::uint8_t data[] = {0x01, 0x02};
        auto rc = h2mux::craft::on_data(nullptr, 0, 7, data, 2, fx.craft_obj.get());
        runner.Check(rc == 0, "on_data: parcel null -> 0 (falls to RST)");
    }

    void TestOnDataUnknownStream(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->init_nghttp2();

        std::uint8_t data[] = {0x01};
        auto rc = h2mux::craft::on_data(nullptr, 0, 99, data, 1, fx.craft_obj.get());
        runner.Check(rc == 0, "on_data: unknown -> 0 (RST submitted)");
    }

    // ─── on_stream_close ──────────────────────────

    void TestOnStreamClosePending(TestRunner &runner)
    {
        CraftFixture fx;
        h2mux::h2_pending_entry entry;
        fx.craft_obj->h2_pending_[1] = std::move(entry);

        auto rc = h2mux::craft::on_stream_close(nullptr, 1, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_stream_close: returns 0");
        runner.Check(fx.craft_obj->h2_pending_.count(1) == 0, "on_stream_close: pending erased");
    }

    void TestOnStreamCloseDuctNullPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->ducts_[3]; // null shared_ptr

        auto rc = h2mux::craft::on_stream_close(nullptr, 3, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_stream_close: duct null -> 0");
        runner.Check(fx.craft_obj->ducts_.count(3) == 1, "on_stream_close: duct entry remains");
    }

    void TestOnStreamCloseParcelNullPtr(TestRunner &runner)
    {
        CraftFixture fx;
        fx.craft_obj->parcels_[4]; // null shared_ptr

        auto rc = h2mux::craft::on_stream_close(nullptr, 4, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_stream_close: parcel null -> 0");
        runner.Check(fx.craft_obj->parcels_.count(4) == 1, "on_stream_close: parcel entry remains");
    }

    void TestOnStreamCloseNoEntries(TestRunner &runner)
    {
        CraftFixture fx;
        auto rc = h2mux::craft::on_stream_close(nullptr, 999, 0, fx.craft_obj.get());
        runner.Check(rc == 0, "on_stream_close: no entries -> 0");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("H2muxCraftDeep2");

    // init_nghttp2
    TestInitNghttp2Success(runner);

    // respond_connect
    TestRespondConnect200(runner);
    TestRespondConnect407(runner);
    TestRespondConnectOtherStatus(runner);

    // handle_connect
    TestHandleConnectNotFound(runner);
    TestHandleConnectFirstConnect(runner);
    TestHandleConnectInvalidInfo(runner);
    TestHandleConnectFirstConnectPreservesHeaders(runner);

    // on_begin_headers
    TestOnBeginHeadersConnect(runner);
    TestOnBeginHeadersNonConnect(runner);
    TestOnBeginHeadersNonHeadersFrame(runner);
    TestOnBeginHeadersNonRequest(runner);

    // on_header
    TestOnHeaderAuthority(runner);
    TestOnHeaderHost(runner);
    TestOnHeaderHostCapitalized(runner);
    TestOnHeaderUserAgent(runner);
    TestOnHeaderProxyAuth(runner);
    TestOnHeaderUnknown(runner);
    TestOnHeaderNotInPending(runner);

    // on_frame_recv
    TestOnFrameRecvNonHeaders(runner);
    TestOnFrameRecvNonRequest(runner);
    TestOnFrameRecvNotInPending(runner);
    TestOnFrameRecvTriggersConnect(runner);

    // on_data
    TestOnDataPendingStream(runner);
    TestOnDataDuctNullPtr(runner);
    TestOnDataParcelNullPtr(runner);
    TestOnDataUnknownStream(runner);

    // on_stream_close
    TestOnStreamClosePending(runner);
    TestOnStreamCloseDuctNullPtr(runner);
    TestOnStreamCloseParcelNullPtr(runner);
    TestOnStreamCloseNoEntries(runner);

    return runner.Summary();
}
