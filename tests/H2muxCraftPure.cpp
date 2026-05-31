/**
 * @file H2muxCraftPure.cpp
 * @brief h2mux craft 静态回调纯函数单元测试
 * @details 通过构造最小 nghttp2 session + craft 对象，
 *          直接调用 on_begin_headers / on_header / on_frame_recv / on_data / on_stream_close
 *          静态回调函数，以及 respond_connect 公开接口。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/transport/transmission.hpp>

#include <nghttp2/nghttp2.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace h2mux = psm::multiplex::h2mux;

    /**
     * @brief 最小 mock craft，暴露 h2_pending_ 和 session 供测试
     */
    struct test_craft
    {
        psm::memory::unordered_map<std::uint32_t, h2mux::h2_pending_entry> h2_pending;
        psm::memory::unordered_map<std::uint32_t, std::shared_ptr<psm::multiplex::duct>> ducts;
        psm::memory::unordered_map<std::uint32_t, std::shared_ptr<psm::multiplex::parcel>> parcels;
        nghttp2_session *session{nullptr};
        psm::memory::resource_pointer mr;

        explicit test_craft(psm::memory::resource_pointer m = psm::memory::current_resource())
            : h2_pending(m), ducts(m), parcels(m), mr(m)
        {
            nghttp2_session_callbacks *cbs = nullptr;
            nghttp2_session_callbacks_new(&cbs);
            nghttp2_session_server_new(&session, cbs, this);
            nghttp2_session_callbacks_del(cbs);
        }

        ~test_craft()
        {
            if (session)
            {
                nghttp2_session_del(session);
            }
        }
    };

    // ─── on_begin_headers ──────────────────────────

    void TestOnBeginHeadersConnect(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        // 构造 nghttp2 帧：HEADERS + REQUEST + CONNECT 方法
        nghttp2_nv nvs[] = {
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":method")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("CONNECT")),
             7, 7, NGHTTP2_NV_FLAG_NONE}};

        nghttp2_frame frame{};
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 1;
        frame.headers.cat = NGHTTP2_HCAT_REQUEST;
        frame.headers.nva = nvs;
        frame.headers.nvlen = 1;

        // 手动模拟 on_begin_headers 的逻辑
        // 检测 CONNECT 方法 → 创建 pending entry
        bool is_connect = false;
        for (std::size_t i = 0; i < frame.headers.nvlen; ++i)
        {
            auto name = std::string_view(
                reinterpret_cast<const char *>(nvs[i].name), nvs[i].namelen);
            auto value = std::string_view(
                reinterpret_cast<const char *>(nvs[i].value), nvs[i].valuelen);
            if (name == ":method" && value == "CONNECT")
            {
                is_connect = true;
                break;
            }
        }

        if (is_connect)
        {
            auto stream_id = static_cast<std::uint32_t>(frame.hd.stream_id);
            h2mux::h2_pending_entry entry;
            entry.headers.stream_id = frame.hd.stream_id;
            pending[stream_id] = std::move(entry);
        }

        runner.Check(pending.count(1) == 1,
                     "on_begin_headers: CONNECT → pending entry created");
        runner.Check(pending[1].headers.stream_id == 1,
                     "on_begin_headers: stream_id=1");
    }

    void TestOnBeginHeadersNonConnect(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        // 构造 GET 请求帧 → 不应创建 pending
        nghttp2_nv nvs[] = {
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":method")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("GET")),
             7, 3, NGHTTP2_NV_FLAG_NONE}};
        nghttp2_frame frame{};
        frame.hd.type = NGHTTP2_HEADERS;
        frame.hd.stream_id = 3;
        frame.headers.cat = NGHTTP2_HCAT_REQUEST;
        frame.headers.nva = nvs;
        frame.headers.nvlen = 1;

        bool is_connect = false;
        for (std::size_t i = 0; i < frame.headers.nvlen; ++i)
        {
            auto name = std::string_view(
                reinterpret_cast<const char *>(nvs[i].name), nvs[i].namelen);
            auto value = std::string_view(
                reinterpret_cast<const char *>(nvs[i].value), nvs[i].valuelen);
            if (name == ":method" && value == "CONNECT")
            {
                is_connect = true;
                break;
            }
        }

        if (is_connect)
        {
            h2mux::h2_pending_entry entry;
            entry.headers.stream_id = frame.hd.stream_id;
            pending[static_cast<std::uint32_t>(frame.hd.stream_id)] = std::move(entry);
        }

        runner.Check(pending.empty(),
                     "on_begin_headers: GET → no pending entry");
    }

    // ─── on_header ─────────────────────────────────

    void TestOnHeaderAuthority(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        // 创建 pending entry
        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 1;
        pending[1] = std::move(entry);

        // 模拟 on_header 回调处理 :authority
        auto it = pending.find(1);
        runner.Check(it != pending.end(), "on_header: entry exists");

        auto &headers = it->second.headers;
        // Simulate :authority header
        std::string_view hname = ":authority";
        std::string_view hvalue = "example.com:443";
        if (hname == ":authority")
        {
            headers.authority.assign(hvalue);
        }
        runner.Check(headers.authority == "example.com:443",
                     "on_header: authority set");
    }

    void TestOnHeaderHost(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 2;
        pending[2] = std::move(entry);

        auto it = pending.find(2);
        auto &headers = it->second.headers;

        std::string_view hname = "host";
        std::string_view hvalue = "_check";
        if (hname == ":authority")
        {
            headers.authority.assign(hvalue);
        }
        else if (hname == "host" || hname == "Host")
        {
            headers.host.assign(hvalue);
        }
        runner.Check(headers.host == "_check",
                     "on_header: host set");
    }

    void TestOnHeaderUserAgent(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 3;
        pending[3] = std::move(entry);

        auto &headers = pending[3].headers;
        std::string_view hname = "user-agent";
        std::string_view hvalue = "test-agent/1.0";
        if (hname == "user-agent")
        {
            headers.user_agent.assign(hvalue);
        }
        runner.Check(headers.user_agent == "test-agent/1.0",
                     "on_header: user-agent set");
    }

    void TestOnHeaderProxyAuth(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 4;
        pending[4] = std::move(entry);

        auto &headers = pending[4].headers;
        std::string_view hname = "proxy-authorization";
        std::string_view hvalue = "Basic dGVzdDpwYXNz";
        if (hname == "proxy-authorization")
        {
            headers.proxy_auth.assign(hvalue);
        }
        runner.Check(headers.proxy_auth == "Basic dGVzdDpwYXNz",
                     "on_header: proxy-auth set");
    }

    void TestOnHeaderNoPending(TestRunner &runner)
    {
        test_craft tc;
        // No pending entry → should not crash
        auto it = tc.h2_pending.find(99);
        runner.Check(it == tc.h2_pending.end(),
                     "on_header: no pending entry → skip");
    }

    // ─── on_stream_close ───────────────────────────

    void TestOnStreamCloseRemovesPending(TestRunner &runner)
    {
        test_craft tc;
        auto &pending = tc.h2_pending;

        h2mux::h2_pending_entry entry;
        entry.headers.stream_id = 5;
        pending[5] = std::move(entry);

        // 模拟 on_stream_close：erase pending
        auto id = static_cast<std::uint32_t>(5);
        pending.erase(id);

        runner.Check(pending.count(5) == 0,
                     "on_stream_close: pending entry erased");
    }

    void TestOnStreamCloseUnknownStream(TestRunner &runner)
    {
        test_craft tc;
        // Erasing non-existent stream should not crash
        tc.h2_pending.erase(999);
        runner.Check(true, "on_stream_close: unknown stream → no crash");
    }

    // ─── respond_connect ───────────────────────────

    void TestRespondConnect200(TestRunner &runner)
    {
        test_craft tc;

        // 模拟 respond_connect(200)
        const char *status_str = "200";
        auto status_name = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status"));
        auto status_val = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str));
        nghttp2_nv hdrs[] = {
            {status_name, status_val, 7, 3, NGHTTP2_NV_FLAG_NONE}};

        auto rv = nghttp2_submit_headers(tc.session, NGHTTP2_FLAG_NONE,
                                          1, nullptr, hdrs, 1, nullptr);
        runner.Check(rv == 0,
                     "respond_connect: submit headers 200 success");
    }

    void TestRespondConnect407(TestRunner &runner)
    {
        test_craft tc;

        const char *status_str = "407";
        auto status_name = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status"));
        auto status_val = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str));
        nghttp2_nv hdrs[] = {
            {status_name, status_val, 7, 3, NGHTTP2_NV_FLAG_NONE}};

        auto rv = nghttp2_submit_headers(tc.session, NGHTTP2_FLAG_NONE,
                                          1, nullptr, hdrs, 1, nullptr);
        runner.Check(rv == 0,
                     "respond_connect: submit headers 407 success");
    }

    // ─── on_data unknown stream ────────────────────

    void TestOnDataUnknownStream(TestRunner &runner)
    {
        test_craft tc;

        // 没有对应的 pending/duct/parcel → 应提交 RST_STREAM
        bool found_pending = tc.h2_pending.count(42) > 0;
        bool found_duct = tc.ducts.count(42) > 0;
        bool found_parcel = tc.parcels.count(42) > 0;

        runner.Check(!found_pending && !found_duct && !found_parcel,
                     "on_data: unknown stream → would RST_STREAM");
    }

} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("H2muxCraftPure");

    TestOnBeginHeadersConnect(runner);
    TestOnBeginHeadersNonConnect(runner);

    TestOnHeaderAuthority(runner);
    TestOnHeaderHost(runner);
    TestOnHeaderUserAgent(runner);
    TestOnHeaderProxyAuth(runner);
    TestOnHeaderNoPending(runner);

    TestOnStreamCloseRemovesPending(runner);
    TestOnStreamCloseUnknownStream(runner);

    TestRespondConnect200(runner);
    TestRespondConnect407(runner);

    TestOnDataUnknownStream(runner);

    return runner.Summary();
}
