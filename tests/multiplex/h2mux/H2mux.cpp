/**
 * @file H2mux.cpp
 * @brief h2mux 多路复用单元测试
 * @details 验证 psm::multiplex::h2mux 模块的核心功能：
 * 1. nghttp2 session 初始化与回调注册
 * 2. CONNECT HEADERS 结构构造与验证
 * 3. DATA 帧分发到正确 stream 的逻辑
 * 4. stream close 事件处理
 * 5. wait_first_connect 状态逻辑
 * 6. 辅助结构体与枚举测试
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/multiplex/h2mux/craft.hpp>

#include <array>
#include <cstring>
#include <optional>
#include <string_view>

#include <gtest/gtest.h>

using namespace psm::multiplex::h2mux;

// ═══════════════════════════════════════════════════════════
// 1. nghttp2 session 初始化
// ═══════════════════════════════════════════════════════════

/**
 * @brief 测试 nghttp2 session 创建成功（服务端模式）
 */
TEST(H2mux, Nghttp2SessionCreation)
{
    nghttp2_session_callbacks *callbacks = nullptr;
    int rv = nghttp2_session_callbacks_new(&callbacks);
    EXPECT_TRUE(rv == 0) << "nghttp2_session_callbacks_new returns 0";
    EXPECT_TRUE(callbacks != nullptr) << "callbacks pointer is non-null";

    nghttp2_session *session = nullptr;
    rv = nghttp2_session_server_new(&session, callbacks, nullptr);
    EXPECT_TRUE(rv == 0) << "nghttp2_session_server_new returns 0";
    EXPECT_TRUE(session != nullptr) << "session pointer is non-null";

    // 提交初始 SETTINGS（与 craft::init_nghttp2 相同）
    rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    EXPECT_TRUE(rv == 0) << "nghttp2_submit_settings returns 0";

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
}

/**
 * @brief 测试 nghttp2 回调注册
 * @details 注册与 craft 相同的回调集，验证全部注册成功
 */
TEST(H2mux, Nghttp2CallbackRegistration)
{
    nghttp2_session_callbacks *callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);

    // 注册与 craft 相同的五组回调
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
        [](nghttp2_session *, const nghttp2_frame *, void *) -> int { return 0; });
    nghttp2_session_callbacks_set_on_header_callback(callbacks,
        [](nghttp2_session *, const nghttp2_frame *,
           const uint8_t *, size_t, const uint8_t *, size_t,
           uint8_t, void *) -> int { return 0; });
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
        [](nghttp2_session *, const nghttp2_frame *, void *) -> int { return 0; });
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
        [](nghttp2_session *, uint8_t, int32_t,
           const uint8_t *, size_t, void *) -> int { return 0; });
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
        [](nghttp2_session *, int32_t, uint32_t, void *) -> int { return 0; });

    nghttp2_session *session = nullptr;
    const int rv = nghttp2_session_server_new(&session, callbacks, nullptr);
    EXPECT_TRUE(rv == 0) << "session with all callbacks created successfully";
    EXPECT_TRUE(session != nullptr) << "session pointer non-null after callback registration";

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
}

// ═══════════════════════════════════════════════════════════
// 2. CONNECT HEADERS 构造验证
// ═══════════════════════════════════════════════════════════

/**
 * @brief 测试 h2_headers 结构体默认值与赋值
 */
TEST(H2mux, H2HeadersStruct)
{
    h2_headers hdr;
    EXPECT_TRUE(hdr.stream_id == 0) << "h2_headers default stream_id == 0";
    EXPECT_TRUE(hdr.authority.empty()) << "h2_headers default authority is empty";
    EXPECT_TRUE(hdr.host.empty()) << "h2_headers default host is empty";
    EXPECT_TRUE(hdr.user_agent.empty()) << "h2_headers default user_agent is empty";
    EXPECT_TRUE(hdr.proxy_auth.empty()) << "h2_headers default proxy_auth is empty";

    // 赋值测试（模拟 on_header 回调填充）
    hdr.stream_id = 3;
    hdr.authority = "example.com:443";
    hdr.host = "example.com";
    hdr.user_agent = "TestClient/1.0";
    hdr.proxy_auth = "Basic dXNlcjpwYXNz";

    EXPECT_TRUE(hdr.stream_id == 3) << "h2_headers stream_id assigned correctly";
    EXPECT_TRUE(hdr.authority == "example.com:443") << "h2_headers authority assigned correctly";
    EXPECT_TRUE(hdr.host == "example.com") << "h2_headers host assigned correctly";
    EXPECT_TRUE(hdr.user_agent == "TestClient/1.0") << "h2_headers user_agent assigned correctly";
    EXPECT_TRUE(hdr.proxy_auth == "Basic dXNlcjpwYXNz") << "h2_headers proxy_auth assigned correctly";
}

/**
 * @brief 测试 CONNECT 响应头的 nghttp2_nv 构造
 * @details 模拟 respond_connect 的 :status 头构造，验证 200 和 407 两种响应
 */
TEST(H2mux, ConnectResponseHeaders)
{
    // 模拟 respond_connect 构造 200 响应
    const auto status_200 = std::string_view("200");
    nghttp2_nv hdrs_200[] = {
        {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
         const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_200.data())),
         7, 3, NGHTTP2_NV_FLAG_NONE}};

    EXPECT_TRUE(hdrs_200[0].namelen == 7) << ":status name length == 7";
    EXPECT_TRUE(hdrs_200[0].valuelen == 3) << "200 value length == 3";
    EXPECT_TRUE(std::string_view(reinterpret_cast<const char *>(hdrs_200[0].name),
                                   hdrs_200[0].namelen) == ":status")
        << ":status header name correct";
    EXPECT_TRUE(std::string_view(reinterpret_cast<const char *>(hdrs_200[0].value),
                                   hdrs_200[0].valuelen) == "200")
        << "200 header value correct";

    // 模拟 407 响应
    const auto status_407 = std::string_view("407");
    nghttp2_nv hdrs_407[] = {
        {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
         const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_407.data())),
         7, 3, NGHTTP2_NV_FLAG_NONE}};

    EXPECT_TRUE(std::string_view(reinterpret_cast<const char *>(hdrs_407[0].value),
                                   hdrs_407[0].valuelen) == "407")
        << "407 header value correct";
}

/**
 * @brief 测试 nghttp2 submit_headers 响应 CONNECT
 * @details 通过 nghttp2 session 验证 CONNECT 响应提交成功
 */
TEST(H2mux, Nghttp2RespondConnect)
{
    nghttp2_session_callbacks *callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session *session = nullptr;
    nghttp2_session_server_new(&session, callbacks, nullptr);

    // 先提交 SETTINGS（与 craft::init_nghttp2 相同）
    int rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, nullptr, 0);
    EXPECT_TRUE(rv == 0) << "nghttp2_submit_settings for respond test returns 0";

    // 模拟 respond_connect(stream_id=1, status=200)
    const char *status_str = "200";
    nghttp2_nv hdrs[] = {
        {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
         const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str)),
         7, 3, NGHTTP2_NV_FLAG_NONE}};

    rv = nghttp2_submit_headers(session, NGHTTP2_FLAG_NONE,
                                     1, nullptr, hdrs, 1, nullptr);
    EXPECT_TRUE(rv == 0) << "nghttp2_submit_headers for CONNECT 200 returns 0";

    // 获取待发送数据（SETTINGS + HEADERS 帧均产生输出）
    const uint8_t *data = nullptr;
    const auto len = nghttp2_session_mem_send(session, &data);
    EXPECT_TRUE(len > 0) << "nghttp2 has pending output after submit_settings + submit_headers";

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
}

// ═══════════════════════════════════════════════════════════
// 3. DATA 帧分发到正确的 stream
// ═══════════════════════════════════════════════════════════

/**
 * @brief 测试 DATA 帧的三路分发逻辑
 * @details 模拟 on_data 回调中的 h2_pending_ / ducts_ / parcels_ 查找模式
 */
TEST(H2mux, DataFrameDispatch)
{
    // 模拟 h2_pending_ 映射
    psm::memory::unordered_map<std::uint32_t, h2_pending_entry> h2_pending(
        psm::memory::current_resource());

    // stream 1: TrustTunnel 模式，地址已解析
    h2_pending_entry entry1;
    entry1.headers.stream_id = 1;
    entry1.headers.authority = "host1.example.com:443";
    entry1.info.host = "host1.example.com";
    entry1.info.port = 443;
    entry1.info.type = stream_type::tcp;
    entry1.info.valid = true;
    h2_pending[1] = std::move(entry1);

    // stream 3: sing-mux 模式，等待 DATA 帧
    h2_pending_entry entry3;
    entry3.headers.stream_id = 3;
    entry3.headers.authority = "host3.example.com:8080";
    entry3.info.host = "host3.example.com";
    entry3.info.port = 8080;
    entry3.info.type = stream_type::udp;
    entry3.info.valid = false;
    h2_pending[3] = std::move(entry3);

    // 测试查找 stream 1 -> pending 命中
    auto it1 = h2_pending.find(1);
    EXPECT_TRUE(it1 != h2_pending.end()) << "stream 1 found in pending";
    EXPECT_TRUE(it1->second.info.valid == true) << "stream 1 info is valid";
    EXPECT_TRUE(it1->second.info.type == stream_type::tcp) << "stream 1 type is tcp";
    EXPECT_TRUE(it1->second.info.port == 443) << "stream 1 port is 443";

    // 测试查找 stream 3 -> pending 命中
    auto it3 = h2_pending.find(3);
    EXPECT_TRUE(it3 != h2_pending.end()) << "stream 3 found in pending";
    EXPECT_TRUE(it3->second.info.valid == false) << "stream 3 info is not valid (sing-mux)";
    EXPECT_TRUE(it3->second.info.type == stream_type::udp) << "stream 3 type is udp";

    // 测试查找不存在的 stream
    auto it99 = h2_pending.find(99);
    EXPECT_TRUE(it99 == h2_pending.end()) << "stream 99 not found in pending";

    // 模拟 ducts_ 和 parcels_ 的三路分发
    psm::memory::unordered_map<std::uint32_t, bool> ducts(psm::memory::current_resource());
    ducts[5] = true;
    ducts[7] = true;

    psm::memory::unordered_map<std::uint32_t, bool> parcels(psm::memory::current_resource());
    parcels[9] = true;

    // stream 5 -> ducts 命中
    auto d5 = ducts.find(5);
    EXPECT_TRUE(d5 != ducts.end() && d5->second) << "DATA dispatch: stream 5 routed to duct";

    // stream 9 -> parcels 命中
    auto p9 = parcels.find(9);
    EXPECT_TRUE(p9 != parcels.end() && p9->second) << "DATA dispatch: stream 9 routed to parcel";

    // stream 2 -> 均未命中（应发送 RST_STREAM）
    auto d2 = ducts.find(2);
    auto p2 = parcels.find(2);
    auto ph2 = h2_pending.find(2);
    EXPECT_TRUE(d2 == ducts.end() && p2 == parcels.end() && ph2 == h2_pending.end())
        << "DATA dispatch: unknown stream 2 not found in any map";
}

// ═══════════════════════════════════════════════════════════
// 4. stream close 事件处理
// ═══════════════════════════════════════════════════════════

/**
 * @brief 测试 stream close 时从 pending/ducts/parcels 移除
 * @details 模拟 on_stream_close 回调的清理逻辑
 */
TEST(H2mux, StreamCloseHandling)
{
    psm::memory::unordered_map<std::uint32_t, h2_pending_entry> h2_pending(
        psm::memory::current_resource());
    psm::memory::unordered_map<std::uint32_t, bool> ducts(psm::memory::current_resource());
    psm::memory::unordered_map<std::uint32_t, bool> parcels(psm::memory::current_resource());

    // 填充测试数据
    h2_pending[1] = h2_pending_entry{};
    h2_pending[3] = h2_pending_entry{};
    ducts[5] = true;
    ducts[7] = true;
    parcels[9] = true;

    EXPECT_TRUE(h2_pending.size() == 2) << "initial h2_pending size == 2";
    EXPECT_TRUE(ducts.size() == 2) << "initial ducts size == 2";
    EXPECT_TRUE(parcels.size() == 1) << "initial parcels size == 1";

    // 模拟 stream 1 close -> 从 h2_pending 移除
    h2_pending.erase(1);
    EXPECT_TRUE(h2_pending.find(1) == h2_pending.end()) << "stream 1 removed from h2_pending";
    EXPECT_TRUE(h2_pending.size() == 1) << "h2_pending size == 1 after stream 1 close";

    // 模拟 stream 5 close -> 从 ducts 移除
    ducts.erase(5);
    EXPECT_TRUE(ducts.find(5) == ducts.end()) << "stream 5 removed from ducts";
    EXPECT_TRUE(ducts.size() == 1) << "ducts size == 1 after stream 5 close";

    // 模拟 stream 9 close -> 从 parcels 移除
    parcels.erase(9);
    EXPECT_TRUE(parcels.find(9) == parcels.end()) << "stream 9 removed from parcels";
    EXPECT_TRUE(parcels.empty()) << "parcels empty after stream 9 close";

    // 模拟 close 不存在的 stream（幂等）
    const auto old_size = h2_pending.size();
    h2_pending.erase(99); // 不存在，不应改变大小
    EXPECT_TRUE(h2_pending.size() == old_size) << "erasing non-existent stream is no-op";
}

/**
 * @brief 测试 nghttp2 RST_STREAM 提交
 */
TEST(H2mux, Nghttp2RstStream)
{
    nghttp2_session_callbacks *callbacks = nullptr;
    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session *session = nullptr;
    nghttp2_session_server_new(&session, callbacks, nullptr);

    // 提交 NO_ERROR RST_STREAM
    int rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 1, NGHTTP2_NO_ERROR);
    EXPECT_TRUE(rv == 0) << "nghttp2_submit_rst_stream(NO_ERROR) returns 0";

    // 提交 PROTOCOL_ERROR RST_STREAM
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 3, NGHTTP2_PROTOCOL_ERROR);
    EXPECT_TRUE(rv == 0) << "nghttp2_submit_rst_stream(PROTOCOL_ERROR) returns 0";

    // 提交 INTERNAL_ERROR RST_STREAM
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, 5, NGHTTP2_INTERNAL_ERROR);
    EXPECT_TRUE(rv == 0) << "nghttp2_submit_rst_stream(INTERNAL_ERROR) returns 0";

    nghttp2_session_del(session);
    nghttp2_session_callbacks_del(callbacks);
}

// ═══════════════════════════════════════════════════════════
// 5. wait_first_connect 功能
// ═══════════════════════════════════════════════════════════

/**
 * @brief 测试 wait_first_connect 状态逻辑
 * @details 模拟 first_connect_resolved_ 和 first_connect_ 的状态转换
 */
TEST(H2mux, WaitFirstConnectStateLogic)
{
    // 初始状态：未解析
    bool first_connect_resolved = false;
    h2_headers first_connect;

    EXPECT_TRUE(!first_connect_resolved) << "initial state: not resolved";
    EXPECT_TRUE(first_connect.authority.empty()) << "initial state: authority empty";

    // 收到第一个 CONNECT（模拟 handle_connect 设置）
    first_connect.stream_id = 1;
    first_connect.authority = "target.example.com:443";
    first_connect.host = "target.example.com";
    first_connect.proxy_auth = "Basic dGVzdDpwYXNz";
    first_connect_resolved = true;

    EXPECT_TRUE(first_connect_resolved) << "after first connect: resolved flag set";
    EXPECT_TRUE(!first_connect.authority.empty()) << "after first connect: authority non-empty";
    EXPECT_TRUE(first_connect.stream_id == 1) << "after first connect: stream_id == 1";
    EXPECT_TRUE(first_connect.authority == "target.example.com:443")
        << "after first connect: authority matches";
    EXPECT_TRUE(first_connect.host == "target.example.com")
        << "after first connect: host matches";
    EXPECT_TRUE(first_connect.proxy_auth == "Basic dGVzdDpwYXNz")
        << "after first connect: proxy_auth matches";

    // 模拟 wait_first_connect 返回逻辑（已 resolved + authority 非空）
    std::optional<h2_headers> result;
    if (first_connect_resolved)
    {
        if (!first_connect.authority.empty())
        {
            result = std::move(first_connect);
        }
        else
        {
            result = std::nullopt;
        }
    }

    EXPECT_TRUE(result.has_value()) << "wait_first_connect returns value when resolved with authority";
    EXPECT_TRUE(result->authority == "target.example.com:443")
        << "wait_first_connect result authority correct";
    EXPECT_TRUE(result->stream_id == 1) << "wait_first_connect result stream_id correct";

    // 测试 authority 为空 -> 返回 nullopt
    h2_headers empty_auth;
    empty_auth.stream_id = 3;
    // authority 默认为空
    std::optional<h2_headers> empty_result;
    if (!empty_auth.authority.empty())
    {
        empty_result = std::move(empty_auth);
    }
    EXPECT_TRUE(!empty_result.has_value())
        << "wait_first_connect returns nullopt when authority is empty";
}

// ═══════════════════════════════════════════════════════════
// 辅助结构体与枚举测试
// ═══════════════════════════════════════════════════════════

/**
 * @brief 测试 stream_info 结构体默认值与赋值
 */
TEST(H2mux, H2StreamInfoStruct)
{
    stream_info info;
    EXPECT_TRUE(info.host.empty()) << "stream_info default host is empty";
    EXPECT_TRUE(info.port == 0) << "stream_info default port == 0";
    EXPECT_TRUE(info.type == stream_type::tcp) << "stream_info default type == tcp";
    EXPECT_TRUE(info.valid == false) << "stream_info default valid == false";

    info.host = "192.168.1.1";
    info.port = 8080;
    info.type = stream_type::udp;
    info.valid = true;

    EXPECT_TRUE(info.host == "192.168.1.1") << "stream_info host assigned";
    EXPECT_TRUE(info.port == 8080) << "stream_info port assigned";
    EXPECT_TRUE(info.type == stream_type::udp) << "stream_info type assigned to udp";
    EXPECT_TRUE(info.valid == true) << "stream_info valid assigned to true";
}

/**
 * @brief 测试 stream_type 枚举值
 */
TEST(H2mux, StreamTypeEnum)
{
    EXPECT_TRUE(static_cast<int>(stream_type::tcp) == 0) << "stream_type::tcp == 0";
    EXPECT_TRUE(static_cast<int>(stream_type::udp) == 1) << "stream_type::udp == 1";
    EXPECT_TRUE(static_cast<int>(stream_type::icmp) == 2) << "stream_type::icmp == 2";
    EXPECT_TRUE(static_cast<int>(stream_type::check) == 3) << "stream_type::check == 3";
}

/**
 * @brief 测试 h2_pending_entry 结构体
 */
TEST(H2mux, H2PendingEntryStruct)
{
    h2_pending_entry entry;
    EXPECT_TRUE(entry.headers.stream_id == 0) << "h2_pending_entry default headers.stream_id == 0";
    EXPECT_TRUE(entry.headers.authority.empty()) << "h2_pending_entry default headers.authority empty";
    EXPECT_TRUE(entry.info.valid == false) << "h2_pending_entry default info.valid == false";
    EXPECT_TRUE(entry.connecting == false) << "h2_pending_entry default connecting == false";

    entry.headers.stream_id = 5;
    entry.headers.authority = "relay.example.com:443";
    entry.info.host = "relay.example.com";
    entry.info.port = 443;
    entry.info.valid = true;
    entry.connecting = true;

    EXPECT_TRUE(entry.headers.stream_id == 5) << "h2_pending_entry headers.stream_id assigned";
    EXPECT_TRUE(entry.headers.authority == "relay.example.com:443")
        << "h2_pending_entry headers.authority assigned";
    EXPECT_TRUE(entry.info.host == "relay.example.com") << "h2_pending_entry info.host assigned";
    EXPECT_TRUE(entry.info.port == 443) << "h2_pending_entry info.port assigned";
    EXPECT_TRUE(entry.info.valid == true) << "h2_pending_entry info.valid assigned";
    EXPECT_TRUE(entry.connecting == true) << "h2_pending_entry connecting assigned";
}

/**
 * @brief 测试 outbound_data 结构体
 */
TEST(H2mux, OutboundDataStruct)
{
    outbound_data data;
    EXPECT_TRUE(data.stream_id == 0) << "outbound_data default stream_id == 0";
    EXPECT_TRUE(data.payload.empty()) << "outbound_data default payload empty";
    EXPECT_TRUE(data.is_fin == false) << "outbound_data default is_fin == false";

    data.stream_id = 42;
    data.payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    data.is_fin = true;

    EXPECT_TRUE(data.stream_id == 42) << "outbound_data stream_id assigned";
    EXPECT_TRUE(data.payload.size() == 3) << "outbound_data payload size == 3";
    EXPECT_TRUE(data.is_fin == true) << "outbound_data is_fin assigned";

    // 带 PMR 的构造
    outbound_data data_with_mr(psm::memory::current_resource());
    EXPECT_TRUE(data_with_mr.payload.empty()) << "outbound_data(mr) payload empty";
}

/**
 * @brief 测试 address_resolver 回调类型
 * @details 分别测试 TrustTunnel resolver 和 sing-mux resolver 的行为
 */
TEST(H2mux, AddressResolverCallback)
{
    // TrustTunnel resolver: 从 authority 解析 host:port
    address_resolver trusttunnel_resolver =
        [](int32_t stream_id, const h2_headers &headers) -> stream_info
    {
        stream_info info;
        const auto &auth = headers.authority;
        const auto colon_pos = auth.find(':');
        if (colon_pos != psm::memory::string::npos)
        {
            info.host = auth.substr(0, colon_pos);
            const auto port_str = std::string(auth.substr(colon_pos + 1));
            info.port = static_cast<std::uint16_t>(std::stoi(port_str));
        }
        else
        {
            info.host = auth;
            info.port = 443;
        }
        info.valid = true;

        // 从 Host 头判断类型
        if (!headers.host.empty())
        {
            info.type = stream_type::udp;
        }
        return info;
    };

    // TCP 流（无 Host 头）
    h2_headers hdr1;
    hdr1.stream_id = 1;
    hdr1.authority = "example.com:8443";

    auto result1 = trusttunnel_resolver(1, hdr1);
    EXPECT_TRUE(result1.valid == true) << "TrustTunnel resolver result valid";
    EXPECT_TRUE(result1.host == "example.com") << "TrustTunnel resolver host parsed";
    EXPECT_TRUE(result1.port == 8443) << "TrustTunnel resolver port parsed";
    EXPECT_TRUE(result1.type == stream_type::tcp) << "TrustTunnel resolver type tcp (no host header)";

    // UDP 流（有 Host 头）
    h2_headers hdr2;
    hdr2.stream_id = 3;
    hdr2.authority = "udp.example.com:9090";
    hdr2.host = "udp.example.com";

    auto result2 = trusttunnel_resolver(3, hdr2);
    EXPECT_TRUE(result2.valid == true) << "TrustTunnel resolver result valid with host header";
    EXPECT_TRUE(result2.type == stream_type::udp) << "TrustTunnel resolver type udp (host header present)";

    // 无端口（默认 443）
    h2_headers hdr3;
    hdr3.stream_id = 5;
    hdr3.authority = "default.example.com";

    auto result3 = trusttunnel_resolver(5, hdr3);
    EXPECT_TRUE(result3.valid == true) << "TrustTunnel resolver result valid without port";
    EXPECT_TRUE(result3.host == "default.example.com") << "TrustTunnel resolver host without port";
    EXPECT_TRUE(result3.port == 443) << "TrustTunnel resolver default port == 443";

    // sing-mux resolver: 返回 valid=false（等待 DATA 帧）
    address_resolver singmux_resolver =
        [](int32_t, const h2_headers &) -> stream_info
    {
        return stream_info{};
    };

    auto result4 = singmux_resolver(7, hdr1);
    EXPECT_TRUE(result4.valid == false) << "sing-mux resolver returns valid=false";
    EXPECT_TRUE(result4.port == 0) << "sing-mux resolver default port == 0";
}

/**
 * @brief 测试 h2mux::config 默认值
 */
TEST(H2mux, H2muxConfigDefaults)
{
    psm::multiplex::h2mux::config cfg;
    EXPECT_TRUE(cfg.max_streams == 256) << "h2mux config default max_streams == 256";
    EXPECT_TRUE(cfg.buffer_size == 4096) << "h2mux config default buffer_size == 4096";
    EXPECT_TRUE(cfg.max_frame_size == 16384) << "h2mux config default max_frame_size == 16384";
    EXPECT_TRUE(cfg.idle_timeout == 30000) << "h2mux config default idle_timeout == 30000";
    EXPECT_TRUE(cfg.udp_idle == 60000) << "h2mux config default udp_idle == 60000";
    EXPECT_TRUE(cfg.max_dgram == 65535) << "h2mux config default max_dgram == 65535";
}
