#include <array>
#include <atomic>
#include <chrono>
#include <format>
#include <iostream>
#include <memory>
#include <string>
#include <prism/channel/connection/pool.hpp>
#include <prism/resolve/router.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/exception/network.hpp>
#include <prism/fault/code.hpp>
#include <prism/memory.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <trace/spdlog.hpp>
#ifdef WIN32
#include <windows.h>
#endif

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;
#include <prism/agent/config.hpp>
#include <prism/agent/context.hpp>
#include <prism/agent/account/directory.hpp>

namespace agent = psm::agent;

namespace
{
    void info(const std::string_view msg)
    {
        psm::trace::info("{}", msg);
    }
}

/**
 * @brief 鍥炴樉鏈嶅姟鍣?
 * @param acceptor 鐩戝惉 acceptor (鎸夊€间紶閫掍互鎺ョ鎵€鏈夋潈)
 * @note 鍥炴樉鏈嶅姟鍣ㄤ細鎸佺画鐩戝惉 acceptor锛岀洿鍒板彂鐢熼敊璇?
 */
net::awaitable<void> echo_server(tcp::acceptor acceptor)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    // 寰幆鎺ュ彈杩炴帴锛岄槻姝粎澶勭悊涓€涓繛鎺ュ悗閫€鍑猴紙濡傛灉娴嬭瘯鐢ㄤ緥鏈夊娆¤繛鎺ラ渶姹傦級
    // 浣嗘牴鎹師閫昏緫鍙帴鍙椾竴娆°€傚鏋滈渶瑕佹寔缁繍琛岋紝淇濇寔鍘熸牱鍗冲彲銆?
    // 鍘熼€昏緫鏄?accept 涓€娆°€?
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    std::array<char, 8192> buf{};
    while (true)
    {
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec || n == 0)
        {
            break;
        }
        co_await net::async_write(socket, net::buffer(buf.data(), n), token);
        if (ec)
        {
            break;
        }
    }
}

/**
 * @brief 浠ｇ悊鏈嶅姟鍣ㄦ帴鍙楄繛鎺?
 * @param acceptor 鐩戝惉 acceptor (鎸夊€间紶閫掍互鎺ョ鎵€鏈夋潈)
 * @param server_ctx 鏈嶅姟鍣ㄤ笂涓嬫枃
 * @param worker_ctx 宸ヤ綔绾跨▼涓婁笅鏂?
 * @note 浠ｇ悊鏈嶅姟鍣ㄤ細鎸佺画鐩戝惉 acceptor锛岀洿鍒板彂鐢熼敊璇?
 */
net::awaitable<void> proxy_accept_one(tcp::acceptor acceptor, agent::server_context &server_ctx,
                                      agent::worker_context &worker_ctx)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }
    auto inbound = psm::channel::transport::make_reliable(std::move(socket));

    agent::session::session_params params{server_ctx, worker_ctx, std::move(inbound)};
    auto session_ptr = agent::session::make_session(std::move(params));
    session_ptr->start();
}

/**
 * @brief 璇诲彇浠ｇ悊鏈嶅姟鍣ㄨ繛鎺ュ搷搴?
 * @param socket 杩炴帴 socket
 * @return std::string 鍝嶅簲瀛楃涓?
 * @note 鍝嶅簲瀛楃涓插繀椤诲寘鍚?"\r\n\r\n" 鎵嶈兘缁撴潫璇诲彇
 */
net::awaitable<std::string> read_proxy_connect_response(tcp::socket &socket)
{
    std::string response;
    response.reserve(256);
    std::array<char, 512> buf{};
    while (response.find("\r\n\r\n") == std::string::npos)
    {
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec)
        {
            throw psm::exception::security("proxy response read failed: " + ec.message());
        }
        if (n == 0)
        {
            throw psm::exception::security("proxy response eof");
        }
        response.append(buf.data(), n);
        if (response.size() > 8192)
        {
            throw psm::exception::security("proxy response too large");
        }
    }

    if (!response.starts_with("HTTP/1.1 200"))
    {
        throw psm::exception::network("proxy connect failed: " + response);
    }

    co_return response;
}

/**
 * @brief 鍙戦€佸彇娑堜俊鍙?
 * @param signal 鍙栨秷淇″彿
 * @param timeout 瓒呮椂鏃堕棿
 * @note 瓒呮椂鏃堕棿鍐呮湭鍙戦€佸彇娑堜俊鍙凤紝浼氳嚜鍔ㄥ彂閫佸彇娑堜俊鍙?
 */
net::awaitable<void> emit_cancel_after(std::shared_ptr<net::cancellation_signal> signal, const std::chrono::milliseconds timeout)
{ // 鑾峰彇褰撳墠鍗忕▼鐨?executor
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(timeout);

    boost::system::error_code ec;
    auto token = net::redirect_error(net::use_awaitable, ec);
    co_await timer.async_wait(token);
    if (!ec)
    {
        signal->emit(net::cancellation_type::all);
    }
}

/**
 * @brief 绛夊緟鐩村埌鏍囧織浣嶄负 true
 * @param flag 鏍囧織浣?
 * @param timeout 瓒呮椂鏃堕棿
 * @note 瓒呮椂鏃堕棿鍐呮湭鏍囧織浣嶄负 true锛屼細鎶涘嚭寮傚父
 */
net::awaitable<void> wait_until_true(std::shared_ptr<std::atomic_bool> flag, const std::chrono::milliseconds timeout)
{
    auto executor = co_await net::this_coro::executor;
    net::steady_timer timer(executor);

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!flag->load())
    {
        if (std::chrono::steady_clock::now() >= deadline)
        {
            throw psm::exception::network("timeout waiting for expected shutdown");
        }

        timer.expires_after(std::chrono::milliseconds(10));
        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await timer.async_wait(token);
        if (ec)
        {
            co_return;
        }
    }
}

/**
 * @brief 浠ｇ悊鏈嶅姟鍣ㄨ繛鎺?echo 鏈嶅姟鍣?
 * @param proxy_ep 浠ｇ悊鏈嶅姟鍣?endpoint
 * @param echo_ep echo 鏈嶅姟鍣?endpoint
 * @param tag 鏃ュ織鍓嶇紑
 * @note 浼氬彂閫?CONNECT 璇锋眰锛岀劧鍚庣瓑寰呭搷搴旓紝鏈€鍚庡彂閫?payload 骞剁瓑寰?echo
 */
net::awaitable<void> proxy_connect_client_echo(const tcp::endpoint proxy_ep, const tcp::endpoint echo_ep,
                                               const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    info(std::format("{} client: connected to proxy", tag));

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    echo_ep.address().to_string(), echo_ep.port(), echo_ep.address().to_string(), echo_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);
    info(std::format("{} client: sent CONNECT", tag));

    const std::string response = co_await read_proxy_connect_response(socket);
    const std::size_t eol = response.find("\r\n");
    const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
    info(std::format("{} client: CONNECT 鍝嶅簲 `{}`", tag, first_line));

    const std::string payload = "hello_forward_engine";
    co_await net::async_write(socket, net::buffer(payload), net::use_awaitable);
    info(std::format("{} client: sent payload, waiting for echo", tag));

    std::string echo;
    echo.resize(payload.size());
    std::size_t got = 0;
    while (got < payload.size())
    {
        got += co_await socket.async_read_some(net::buffer(echo.data() + got, payload.size() - got),
                                               net::use_awaitable);
    }

    if (echo != payload)
    {
        throw psm::exception::network("echo mismatch");
    }

    info(std::format("{} client: echo verified, closing connection", tag));

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

/**
 * @brief 绛夊緟 acceptor 鎺ュ彈杩炴帴鍚庯紝寤惰繜鍏抽棴 socket
 * @param acceptor acceptor (鎸夊€间紶閫掍互鎺ョ鎵€鏈夋潈)
 * @param delay 寤惰繜鏃堕棿
 * @note 瓒呮椂鏃堕棿鍐呮湭鍏抽棴 socket锛屼細鑷姩鍏抽棴 socket
 */
net::awaitable<void> upstream_close_after_accept(tcp::acceptor acceptor, const std::chrono::milliseconds delay)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(delay);
    boost::system::error_code wait_ec;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, wait_ec));

    boost::system::error_code close_ec;
    socket.shutdown(tcp::socket::shutdown_both, close_ec);
    socket.close(close_ec);
}

/**
 * @brief 绛夊緟 acceptor 鎺ュ彈杩炴帴鍚庯紝绛夊緟 peer 鍏抽棴杩炴帴
 * @param acceptor acceptor (鎸夊€间紶閫掍互鎺ョ鎵€鏈夋潈)
 * @param closed_flag 鏍囧織浣嶏紝peer 鍏抽棴杩炴帴鍚庝細璁剧疆涓?true
 * @param timeout 瓒呮椂鏃堕棿
 * @note 瓒呮椂鏃堕棿鍐呮湭鍏抽棴杩炴帴锛屼細鑷姩璁剧疆鏍囧織浣嶄负 true
 */
net::awaitable<void> upstream_wait_peer_close(tcp::acceptor acceptor, std::shared_ptr<std::atomic_bool> closed_flag,
                                              const std::chrono::milliseconds timeout)
{
    boost::system::error_code accept_ec;
    auto accept_token = net::redirect_error(net::use_awaitable, accept_ec);
    tcp::socket socket = co_await acceptor.async_accept(accept_token);
    if (accept_ec)
    {
        co_return;
    }

    auto timeout_signal = std::make_shared<net::cancellation_signal>();
    net::co_spawn(co_await net::this_coro::executor, emit_cancel_after(timeout_signal, timeout), net::detached);

    std::array<char, 1> buf{};
    boost::system::error_code ec;
    auto token = net::bind_cancellation_slot(timeout_signal->slot(), net::redirect_error(net::use_awaitable, ec));

    while (true)
    {
        ec.clear();
        const std::size_t n = co_await socket.async_read_some(net::buffer(buf), token);
        if (ec == net::error::operation_aborted)
        {
            co_return;
        }
        if (n == 0 || ec)
        {
            closed_flag->store(true);
            co_return;
        }
    }
}

/**
 * @brief 浠ｇ悊鏈嶅姟鍣ㄨ繛鎺?echo 鏈嶅姟鍣紝绛夊緟 peer 鍏抽棴杩炴帴
 * @param proxy_ep 浠ｇ悊鏈嶅姟鍣?endpoint
 * @param upstream_ep echo 鏈嶅姟鍣?endpoint
 * @param tag 鏃ュ織鍓嶇紑
 * @note 浼氬彂閫?CONNECT 璇锋眰锛岀劧鍚庣瓑寰呭搷搴旓紝鏈€鍚庣瓑寰?peer 鍏抽棴杩炴帴
 */
net::awaitable<void> proxy_connect_client_expect_close(const tcp::endpoint proxy_ep, const tcp::endpoint upstream_ep,
                                                       const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    info(std::format("{} client: 宸茶繛鎺ヤ唬鐞嗭紝鍑嗗绛夊緟浠ｇ悊涓诲姩鍏抽棴", tag));

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    upstream_ep.address().to_string(), upstream_ep.port(), upstream_ep.address().to_string(), upstream_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    const std::string response = co_await read_proxy_connect_response(socket);
    const std::size_t eol = response.find("\r\n");
    const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
    info(std::format("{} client: CONNECT 鍝嶅簲 `{}`", tag, first_line));

    auto timeout_signal = std::make_shared<net::cancellation_signal>();
    net::co_spawn(co_await net::this_coro::executor,
                  emit_cancel_after(timeout_signal, std::chrono::milliseconds(1500)),
                  net::detached);

    std::array<char, 1> one{};
    boost::system::error_code ec;
    auto token = net::bind_cancellation_slot(timeout_signal->slot(), net::redirect_error(net::use_awaitable, ec));
    const std::size_t n = co_await socket.async_read_some(net::buffer(one), token);

    if (ec == net::error::operation_aborted)
    {
        throw psm::exception::security("timeout waiting for proxy to close client");
    }

    if (!ec && n != 0)
    {
        throw psm::exception::security("expected close but received data");
    }

    info(std::format("{} client: 宸茶瀵熷埌浠ｇ悊鍏抽棴", tag));

    boost::system::error_code close_ec;
    socket.shutdown(tcp::socket::shutdown_both, close_ec);
    socket.close(close_ec);
}

/**
 * @brief 浠ｇ悊鏈嶅姟鍣ㄨ繛鎺?echo 鏈嶅姟鍣紝绛夊緟 peer 鍏抽棴杩炴帴鍚庯紝鍏抽棴 socket
 * @param proxy_ep 浠ｇ悊鏈嶅姟鍣?endpoint
 * @param upstream_ep echo 鏈嶅姟鍣?endpoint
 * @param tag 鏃ュ織鍓嶇紑
 * @note 浼氬彂閫?CONNECT 璇锋眰锛岀劧鍚庣瓑寰呭搷搴旓紝鏈€鍚庣瓑寰?peer 鍏抽棴杩炴帴鍚庯紝鍏抽棴 socket
 */
net::awaitable<void> proxy_connect_client_then_close(const tcp::endpoint proxy_ep, const tcp::endpoint upstream_ep,
                                                     const std::string_view tag)
{
    tcp::socket socket(co_await net::this_coro::executor);
    co_await socket.async_connect(proxy_ep, net::use_awaitable);
    info(std::format("{} client: connected to proxy, will close actively", tag));

    const std::string connect_request = std::format("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                                                    upstream_ep.address().to_string(), upstream_ep.port(), upstream_ep.address().to_string(), upstream_ep.port());

    co_await net::async_write(socket, net::buffer(connect_request), net::use_awaitable);

    const std::string response = co_await read_proxy_connect_response(socket);
    const std::size_t eol = response.find("\r\n");
    const std::string first_line = (eol == std::string::npos) ? response : response.substr(0, eol);
    info(std::format("{} client: CONNECT 鍝嶅簲 `{}`", tag, first_line));

    boost::system::error_code ec;
    socket.shutdown(tcp::socket::shutdown_both, ec);
    socket.close(ec);

    info(std::format("{} client: closed connection", tag));
}

/**
 * @brief 娴嬭瘯 echo 鏈嶅姟鍣?
 * @param server_ctx server_context
 * @param worker_ctx worker_context
 * @param tag 鏃ュ織鍓嶇紑
 * @note 浼氬惎鍔?echo 鏈嶅姟鍣ㄥ拰浠ｇ悊鏈嶅姟鍣紝鐒跺悗杩炴帴浠ｇ悊鏈嶅姟鍣紝鏈€鍚庡叧闂繛鎺?
 */
net::awaitable<void> run_case_echo(agent::server_context &server_ctx, agent::worker_context &worker_ctx,
                                   const std::string_view tag)
{
    info(std::format("{} === case: echo ===", tag));

    auto &ioc = worker_ctx.io_context;
    tcp::acceptor echo_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    const auto echo_ep = echo_acceptor.local_endpoint();
    const auto proxy_ep = proxy_acceptor.local_endpoint();

    net::co_spawn(ioc, echo_server(std::move(echo_acceptor)), net::detached);
    net::co_spawn(ioc, proxy_accept_one(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);
    co_await proxy_connect_client_echo(proxy_ep, echo_ep, tag);

    info(std::format("{} === case: echo done ===", tag));
}

/**
 * @brief 娴嬭瘯 echo 鏈嶅姟鍣紝褰撲笂娓稿叧闂繛鎺ュ悗锛屼唬鐞嗘湇鍔″櫒搴旇鍏抽棴瀹㈡埛绔繛鎺?
 * @param server_ctx server_context
 * @param worker_ctx worker_context
 * @param tag 鏃ュ織鍓嶇紑
 * @note 浼氬惎鍔?echo 鏈嶅姟鍣ㄥ拰浠ｇ悊鏈嶅姟鍣紝鐒跺悗杩炴帴浠ｇ悊鏈嶅姟鍣紝鏈€鍚庡叧闂繛鎺?
 */
net::awaitable<void> run_case_upstream_close_should_close_client(agent::server_context &server_ctx,
                                                                 agent::worker_context &worker_ctx, const std::string_view tag)
{
    info(std::format("{} === case: upstream_close_should_close_client ===", tag));

    auto &ioc = worker_ctx.io_context;
    tcp::acceptor upstream_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    const auto upstream_ep = upstream_acceptor.local_endpoint();
    const auto proxy_ep = proxy_acceptor.local_endpoint();

    net::co_spawn(ioc, upstream_close_after_accept(std::move(upstream_acceptor), std::chrono::milliseconds(50)), net::detached);
    net::co_spawn(ioc, proxy_accept_one(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

    co_await proxy_connect_client_expect_close(proxy_ep, upstream_ep, tag);

    info(std::format("{} === case: upstream_close_should_close_client done ===", tag));
}

/**
 * @brief 娴嬭瘯 echo 鏈嶅姟鍣紝褰撳鎴风鍏抽棴杩炴帴鍚庯紝浠ｇ悊鏈嶅姟鍣ㄥ簲璇ュ叧闂笂娓歌繛鎺?
 * @param server_ctx server_context
 * @param worker_ctx worker_context
 * @param tag 鏃ュ織鍓嶇紑
 * @note 浼氬惎鍔?echo 鏈嶅姟鍣ㄥ拰浠ｇ悊鏈嶅姟鍣紝鐒跺悗杩炴帴浠ｇ悊鏈嶅姟鍣紝鏈€鍚庡叧闂繛鎺?
 */
net::awaitable<void> run_case_client_close_should_close_upstream(agent::server_context &server_ctx,
                                                                 agent::worker_context &worker_ctx, const std::string_view tag)
{
    info(std::format("{} === case: client_close_should_close_upstream ===", tag));

    auto &ioc = worker_ctx.io_context;
    tcp::acceptor upstream_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    tcp::acceptor proxy_acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));

    const auto upstream_ep = upstream_acceptor.local_endpoint();
    const auto proxy_ep = proxy_acceptor.local_endpoint();

    constexpr auto EXPECTED_SHUTDOWN_TIMEOUT = std::chrono::milliseconds(1500);
    auto upstream_closed = std::make_shared<std::atomic_bool>(false);

    net::co_spawn(ioc, upstream_wait_peer_close(std::move(upstream_acceptor), upstream_closed, EXPECTED_SHUTDOWN_TIMEOUT),
                  net::detached);
    net::co_spawn(ioc, proxy_accept_one(std::move(proxy_acceptor), server_ctx, worker_ctx), net::detached);

    co_await proxy_connect_client_then_close(proxy_ep, upstream_ep, tag);
    co_await wait_until_true(upstream_closed, EXPECTED_SHUTDOWN_TIMEOUT);

    info(std::format("{} === case: client_close_should_close_upstream done ===", tag));
}

net::awaitable<void> run_all_tests(agent::server_context &server_ctx, agent::worker_context &worker_ctx,
                                   const std::string_view tag)
{
    co_await run_case_echo(server_ctx, worker_ctx, tag);
    co_await run_case_upstream_close_should_close_client(server_ctx, worker_ctx, tag);
    co_await run_case_client_close_should_close_upstream(server_ctx, worker_ctx, tag);

    // 缁欏垎绂荤殑 session 鍗忕▼涓€鐐规椂闂磋繘琛屾竻鐞嗗拰鑷垜閿€姣侊紝闃叉 ioc.stop() 瀵艰嚧鐨勬瀽鏋勭珵鎬佸穿婧?
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(std::chrono::milliseconds(200));
    co_await timer.async_wait(net::use_awaitable);
}

int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    try
    {
        psm::memory::system::enable_global_pooling();
        {
            psm::trace::config cfg;
            cfg.path_name = (std::filesystem::path("test_logs") / "session").string();
            cfg.file_name = "session_test.log";
            cfg.max_size = 4U * 1024U * 1024U;
            cfg.max_files = 2U;
            cfg.queue_size = 8192U;
            cfg.thread_count = 1U;
            cfg.enable_console = true;
            cfg.enable_file = false;
            cfg.log_level = "debug";
            cfg.trace_name = "session_test";
            psm::trace::init(cfg);
        }

        // 1. ioc 蹇呴』鏈€鍏堝０鏄庯紙鏈€鍚庢瀽鏋勶級
        // 纭繚 socket/pool/dist 鏋愭瀯鏃?ioc 浠嶇劧鏈夋晥
        const auto ioc_ptr = std::make_unique<net::io_context>();
        auto &ioc = *ioc_ptr;

        // 2. 渚濊禆璧勬簮澹版槑锛堝湪 ioc 涔嬪悗锛屽厛鏋愭瀯锛?

        // 鍒濆鍖?
        const auto pool = std::make_unique<psm::channel::connection_pool>(ioc);
        psm::resolve::config dns_cfg;
        auto dist = std::make_unique<psm::resolve::router>(*pool, ioc, std::move(dns_cfg));

        auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12);
        ssl_ctx->set_verify_mode(ssl::verify_none);

        agent::config cfg;
        auto account_store = std::make_shared<agent::account::directory>(psm::memory::system::global_pool());
        agent::server_context server_ctx{cfg, ssl_ctx, account_store};

        auto mr = psm::memory::system::thread_local_pool();
        agent::worker_context worker_ctx{ioc, *dist, mr};

        // 娉ㄥ唽鍗忚澶勭悊鍣?
        // 娉ㄦ剰锛氳繖閲岀殑 arena 浠呯敤浜?handler 鏋勯€狅紝瀹為檯澶勭悊鏃朵細浣跨敤 session 鐨?arena
        // 浣嗙敱浜?handler 宸ュ巶璁捐闂锛屾垜浠渶瑕佹彁渚涗竴涓复鏃剁殑 arena
        // 蹇呴』淇濊瘉 arena 鍦ㄦ祴璇曟湡闂村瓨娲?
        psm::memory::frame_arena dummy_arena;
        // frame_arena 榛樿鏋勯€犱娇鐢?thread_local_pool锛屼笉闇€瑕?mr 鍙傛暟
        // 涔嬪墠鐨?mr 鍙橀噺鍏跺疄娌＄敤锛宖rame_arena 鍐呴儴鑷繁鑾峰彇


        std::exception_ptr test_error;

        {
            auto function = [&server_ctx, &worker_ctx]() -> net::awaitable<void>
            {
                info("session_test: start");
                co_await run_all_tests(server_ctx, worker_ctx, "session_test");
                info("session_test: done");
            };

            auto token = [&ioc, &test_error](const std::exception_ptr &ep)
            {
                test_error = ep;
                ioc.stop();
            };
            net::co_spawn(ioc, function(), token);

            ioc.run();
        }

        if (test_error)
        {
            std::rethrow_exception(test_error);
        }

        psm::trace::shutdown();
    }
    catch (const std::exception &e)
    {
        psm::trace::shutdown();
        std::cerr << std::format("session_test failed: {}", e.what()) << std::endl;
        return 1;
    }

    std::cout << "session_test passed" << std::endl;
    return 0;
}


