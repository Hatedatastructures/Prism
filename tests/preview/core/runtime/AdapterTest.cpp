/**
 * @file AdapterTest.cpp
 * @brief adapter 接入缝专项测试（阶段 5 v2）
 * @details 覆盖：
 *          - make_protocol_accept 的 ctx 装配（target/identity/is_dgram/post_dial/inbound 替换）
 *          - 失败映射（bad_auth/not_supported/io_error/unexpected_eof/未知错误）
 *          - 全枚举黄金断言：fault::to_code 的 preview.protocol 分支映射稳定
 *          - 空传输兜底（无错误但无传输 → io_error）
 *          - session 分支：is_dgram 但未注册 udp_service → not_supported
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/fault/code.hpp>
#include <common/core/fault/handling.hpp>
#include <common/core/middleware/context.hpp>
#include <common/core/runtime/adapter/handler.hpp>
#include <common/core/runtime/adapter/protocol_adapter.hpp>
#include <common/core/runtime/session.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace preview;

    using psm::testing::run_coro; // 公共样板（见 <common/RuntimeTestHelpers.hpp>）

    /// 可识别首包（socks5 greeting）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<memory_stream>, std::shared_ptr<memory_stream>>
    {
        auto [a, b] = make_memory_pair(ioc.get_executor());
        return {std::make_shared<memory_stream>(std::move(a)),
                std::make_shared<memory_stream>(std::move(b))};
    }

    /// 桩协议处理器：按预设结果返回
    class stub_handler final : public runtime::handler::ProtocolHandler
    {
    public:
        explicit stub_handler(runtime::handler::AcceptResult result) : result_(std::move(result)) {}

        auto accept(shared_transmission) -> net::awaitable<runtime::handler::AcceptResult> override
        {
            co_return result_;
        }

        [[nodiscard]] auto name() const -> std::string_view override { return "stub"; }

    private:
        runtime::handler::AcceptResult result_;
    };

    auto make_stub_accept(runtime::handler::AcceptResult result)
        -> runtime::session_options::protocol_accept_fn
    {
        return runtime::make_protocol_accept(std::make_shared<stub_handler>(std::move(result)));
    }

    /// 构造成功结果
    auto success_result(std::shared_ptr<memory_stream> tr) -> runtime::handler::AcceptResult
    {
        runtime::handler::AcceptResult r;
        r.err = error::none;
        r.target.host = "example.com";
        r.target.port = "443";
        r.identity = "alice";
        r.is_dgram = true;
        r.transmission = std::move(tr);
        return r;
    }

    TEST(AdapterSeam, FillContext)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = make_pair_shared(ioc);
                     const auto *expected = client_s.get();
                     auto accept = make_stub_accept(success_result(client_s));

                     middleware::context ctx;
                     shared_transmission in = inbound_s;
                     const auto ec = co_await accept(in, ctx);

                     EXPECT_EQ(ec, fault::code::success);
                     EXPECT_EQ(ctx.target.host, "example.com");
                     EXPECT_EQ(ctx.target.port, "443");
                     EXPECT_EQ(ctx.identity, "alice");
                     EXPECT_TRUE(ctx.is_dgram);
                     EXPECT_EQ(in.get(), expected);
                 });
    }

    TEST(AdapterSeam, EmptyTransmissionFallsBackToIoError)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = make_pair_shared(ioc);
                     runtime::handler::AcceptResult r;
                     r.err = error::none; // 无错误但无传输 → 兜底 io_error
                     auto accept = make_stub_accept(std::move(r));

                     middleware::context ctx;
                     shared_transmission in = inbound_s;
                     const auto ec = co_await accept(in, ctx);
                     EXPECT_EQ(ec, fault::code::io_error);
                 });
    }

    TEST(AdapterSeam, ErrorMapping)
    {
        const std::pair<preview::error, fault::code> cases[] = {
            {preview::error::bad_auth, fault::code::auth_failed},
            {preview::error::auth_failed, fault::code::auth_failed},
            {preview::error::not_supported, fault::code::not_supported},
            {preview::error::io_error, fault::code::io_error},
            {preview::error::unexpected_eof, fault::code::eof},
            {static_cast<preview::error>(999), fault::code::generic_error},
        };
        for (const auto &[err, want] : cases)
        {
            net::io_context ioc;
            run_coro(ioc,
                     [&]() -> net::awaitable<void>
                     {
                         auto [client_s, inbound_s] = make_pair_shared(ioc);
                         runtime::handler::AcceptResult r;
                         r.err = err;
                         auto accept = make_stub_accept(std::move(r));

                         middleware::context ctx;
                         shared_transmission in = inbound_s;
                         const auto ec = co_await accept(in, ctx);
                         EXPECT_EQ(ec, want);
                     });
        }
    }

    /// 全枚举黄金断言：fault::to_code 的 preview.protocol 分支映射稳定
    /// （SPEC §3：桥接错误映射只允许一套口径，唯一表在 fault/handling.hpp，
    ///  adapter 层不再保留本地副本）
    TEST(AdapterSeam, ErrorMappingMirrorsFaultToCode)
    {
        const auto expect = [](preview::error e) -> preview::fault::code
        {
            switch (e)
            {
            case preview::error::none: return preview::fault::code::success;
            case preview::error::need_more: return preview::fault::code::would_block;
            case preview::error::unexpected_eof: return preview::fault::code::eof;
            case preview::error::bad_length:
            case preview::error::bad_magic:
            case preview::error::bad_message:
            case preview::error::version_mismatch: return preview::fault::code::bad_message;
            case preview::error::bad_auth:
            case preview::error::auth_failed: return preview::fault::code::auth_failed;
            case preview::error::not_supported:
            case preview::error::unsupported: return preview::fault::code::not_supported;
            case preview::error::bad_address: return preview::fault::code::unsupported_address;
            case preview::error::not_open:
            case preview::error::broken_pipe:
            case preview::error::io_error: return preview::fault::code::io_error;
            case preview::error::canceled: return preview::fault::code::canceled;
            case preview::error::timeout: return preview::fault::code::timeout;
            case preview::error::protocol_error: return preview::fault::code::protocol_error;
            case preview::error::kdf_error: return preview::fault::code::generic_error;
            default: return preview::fault::code::generic_error;
            }
        };

        for (int v = 0; v <= static_cast<int>(preview::error::io_error); ++v)
        {
            const auto e = static_cast<preview::error>(v);
            EXPECT_EQ(expect(e), preview::fault::to_code(preview::make_error_code(e)))
                << "mismatch at preview::error value " << v;
        }
        // 越界枚举（无对应 case）：走 default 分支
        const auto bogus = static_cast<preview::error>(999);
        EXPECT_EQ(preview::fault::code::generic_error,
                  preview::fault::to_code(preview::make_error_code(bogus)));
    }

    TEST(AdapterSeam, SessionRejectsDgramWithoutUdpService)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [data_s, peer_s] = make_pair_shared(ioc);

        runtime::session_options opts;
        runtime::handler::AcceptResult r;
        r.err = error::none;
        r.is_dgram = true;
        r.transmission = std::move(data_s);
        opts.accept_protocol = make_stub_accept(std::move(r));
        runtime::session session(std::move(opts));

        fault::code rc = fault::code::success;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 先写入可识别首包，recognition 预读不挂起
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await inbound_s->async_write_some(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                         wec);

                     rc = co_await session.run(client_s);
                 });
        EXPECT_EQ(rc, fault::code::not_supported);
    }

} // namespace