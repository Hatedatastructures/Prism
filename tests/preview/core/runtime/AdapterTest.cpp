/**
 * @file AdapterTest.cpp
 * @brief adapter 接入缝专项测试（阶段 5 v2）
 * @details 覆盖：
 *          - MakeProtocolAccept 的 ctx 装配（Target/identity/IsDgram/post_dial/inbound 替换）
 *          - 失败映射（bad_auth/not_supported/io_error/unexpected_eof/未知错误）
 *          - 全枚举黄金断言：Fault::ToCode 的 make_error_code.Protocol 分支映射稳定
 *          - 空传输兜底（无错误但无传输 → io_error）
 *          - Session 分支：IsDgram 但未注册 udp_service → not_supported
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <common/Core/Error.hpp>
#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Handling.hpp>
#include <common/Core/Middleware/Context.hpp>
#include <common/Core/Runtime/Adapter/Handler.hpp>
#include <common/Core/Runtime/Adapter/ProtocolAdapter.hpp>
#include <common/Core/Runtime/Session.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transmission.hpp>
#include <common/RuntimeTestHelpers.hpp>

namespace
{

    namespace net = boost::asio;
    using namespace make_error_code;

    using psm::testing::RunCoro; // 公共样板（见 <common/RuntimeTestHelpers.hpp>）

    /// 可识别首包（socks5 Greeting）
    auto socks5_greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto make_pair_shared(net::io_context &ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(a)),
                std::make_shared<MemoryStream>(std::move(b))};
    }

    /// 桩协议处理器：按预设结果返回
    class stub_handler final : public Runtime::Handler::ProtocolHandler
    {
    public:
        explicit stub_handler(Runtime::Handler::AcceptResult Result) : result_(std::move(Result)) {}

        auto Accept(SharedTransmission) -> net::awaitable<Runtime::Handler::AcceptResult> override
        {
            co_return result_;
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "stub"; }

    private:
        Runtime::Handler::AcceptResult result_;
    };

    auto make_stub_accept(Runtime::Handler::AcceptResult Result)
        -> Runtime::SessionOptions::ProtocolAcceptFn
    {
        return Runtime::MakeProtocolAccept(std::make_shared<stub_handler>(std::move(Result)));
    }

    /// 构造成功结果
    auto success_result(std::shared_ptr<MemoryStream> tr) -> Runtime::Handler::AcceptResult
    {
        Runtime::Handler::AcceptResult r;
        r.err = Error::none;
        r.Target.Host = "example.com";
        r.Target.Port = "443";
        r.identity = "alice";
        r.IsDgram = true;
        r.Transmission = std::move(tr);
        return r;
    }

    TEST(AdapterSeam, FillContext)
    {
        net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = make_pair_shared(ioc);
                     const auto *expected = client_s.get();
                     auto Accept = make_stub_accept(success_result(client_s));

                     Middleware::Context ctx;
                     SharedTransmission yn = inbound_s;
                     const auto ec = co_await Accept(yn, ctx);

                     EXPECT_EQ(ec, Fault::Code::success);
                     EXPECT_EQ(ctx.Target.Host, "example.com");
                     EXPECT_EQ(ctx.Target.Port, "443");
                     EXPECT_EQ(ctx.identity, "alice");
                     EXPECT_TRUE(ctx.IsDgram);
                     EXPECT_EQ(yn.get(), expected);
                 });
    }

    TEST(AdapterSeam, EmptyTransmissionFallsBackToIoError)
    {
        net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = make_pair_shared(ioc);
                     Runtime::Handler::AcceptResult r;
                     r.err = Error::none; // 无错误但无传输 → 兜底 io_error
                     auto Accept = make_stub_accept(std::move(r));

                     Middleware::Context ctx;
                     SharedTransmission yn = inbound_s;
                     const auto ec = co_await Accept(yn, ctx);
                     EXPECT_EQ(ec, Fault::Code::io_error);
                 });
    }

    TEST(AdapterSeam, ErrorMapping)
    {
        const std::pair<std::Error, Fault::Code> cases[] = {
            {std::Error::bad_auth, Fault::Code::auth_failed},
            {std::Error::auth_failed, Fault::Code::auth_failed},
            {std::Error::not_supported, Fault::Code::not_supported},
            {std::Error::io_error, Fault::Code::io_error},
            {std::Error::unexpected_eof, Fault::Code::eof},
            {static_cast<std::Error>(999), Fault::Code::generic_error},
        };
        for (const auto &[err, Want] : cases)
        {
            net::io_context ioc;
            RunCoro(ioc,
                     [&]() -> net::awaitable<void>
                     {
                         auto [client_s, inbound_s] = make_pair_shared(ioc);
                         Runtime::Handler::AcceptResult r;
                         r.err = err;
                         auto Accept = make_stub_accept(std::move(r));

                         Middleware::Context ctx;
                         SharedTransmission yn = inbound_s;
                         const auto ec = co_await Accept(yn, ctx);
                         EXPECT_EQ(ec, Want);
                     });
        }
    }

    /// 全枚举黄金断言：Fault::ToCode 的 make_error_code.Protocol 分支映射稳定
    /// （SPEC §3：桥接错误映射只允许一套口径，唯一表在 fault/handling.hpp，
    ///  adapter 层不再保留本地副本）
    TEST(AdapterSeam, ErrorMappingMirrorsFaultToCode)
    {
        const auto Expect = [](std::Error e) -> std::Fault::Code
        {
            switch (e)
            {
            case std::Error::none: return std::Fault::Code::success;
            case std::Error::need_more: return std::Fault::Code::would_block;
            case std::Error::unexpected_eof: return std::Fault::Code::eof;
            case std::Error::bad_length:
            case std::Error::bad_magic:
            case std::Error::bad_message:
            case std::Error::version_mismatch: return std::Fault::Code::bad_message;
            case std::Error::bad_auth:
            case std::Error::auth_failed: return std::Fault::Code::auth_failed;
            case std::Error::not_supported:
            case std::Error::unsupported: return std::Fault::Code::not_supported;
            case std::Error::bad_address: return std::Fault::Code::unsupported_address;
            case std::Error::not_open:
            case std::Error::broken_pipe:
            case std::Error::io_error: return std::Fault::Code::io_error;
            case std::Error::canceled: return std::Fault::Code::canceled;
            case std::Error::timeout: return std::Fault::Code::timeout;
            case std::Error::protocol_error: return std::Fault::Code::protocol_error;
            case std::Error::kdf_error: return std::Fault::Code::generic_error;
            default: return std::Fault::Code::generic_error;
            }
        };

        for (int v = 0; v <= static_cast<int>(std::Error::io_error); ++v)
        {
            const auto e = static_cast<std::Error>(v);
            EXPECT_EQ(Expect(e), std::Fault::ToCode(std::make_error_code(e)))
                << "mismatch at std::Error value " << v;
        }
        // 越界枚举（无对应 case）：走 default 分支
        const auto bogus = static_cast<std::Error>(999);
        EXPECT_EQ(std::Fault::Code::generic_error,
                  std::Fault::ToCode(std::make_error_code(bogus)));
    }

    TEST(AdapterSeam, SessionRejectsDgramWithoutUdpService)
    {
        net::io_context ioc;
        auto [client_s, inbound_s] = make_pair_shared(ioc);
        auto [data_s, peer_s] = make_pair_shared(ioc);

        Runtime::SessionOptions opts;
        Runtime::Handler::AcceptResult r;
        r.err = Error::none;
        r.IsDgram = true;
        r.Transmission = std::move(data_s);
        opts.AcceptProtocol = make_stub_accept(std::move(r));
        Runtime::Session Session(std::move(opts));

        Fault::Code Arc = Fault::Code::success;
        RunCoro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 先写入可识别首包，recognition 预读不挂起
                     std::error_code wec;
                     const auto payload = socks5_greeting();
                     co_await inbound_s->AsyncWriteSome(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                         wec);

                     Arc = co_await Session.Run(client_s);
                 });
        EXPECT_EQ(Arc, Fault::Code::not_supported);
    }

} // namespace