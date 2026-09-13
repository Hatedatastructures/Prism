/**
 * @file AdapterTest.cpp
 * @brief adapter 接入缝专项测试（阶段 5 v2）
 * @details 覆盖：
 *          - MakeProtocolAccept 的 ctx 装配（Target/identity/IsDgram/PostDial/Inbound 替换）
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

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Fault/Handling.hpp>
#include <preview/Foundation/Utility/Account/Authenticator.hpp>
#include <preview/Foundation/Utility/Account/Directory.hpp>
#include <preview/Runtime/Middleware/Context.hpp>
#include <preview/Runtime/Contract/Handler.hpp>
#include <preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Runtime = Preview::Runtime;

    using Preview::Testing::RunCoro; // 公共样板（见 <TestSupport/Fixtures/RuntimeTestHelpers.hpp>）

    /// 可识别首包（socks5 Greeting）
    auto Socks5Greeting() -> std::string
    {
        return std::string("\x05\x01\x00", 3);
    }

    /// 内存流对 → shared 包装
    auto MakePairShared(Net::io_context &Ioc)
        -> std::pair<std::shared_ptr<MemoryStream>, std::shared_ptr<MemoryStream>>
    {
        auto [A, B] = MakeMemoryPair(Ioc.get_executor());
        return {std::make_shared<MemoryStream>(std::move(A)),
                std::make_shared<MemoryStream>(std::move(B))};
    }

    /// 桩协议处理器：按预设结果返回
    class StubHandler final : public Runtime::Handler::ProtocolHandler
    {
    public:
        explicit StubHandler(Runtime::Handler::AcceptResult Result) : result_(std::move(Result)) {}

        auto Accept(SharedTransmission) -> Net::awaitable<Runtime::Handler::AcceptResult> override
        {
            co_return std::move(result_);
        }

        [[nodiscard]] auto Name() const -> std::string_view override { return "stub"; }

    private:
        Runtime::Handler::AcceptResult result_;
    };

    auto MakeStubAccept(Runtime::Handler::AcceptResult Result)
        -> Runtime::SessionOptions::ProtocolAcceptFn
    {
        return Runtime::MakeProtocolAccept(std::make_shared<StubHandler>(std::move(Result)));
    }

    /// 构造成功结果
    auto SuccessResult(std::shared_ptr<MemoryStream> Transmission) -> Runtime::Handler::AcceptResult
    {
        Runtime::Handler::AcceptResult r;
        r.err = Error::None;
        r.Target.Host = "example.com";
        r.Target.Port = "443";
        r.identity = "alice";
        r.ProtocolAuthenticated = true;
        r.IsDgram = true;
        r.Transmission = std::move(Transmission);
        return r;
    }

    TEST(AdapterSeam, FillContext)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = MakePairShared(ioc);
                     const auto *expected = client_s.get();
                     auto Accept = MakeStubAccept(SuccessResult(client_s));

                     Middleware::Context ctx;
                     SharedTransmission yn = inbound_s;
                     const auto ec = co_await Accept(yn, ctx);

                     EXPECT_EQ(ec, Fault::Code::Success);
                     EXPECT_EQ(ctx.Target.Host, "example.com");
                     EXPECT_EQ(ctx.Target.Port, "443");
                     EXPECT_EQ(ctx.identity, "alice");
                     EXPECT_TRUE(ctx.ProtocolAuthenticated);
                     EXPECT_TRUE(ctx.IsDgram);
                     EXPECT_EQ(yn.get(), expected);
                 });
    }

    TEST(AdapterSeam, TransfersProtocolAccountLeaseToContext)
    {
        Net::io_context Io;
        Preview::Account::Directory Directory;
        Directory.Upsert("credential", 1);
        auto Authenticator = std::make_shared<Preview::Account::DirectoryAuthenticator>(&Directory);
        auto AuthResult = Authenticator->Check("", "credential");
        ASSERT_TRUE(AuthResult.Ok);
        ASSERT_TRUE(AuthResult.Lease.has_value());
        EXPECT_EQ(Directory.Find("credential")->Active(), 1U);

        Runtime::Handler::AcceptResult Result;
        Result.err = Error::None;
        Result.ProtocolAuthenticated = true;
        Result.AccountLease = std::move(AuthResult.Lease);
        auto [Client, Inbound] = MakePairShared(Io);
        Result.Transmission = Client;
        auto Accept = MakeStubAccept(std::move(Result));

        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        RunCoro(Io,
                [&]() -> Net::awaitable<void>
                {
                    const auto Code = co_await Accept(Transport, Context);
                    EXPECT_EQ(Code, Fault::Code::Success);
                });

        EXPECT_TRUE(Context.ProtocolAuthenticated);
        ASSERT_TRUE(Context.AccountLease.has_value());
        EXPECT_TRUE(*Context.AccountLease);
        EXPECT_EQ(Directory.Find("credential")->Active(), 1U);
        Context.AccountLease.reset();
        EXPECT_EQ(Directory.Find("credential")->Active(), 0U);
    }

    TEST(AdapterSeam, EmptyTransmissionFallsBackToIoError)
    {
        Net::io_context ioc;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto [client_s, inbound_s] = MakePairShared(ioc);
                     Runtime::Handler::AcceptResult r;
                     r.err = Error::None; // 无错误但无传输 → 兜底 io_error
                     auto Accept = MakeStubAccept(std::move(r));

                     Middleware::Context ctx;
                     SharedTransmission yn = inbound_s;
                     const auto ec = co_await Accept(yn, ctx);
                     EXPECT_EQ(ec, Fault::Code::IoError);
                 });
    }

    TEST(AdapterSeam, ErrorMapping)
    {
        const std::pair<Preview::Error, Fault::Code> cases[] = {
            {Preview::Error::BadAuth, Fault::Code::AuthFailed},
            {Preview::Error::AuthFailed, Fault::Code::AuthFailed},
            {Preview::Error::NotSupported, Fault::Code::NotSupported},
            {Preview::Error::IoError, Fault::Code::IoError},
            {Preview::Error::UnexpectedEof, Fault::Code::Eof},
            {static_cast<Preview::Error>(999), Fault::Code::GenericError},
        };
        for (const auto &[err, Want] : cases)
        {
            Net::io_context ioc;
            RunCoro(ioc,
                     [&]() -> Net::awaitable<void>
                     {
                         auto [client_s, inbound_s] = MakePairShared(ioc);
                         Runtime::Handler::AcceptResult r;
                         r.err = err;
                         auto Accept = MakeStubAccept(std::move(r));

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
        const auto Expect = [](Preview::Error e) -> Preview::Fault::Code
        {
            switch (e)
            {
            case Preview::Error::None: return Preview::Fault::Code::Success;
            case Preview::Error::NeedMore: return Preview::Fault::Code::WouldBlock;
            case Preview::Error::UnexpectedEof: return Preview::Fault::Code::Eof;
            case Preview::Error::BadLength:
            case Preview::Error::BadMagic:
            case Preview::Error::BadMessage:
            case Preview::Error::VersionMismatch: return Preview::Fault::Code::BadMessage;
            case Preview::Error::BadAuth:
            case Preview::Error::AuthFailed: return Preview::Fault::Code::AuthFailed;
            case Preview::Error::NotSupported:
            case Preview::Error::Unsupported: return Preview::Fault::Code::NotSupported;
            case Preview::Error::BadAddress: return Preview::Fault::Code::UnsupportedAddress;
            case Preview::Error::NotOpen:
            case Preview::Error::BrokenPipe:
            case Preview::Error::IoError: return Preview::Fault::Code::IoError;
            case Preview::Error::Canceled: return Preview::Fault::Code::Canceled;
            case Preview::Error::Timeout: return Preview::Fault::Code::Timeout;
            case Preview::Error::ProtocolError: return Preview::Fault::Code::ProtocolError;
            case Preview::Error::KdfError: return Preview::Fault::Code::GenericError;
            default: return Preview::Fault::Code::GenericError;
            }
        };

        for (int v = 0; v <= static_cast<int>(Preview::Error::IoError); ++v)
        {
            const auto e = static_cast<Preview::Error>(v);
            EXPECT_EQ(Expect(e), Preview::Fault::ToCode(Preview::make_error_code(e)))
                << "mismatch at Preview::Error value " << v;
        }
        // 越界枚举（无对应 case）：走 default 分支
        const auto bogus = static_cast<Preview::Error>(999);
        EXPECT_EQ(Preview::Fault::Code::GenericError,
                  Preview::Fault::ToCode(Preview::make_error_code(bogus)));
    }

    TEST(AdapterSeam, SessionRejectsDgramWithoutUdpService)
    {
        Net::io_context ioc;
        auto [client_s, inbound_s] = MakePairShared(ioc);
        auto [data_s, peer_s] = MakePairShared(ioc);

        Runtime::SessionOptions opts;
        Runtime::Handler::AcceptResult r;
        r.err = Error::None;
        r.IsDgram = true;
        r.Transmission = std::move(data_s);
        opts.AcceptProtocol = MakeStubAccept(std::move(r));
        Runtime::Session Session(std::move(opts));

        Fault::Code Arc = Fault::Code::Success;
        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 先写入可识别首包，recognition 预读不挂起
                     std::error_code wec;
                     const auto payload = Socks5Greeting();
                     co_await inbound_s->async_write_some(
                         std::span<const std::byte>(
                             reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                         wec);

                     Arc = co_await Session.Run(client_s);
                 });
        EXPECT_EQ(Arc, Fault::Code::NotSupported);
    }

} // namespace
