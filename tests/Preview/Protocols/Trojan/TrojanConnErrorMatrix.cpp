/**
 * @file TrojanConnErrorMatrix.cpp
 * @brief Trojan Conn 错误矩阵测试
 * @details 服务端握手错误路径：
 * - 凭据不匹配（bad_auth）
 * - 凭据后缺 CRLF（bad_magic）
 * - 非法命令（not_supported）
 * - 非法地址类型（bad_message）
 * - 半包截断（io_error）
 * - 客户端响应校验失败
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Preview::Trojan;
    using Preview::AsBytes;
    using Preview::Error;
    using Preview::Fault::Failure;
    using Preview::Fault::Code;
    using Preview::Fault::ToCode;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::SharedTransmission;

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct EagerTaskState final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    /** @brief 立即启动错误 server operation 并保存首异常。 */
    auto SpawnEagerTask(Net::any_io_executor Executor, Net::awaitable<void> Operation)
        -> EagerTaskState
    {
        EagerTaskState State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>()};
        Net::co_spawn(
            Executor,
            std::move(Operation),
            [State](std::exception_ptr ErrorValue)
            {
                *State.Failure = ErrorValue;
                (void)State.Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    /** @brief 等待错误 server 的真实 completion。 */
    auto WaitEagerTask(EagerTaskState State) -> Net::awaitable<void>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    struct ErrorServerRequest final
    {
        SharedTransmission Server;
        Trojan::ServerConfig Config;
        std::shared_ptr<Failure> Observed;
    };

    /** @brief 接收一个错误握手并验证正式错误码与空连接。 */
    auto RunErrorServer(ErrorServerRequest Request) -> Net::awaitable<void>
    {
        auto Result = co_await Trojan::Accept(std::move(Request.Server), Request.Config);
        *Request.Observed = Result ? Failure{} : Result.error();
    }

    struct ErrorScenarioRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        Trojan::ServerConfig Config;
        std::vector<std::uint8_t> Wire;
        Error Expected;
        bool HalfCloseClientWrite;
        std::shared_ptr<Failure> Observed;
    };

    /** @brief 发送完整错误 wire，等待服务端 operation 完成。 */
    auto RunErrorScenario(ErrorScenarioRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerTask(
            Request.Server->Executor(),
            RunErrorServer(ErrorServerRequest{
                Request.Server, Request.Config, Request.Observed}));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Write = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Request.Wire)));
            EXPECT_FALSE(Write.Failure.Failed());
            EXPECT_EQ(Write.Bytes, Request.Wire.size());
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        if (Request.HalfCloseClientWrite)
        {
            const auto Shutdown = co_await Request.Client->WriteShutdown();
            EXPECT_TRUE(Shutdown);
            if (!Shutdown)
            {
                const auto ClientClose = Request.Client->Close();
                EXPECT_TRUE(ClientClose);
            }
        }
        co_await WaitEagerTask(std::move(ServerTask));
        EXPECT_EQ(Request.Observed->Code, ToCode(Preview::make_error_code(Request.Expected)));
        const auto ClientClose = Request.Client->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = Request.Server->Close();
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await Request.Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await Request.Server->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 客户端握手精确写失败保留已经写出的进度与原生原因。 */
    auto RunNativePartialHandshakeWrite(Net::io_context &IoContext, const std::error_code Native)
        -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->WriteErrorBytes = 1;
        Raw->SetWriteError(Native);
        const Trojan::ClientConfig Config{"prism"};
        const auto Target = Trojan::Address{Trojan::AddressType::Domain, "example.com", 443};
        auto Result = co_await Trojan::Connect(Trojan::ConnectParameters{Raw, Config, Target});
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Preview::Fault::Code::ConnectionReset);
            EXPECT_EQ(Result.error().Native, Native);
        }
        EXPECT_EQ(Raw->Written.size(), 1U);
        const auto Drain = co_await Raw->Activity()->Drain();
        EXPECT_TRUE(Raw->IsClosed());
        EXPECT_TRUE(Drain);
    }

    /** @brief 服务端握手精确读失败保留已经读出的进度与原生原因。 */
    auto RunNativePartialHandshakeRead(Net::io_context &IoContext, const std::error_code Native)
        -> Net::awaitable<void>
    {
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->InjectRead({0x01});
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(Native);
        const Trojan::ServerConfig Config{"prism"};
        auto Result = co_await Trojan::Accept(Raw, Config);
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Preview::Fault::Code::ConnectionReset);
            EXPECT_EQ(Result.error().Native, Native);
        }
        const auto Close = Raw->Close();
        const auto Drain = co_await Raw->Activity()->Drain();
        EXPECT_TRUE(Close && Drain);
    }

    TEST(TrojanConnErrorMatrix, BadCredential)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const std::string Credential(56, '0');
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        const std::array<std::uint8_t, 12> RequestSuffix{
            '\r', '\n', 0x01, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50, '\r', '\n'};
        Wire.insert(Wire.end(), RequestSuffix.begin(), RequestSuffix.end());
        Trojan::ServerConfig Config;
        Config.Password = "correct";
        const auto Observed = std::make_shared<Failure>();
        RunCoroutine(IoContext, RunErrorScenario(ErrorScenarioRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Config, Wire, Error::BadAuth, true, Observed}));
        EXPECT_EQ(Observed->Code, ToCode(Preview::make_error_code(Error::BadAuth)));
        EXPECT_FALSE(Observed->Native);
    }

    TEST(TrojanConnErrorMatrix, MissingCrlf)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("prism");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {0x01, 0x02});
        Trojan::ServerConfig Config{"prism"};
        const auto Observed = std::make_shared<Failure>();
        RunCoroutine(IoContext, RunErrorScenario(ErrorScenarioRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Config, Wire, Error::BadMagic, true, Observed}));
        EXPECT_EQ(Observed->Code, ToCode(Preview::make_error_code(Error::BadMagic)));
        EXPECT_FALSE(Observed->Native);
    }

    TEST(TrojanConnErrorMatrix, BadCommand)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("prism");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x99, 0x01, 0x00, 0x50});
        const auto Observed = std::make_shared<Failure>();
        RunCoroutine(IoContext, RunErrorScenario(ErrorScenarioRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"prism"}, Wire, Error::BadMessage, true, Observed}));
        EXPECT_EQ(Observed->Code, ToCode(Preview::make_error_code(Error::BadMessage)));
        EXPECT_FALSE(Observed->Native);
    }

    TEST(TrojanConnErrorMatrix, BadAddressType)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("prism");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x01, 0x09, 0x00, 0x50});
        const auto Observed = std::make_shared<Failure>();
        RunCoroutine(IoContext, RunErrorScenario(ErrorScenarioRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"prism"}, Wire, Error::BadMessage, true, Observed}));
        EXPECT_EQ(Observed->Code, ToCode(Preview::make_error_code(Error::BadMessage)));
        EXPECT_FALSE(Observed->Native);
    }

    TEST(TrojanConnErrorMatrix, TruncatedHeader)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("prism");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x01});
        const auto Observed = std::make_shared<Failure>();
        RunCoroutine(IoContext, RunErrorScenario(ErrorScenarioRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"prism"}, Wire, Error::IoError, true, Observed}));
        EXPECT_EQ(Observed->Code, Code::Eof);
        EXPECT_FALSE(Observed->Native);
    }

TEST(TrojanConnErrorMatrix, NativePartialHandshakeIo)
{
    Net::io_context IoContext;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    RunCoroutine(IoContext, RunNativePartialHandshakeWrite(IoContext, Native));
    RunCoroutine(IoContext, RunNativePartialHandshakeRead(IoContext, Native));
}

} // namespace
