/**
 * @file RestlsConnSession.cpp
 * @brief Restls Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（同一 ServerRandom）→ 双向回显
 * 2. 派生密钥一致性校验（Secret()）
 * 3. 错误分支：bad_length（ServerRandom 长度非法）/ not_open（未握手读写）
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <string>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Restls/Restls.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Restls = Preview::Restls;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoro(
        Net::io_context &IoContext,
        A Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 构造 32 字节服务端随机数（固定模式）
    auto MakeServerRandom() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Random{};
        for (std::size_t Index = 0; Index < Random.size(); ++Index)
        {
            Random[Index] = static_cast<std::uint8_t>(Index * 5 + 1);
        }
        return Random;
    }

    TEST(RestlsConnSession, HandshakeClientServerEcho)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        const auto ServerRandom = MakeServerRandom();
        const std::string Payload = "restls echo payload";

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                {
                    // 服务端：Accept 握手 → 回显
                     auto ServerDone = std::make_shared<
                        Net::experimental::channel<void(boost::system::error_code)>>(
                            IoContext.get_executor(), 1);
                     auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
                    auto ServerCoroutine = [ServerDone,
                                            ServerTransport = std::move(ServerTransport),
                                            ServerRandom,
                                            Payload]() mutable -> Net::awaitable<void>
                    {
                        Restls::ServerConfig ServerConfig{"pw123456"};
                        auto [AcceptError, Connection] = co_await Restls::Accept(
                            std::move(ServerTransport), ServerConfig, ServerRandom);
                        if (AcceptError != Error::None || !Connection)
                        {
                            EXPECT_TRUE(false) << "Accept Failed";
                            co_return;
                        }
                        // 服务端派生密钥与客户端一致
                        EXPECT_EQ(Connection->Secret(), Restls::DeriveSecret("pw123456"));
                        std::array<std::byte, 1024> Buffer{};
                        std::error_code ErrorCode;
                        const auto ReadSize = co_await Connection->async_read_some(Buffer, ErrorCode);
                        EXPECT_FALSE(ErrorCode);
                        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), ReadSize), Payload);
                        const auto Response = std::span<const std::byte>(Buffer.data(), ReadSize);
                        co_await Connection->async_write_some(Response, ErrorCode);
                        EXPECT_FALSE(ErrorCode);
                        Connection->Close();
                    };
                    auto ServerCompletion = [ServerDone](std::exception_ptr) -> void
                    {
                        (void)ServerDone->try_send(boost::system::error_code{});
                    };
                    Net::co_spawn(
                        IoContext.get_executor(), std::move(ServerCoroutine), std::move(ServerCompletion));

                    Restls::ClientConfig ClientConfig{"pw123456"};
                    auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                    auto [ConnectError, Client] = co_await Restls::Connect(
                        std::move(ClientTransport), ClientConfig, ServerRandom);
                    EXPECT_EQ(ConnectError, Error::None);
                    if (!Client)
                    {
                        co_return;
                    }
                    EXPECT_EQ(Client->Secret(), Restls::DeriveSecret("pw123456"));
                    std::error_code ErrorCode;
                    const auto Request = std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
                    co_await Client->async_write_some(Request, ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    std::array<std::byte, 1024> Buffer{};
                    const auto ReadSize = co_await Client->async_read_some(Buffer, ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), ReadSize), Payload);
                    Client->Close();
                    boost::system::error_code ServerError;
                    co_await ServerDone->async_receive(
                        Net::redirect_error(Net::use_awaitable, ServerError));
                    EXPECT_FALSE(ServerError);
                });
    }

    TEST(RestlsConnSession, BadLengthRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // ServerRandom 长度非法（31 字节）→ bad_length
                     const std::array<std::uint8_t, 31> ShortRandom{};
                     Restls::ClientConfig ClientConfig{"pw"};
                     auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                     const auto ShortRandomSpan = std::span<const std::uint8_t>(ShortRandom);
                     auto [ConnectError, Client] = co_await Restls::Connect(
                         std::move(ClientTransport), ClientConfig, ShortRandomSpan);
                     EXPECT_EQ(ConnectError, Error::BadLength);
                     EXPECT_FALSE(Client);

                     auto ServerTransport = std::make_shared<MemoryStream>(std::move(ServerMemory));
                     auto Connection = std::make_shared<Restls::Conn<>>(std::move(ServerTransport), "pw");
                     const std::array<std::uint8_t, 33> LongRandom{};
                     const auto LongRandomSpan = std::span<const std::uint8_t>(LongRandom);
                     const auto AcceptError = co_await Connection->ReadHandshake(LongRandomSpan);
                     EXPECT_EQ(AcceptError, Error::BadLength);
                 });
    }

    TEST(RestlsConnSession, NotOpenRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext,
                [&]() -> Net::awaitable<void>
                 {
                     // 未握手 Conn：读写返回 not_open
                     auto ClientTransport = std::make_shared<MemoryStream>(std::move(ClientMemory));
                     auto Connection = std::make_shared<Restls::Conn<>>(std::move(ClientTransport), "pw");
                     std::array<std::byte, 64> Buffer{};
                     std::error_code ErrorCode;
                     const auto ReadSize = co_await Connection->async_read_some(Buffer, ErrorCode);
                     EXPECT_EQ(ReadSize, 0u);
                     EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::NotOpen));
                     ErrorCode.clear();
                     const auto WriteBuffer = std::span<const std::byte>(Buffer.data(), 4);
                     co_await Connection->async_write_some(WriteBuffer, ErrorCode);
                     EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::NotOpen));
                     Connection->Close();
                     Connection->Cancel();
                     EXPECT_TRUE(Connection->Executor());
                     EXPECT_NE(Connection->NextLayer(), nullptr);
                     EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
                     const Restls::Conn<> *ConstConnection = Connection.get();
                     EXPECT_NE(ConstConnection->NextLayer(), nullptr);
                     auto Released = Connection->Release();
                     EXPECT_TRUE(Released);
                     EXPECT_EQ(Connection->NextLayer(), nullptr);
                 });
    }

} // namespace
