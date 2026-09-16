/**
 * @file ShadowtlsConnSession.cpp
 * @brief ShadowTLS v3 Conn 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（ClientHello SessionId HMAC）→ 双向回显
 * 2. 错误分支：bad_auth（密码不匹配）/ not_open（未握手读写）
 * 3. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Shadowtls/Shadowtls.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowtls = Preview::Shadowtls;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /// 运行协程直至完成（异常重抛）
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

    /// 构造 32 字节随机数（固定模式）
    auto make_random(std::uint8_t seed) -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> rnd{};
        for (std::size_t i = 0; i < rnd.size(); ++i)
        {
            rnd[i] = static_cast<std::uint8_t>(i * 3 + seed);
        }
        return rnd;
    }

    TEST(ShadowtlsConnSession, HandshakeClientServerEcho)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x11);
        const auto client_rnd = make_random(0x22);
        const std::string payload = "shadowtls echo payload";

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：Accept 校验 ClientHello SessionId HMAC → 回显
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, Conn] =
                             co_await Shadowtls::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                         Shadowtls::ServerConfig{"pw123456"});
                         if (err != Error::None || !Conn)
                         {
                             EXPECT_TRUE(false) << "Accept Failed";
                             co_return;
                         }
                         std::array<std::byte, 1024> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         co_await Conn->async_write_some(std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         Conn->Close();
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     auto [herr, cli] = co_await Shadowtls::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), Shadowtls::ClientConfig{"pw123456"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd)});
                     EXPECT_EQ(herr, Error::None);
                     if (!cli)
                     {
                         co_return;
                     }
                     std::error_code ec;
                     co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 1024> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                     cli->Close();
                 });
    }

    TEST(ShadowtlsConnSession, StandardApplicationRecordsAfterExplicitEnable)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        const auto server_rnd = make_random(0x61);
        const auto client_rnd = make_random(0x72);
        const std::string payload = "shadowtls protected payload";

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, Conn] =
                             co_await Shadowtls::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                         Shadowtls::ServerConfig{"record-pw"});
                         EXPECT_EQ(err, Error::None);
                         EXPECT_TRUE(Conn);
                         if (err != Error::None || !Conn)
                         {
                             co_return;
                         }
                         const auto ProtectionError =
                             Conn->EnableRecordProtection(server_rnd, Shadowtls::TagServer, Shadowtls::TagClient);
                         EXPECT_EQ(ProtectionError, Error::None);
                         if (ProtectionError != Error::None)
                         {
                             co_return;
                         }
                         std::array<std::byte, 128> buf{};
                         std::error_code ec;
                         const auto n = co_await Conn->async_read_some(buf, ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                         const auto written = co_await Conn->async_write_some(
                             std::span<const std::byte>(buf.data(), n), ec);
                         EXPECT_FALSE(ec);
                         EXPECT_EQ(written, n);
                         Conn->Close();
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     auto [herr, cli] = co_await Shadowtls::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), Shadowtls::ClientConfig{"record-pw"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd)});
                     EXPECT_EQ(herr, Error::None);
                     EXPECT_TRUE(cli);
                     if (herr != Error::None || !cli)
                     {
                         co_return;
                     }
                     const auto ProtectionError = cli->EnableRecordProtection(server_rnd);
                     EXPECT_EQ(ProtectionError, Error::None);
                     if (ProtectionError != Error::None)
                     {
                         co_return;
                     }
                     std::error_code ec;
                     const auto written = co_await cli->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(written, payload.size());
                     std::array<std::byte, 128> buf{};
                     const auto n = co_await cli->async_read_some(buf, ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::string(reinterpret_cast<const char *>(buf.data()), n), payload);
                     cli->Close();
                 });
    }

    TEST(ShadowtlsConnSession, ReadsAndRetainsStandardClientHelloWire)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Wire = []
        {
            std::vector<std::uint8_t> Hello(75, 0);
            Hello[0] = 0x03;
            Hello[1] = 0x03;
            for (std::size_t I = 0; I < Shadowtls::TlsRndSize; ++I)
            {
                Hello[2 + I] = static_cast<std::uint8_t>(0x60 + I);
            }
            Hello[34] = Shadowtls::TlsSessionIdSz;
            Hello[67] = 0;
            Hello[68] = 2;
            Hello[69] = 0x13;
            Hello[70] = 0x01;
            Hello[71] = 1;
            Hello[72] = 0;
            Hello[73] = 0;
            Hello[74] = 0;
            std::vector<std::uint8_t> Record(Shadowtls::TlsHdrsize + 4 + Hello.size(), 0);
            Record[0] = 0x16;
            Record[1] = 0x03;
            Record[2] = 0x03;
            const auto BodyLength = static_cast<std::uint16_t>(4 + Hello.size());
            Record[3] = static_cast<std::uint8_t>(BodyLength >> 8);
            Record[4] = static_cast<std::uint8_t>(BodyLength);
            Record[5] = Shadowtls::HsTypeClienthello;
            Record[7] = static_cast<std::uint8_t>(Hello.size() >> 8);
            Record[8] = static_cast<std::uint8_t>(Hello.size());
            std::copy(Hello.begin(), Hello.end(), Record.begin() + 9);
            std::span<std::uint8_t, Shadowtls::TlsSessionIdSz> SessionId(
                Record.data() + Shadowtls::TlsHdrsize + Shadowtls::SessionIdStart,
                Shadowtls::TlsSessionIdSz);
            EXPECT_EQ(Shadowtls::GenerateSessionId(
                          Shadowtls::SessionIdInput{"pw", std::span<const std::uint8_t>(Record).subspan(5),
                                                    SessionId}),
                      Error::None);
            return Record;
        }();

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Source = std::make_shared<MemoryStream>(std::move(a));
                     auto Target = std::make_shared<MemoryStream>(std::move(b));
                     std::error_code ec;
                     const auto Written = co_await Source->async_write_some(
                         std::span<const std::byte>(reinterpret_cast<const std::byte *>(Wire.data()), Wire.size()),
                         ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(Written, Wire.size());
                     auto Conn = std::make_shared<Shadowtls::Conn<>>(Target, "pw");
                     EXPECT_EQ(co_await Conn->ReadStandardHandshake(), Error::None);
                     EXPECT_EQ(Conn->TakeClientHelloWire(), Wire);
                     Conn->Close();
                 });
    }

    TEST(ShadowtlsConnSession, WritesStandardClientHelloWithComputedSessionId)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        std::vector<std::uint8_t> Template(Shadowtls::TlsHdrsize + 4 + 75, 0);
        Template[0] = 0x16;
        Template[1] = 0x03;
        Template[2] = 0x03;
        const auto BodyLength = static_cast<std::uint16_t>(4 + 75);
        Template[3] = static_cast<std::uint8_t>(BodyLength >> 8);
        Template[4] = static_cast<std::uint8_t>(BodyLength);
        Template[5] = Shadowtls::HsTypeClienthello;
        Template[7] = 0;
        Template[8] = 75;
        Template[9] = 0x03;
        Template[10] = 0x03;
        for (std::size_t I = 0; I < Shadowtls::TlsRndSize; ++I)
        {
            Template[11 + I] = static_cast<std::uint8_t>(0x20 + I);
        }
        Template[43] = Shadowtls::TlsSessionIdSz;
        Template[76] = 0;
        Template[77] = 2;
        Template[78] = 0x13;
        Template[79] = 0x01;
        Template[80] = 1;
        Template[81] = 0;
        Template[82] = 0;
        Template[83] = 0;
        const std::string Password = "standard-pw";

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto WriterTransport = std::make_shared<MemoryStream>(std::move(a));
                     auto ReaderTransport = std::make_shared<MemoryStream>(std::move(b));
                     Shadowtls::ClientConfig ClientConfig{Password};
                     Shadowtls::ServerConfig ServerConfig{Password};
                     auto ReaderTask = Net::co_spawn(
                         ReaderTransport->Executor(),
                         [ReaderTransport, ServerConfig]() mutable
                             -> Net::awaitable<std::tuple<Error, std::vector<std::uint8_t>, Shadowtls::SharedConn>>
                         { co_return co_await Shadowtls::AcceptStandard(ReaderTransport, ServerConfig); },
                         Net::use_awaitable);
                     const auto [WriteError, Writer] = co_await Shadowtls::ConnectStandard(
                         Shadowtls::StandardConnectParameters{WriterTransport, ClientConfig, Template});
                     EXPECT_EQ(WriteError, Error::None);
                     const auto [ReadError, ReaderWire, Reader] = co_await std::move(ReaderTask);
                     EXPECT_EQ(ReadError, Error::None);
                     std::vector<std::uint8_t> WriterWire;
                     if (Writer)
                     {
                         WriterWire = Writer->TakeClientHelloWire();
                     }
                     EXPECT_EQ(WriterWire, ReaderWire);
                     EXPECT_TRUE(Shadowtls::VerifyClientHello(
                         Password, std::span<const std::byte>(reinterpret_cast<const std::byte *>(WriterWire.data()),
                                                              WriterWire.size())));
                     if (Writer)
                     {
                         Writer->Close();
                     }
                     if (Reader)
                     {
                         Reader->Close();
                     }
                 });
    }

    TEST(ShadowtlsConnSession, StandardHandshakeRejectsNullTransport)
    {
        Net::io_context ioc;
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Conn = std::make_shared<Shadowtls::Conn<>>(nullptr, "pw");
                     EXPECT_EQ(co_await Conn->ReadStandardHandshake(), Error::NotOpen);
                     EXPECT_EQ(co_await Conn->WriteStandardHandshake(std::span<const std::uint8_t>{}),
                               Error::NotOpen);
                 });
    }

    TEST(ShadowtlsConnSession, BadAuthRejected)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 服务端：密码不匹配 → SessionId HMAC 校验失败 → bad_auth
                     auto server_coro = [&]() -> Net::awaitable<void>
                     {
                         auto [err, Conn] =
                             co_await Shadowtls::Accept(std::make_shared<MemoryStream>(std::move(b)),
                                                         Shadowtls::ServerConfig{"Expect-pw"});
                         EXPECT_EQ(err, Error::BadAuth);
                         EXPECT_FALSE(Conn);
                     };
                     Net::co_spawn(ioc.get_executor(), server_coro(), Net::detached);

                     const auto server_rnd = make_random(0x33);
                     const auto client_rnd = make_random(0x44);
                     auto [herr, cli] = co_await Shadowtls::Connect({
                         std::make_shared<MemoryStream>(std::move(a)), Shadowtls::ClientConfig{"wrong-pw"},
                         std::span<const std::uint8_t>(server_rnd), std::span<const std::uint8_t>(client_rnd)});
                     EXPECT_EQ(herr, Error::None); // 客户端只发送，不感知认证结果
                     if (cli)
                     {
                         cli->Close();
                     }
                 });
    }

    TEST(ShadowtlsConnSession, NotOpenRejected)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 未握手 Conn：读写返回 not_open
                     auto c = std::make_shared<Shadowtls::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     ec.clear();
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(ec.value(), static_cast<int>(Error::NotOpen));
                     c->Close();
                     c->Cancel();
                     EXPECT_TRUE(c->Executor());
                     EXPECT_NE(c->NextLayer(), nullptr);
                     EXPECT_NE(c->lowest_layer<MemoryStream>(), nullptr);
                     const Shadowtls::Conn<> *const_c = c.get();
                     EXPECT_NE(const_c->NextLayer(), nullptr);
                     auto released = c->Release();
                     EXPECT_TRUE(released);
                     EXPECT_EQ(c->NextLayer(), nullptr);
                 });
    }

} // namespace
