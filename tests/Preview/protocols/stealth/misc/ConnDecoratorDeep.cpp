/**
 * @file ConnDecoratorDeep.cpp
 * @brief 测试库 Conn 装饰器剩余方法深度测试
 * @details 覆盖 gun / reality / anytls / tuic 四个 Conn 装饰器的
 *          Executor / Cancel / NextLayer（const + 非 const）/ Release
 *          / Close 等透传方法，以及 Mux::StreamTransmission 的
 *          空句柄 Executor 与 Cancel 分支。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <array>
#include <memory>
#include <string>

#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Stream.hpp>
#include <Preview/Protocols/Tuic/Conn.hpp>
#include <Preview/Protocols/Anytls/Conn.hpp>
#include <Preview/Protocols/Gun/Conn.hpp>
#include <Preview/Protocols/Reality/Conn.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Anytls = Preview::Anytls;
    namespace Gun = Preview::Gun;
    namespace Mux = Preview::Mux;
    namespace Reality = Preview::Reality;
    namespace Tuic = Preview::Tuic;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;

    /**
     * @brief 驱动协程运行
     */
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        // 同一 io_context 可能被多次驱动，restart() 重置 stopped 标志
        IoContext.restart();
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

    class ZeroProgressTransport final : public Preview::Transmission
    {
    public:
        explicit ZeroProgressTransport(Net::any_io_executor Executor)
            : Executor_(std::move(Executor))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error = std::make_error_code(std::errc::operation_canceled);
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ++Writes_;
            BufferSize_ = Buffer.size();
            if (Writes_ == 1)
            {
                Error.clear();
                if (Overreport_)
                {
                    co_return BufferSize_ + 1;
                }
                co_return 0;
            }
            Error = std::make_error_code(std::errc::broken_pipe);
            co_return 0;
        }

        void Close() override {}
        void Cancel() override {}

        std::size_t Writes_{0};
        std::size_t BufferSize_{0};
        bool Overreport_{false};

    private:
        Net::any_io_executor Executor_;
    };

    TEST(ConnDecorator, AnytlsZeroProgressWriteFailsImmediately)
    {
        Net::io_context ioc;
        auto transport = std::make_shared<ZeroProgressTransport>(ioc.get_executor());
        auto Conn = std::make_shared<Anytls::Conn<>>(transport, "password");
        Error Result = Error::None;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->WriteHandshake(0);
                 });

        EXPECT_EQ(Result, Error::IoError);
        EXPECT_EQ(transport->Writes_, 1u);
    }

    TEST(ConnDecorator, AnytlsOverreportedWriteFailsImmediately)
    {
        Net::io_context ioc;
        auto transport = std::make_shared<ZeroProgressTransport>(ioc.get_executor());
        transport->Overreport_ = true;
        auto Conn = std::make_shared<Anytls::Conn<>>(transport, "password");
        Error Result = Error::None;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->WriteHandshake(0);
                 });

        EXPECT_EQ(Result, Error::IoError);
        EXPECT_EQ(transport->Writes_, 1u);
    }

    TEST(ConnDecorator, AnytlsOverreportedReadFailsImmediately)
    {
        Net::io_context ioc;
        auto transport = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        transport->OverreportRead = true;
        auto Conn = std::make_shared<Anytls::Conn<>>(transport, "password");
        Error Result = Error::None;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->ReadHandshake();
                 });

        EXPECT_EQ(Result, Error::UnexpectedEof);
        EXPECT_EQ(transport->ReadsDone, 1u);
    }

    TEST(ConnDecorator, RealityOverreportedReadFailsImmediately)
    {
        Net::io_context ioc;
        auto transport = std::make_shared<Preview::PreviewMockTransport>(ioc.get_executor());
        transport->OverreportRead = true;
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PeerPublicKey{};
        ASSERT_FALSE(Reality::GenerateKeypair(PrivateKey, PeerPublicKey));
        auto Conn = std::make_shared<Reality::Conn<>>(transport, PrivateKey);
        const std::array<std::uint8_t, 32> ClientRandom{};
        const std::array<std::uint8_t, 1> Hello{};
        const Reality::HandshakeParams Params{ClientRandom, Hello};
        std::array<std::uint8_t, Reality::MaxShortIdLen> ShortId{};
        Error Result = Error::None;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->ReadHandshake(PeerPublicKey, Params, ShortId);
                 });

        EXPECT_EQ(Result, Error::UnexpectedEof);
        EXPECT_EQ(transport->ReadsDone, 1u);
    }

    TEST(ConnDecorator, RealityOverreportedWriteFailsImmediately)
    {
        Net::io_context ioc;
        auto transport = std::make_shared<ZeroProgressTransport>(ioc.get_executor());
        transport->Overreport_ = true;
        std::array<std::uint8_t, Reality::KeyLen> PrivateKey{};
        std::array<std::uint8_t, Reality::KeyLen> PeerPublicKey{};
        ASSERT_FALSE(Reality::GenerateKeypair(PrivateKey, PeerPublicKey));
        auto Conn = std::make_shared<Reality::Conn<>>(transport, PrivateKey);
        const std::array<std::uint8_t, 32> ClientRandom{};
        const std::array<std::uint8_t, 71> Hello{};
        const Reality::HandshakeParams Params{ClientRandom, Hello};
        Error Result = Error::None;

        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Result = co_await Conn->WriteHandshake(PeerPublicKey, Params);
                 });

        EXPECT_EQ(Result, Error::IoError);
        EXPECT_EQ(transport->Writes_, 1u);
    }

    /**
     * @brief 断言装饰器透传方法（Executor/Cancel/NextLayer/Release/Close）
     */
    template <typename DecoT>
    auto CheckDecorator(const std::shared_ptr<DecoT> &ConnT, Net::io_context &IoContext) -> void
    {
        (void)IoContext;
        (void)ConnT->Executor();
        EXPECT_NE(ConnT->NextLayer(), nullptr);
        const auto *cconn = ConnT.get();
        EXPECT_NE(cconn->NextLayer(), nullptr);
        EXPECT_EQ(ConnT->template lowest_layer<MemoryStream>(), ConnT->NextLayer());
        ConnT->Cancel();
        ConnT->Close();
        auto released = ConnT->Release();
        EXPECT_NE(released, nullptr);
        EXPECT_EQ(ConnT->NextLayer(), nullptr);
    }

    TEST(ConnDecorator, GunConn)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Conn = std::make_shared<Gun::Conn<>>(std::make_shared<MemoryStream>(std::move(a)));

        // 未握手读写 → not_open
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await Conn->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await Conn->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                 });

        // 客户端握手 → 数据面透传
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     EXPECT_EQ(co_await Conn->WriteHandshake("example.com"), Error::None);
                     std::array<std::byte, 8> wbuf{std::byte{0x42}};
                     std::error_code ec;
                     EXPECT_EQ(co_await Conn->async_write_some(std::span<const std::byte>(wbuf), ec), 8u);

                     // 先读 CONNECT 握手头（"CONNECT example.com HTTP/2\r\n\r\n" 共 30 字节），
                     // 再验证数据面载荷原样透传
                     std::array<std::byte, 64> hdr{};
                     const auto hn = co_await peer->async_read_some(std::span<std::byte>(hdr), ec);
                     EXPECT_EQ(hn, 30u);
                     std::array<std::byte, 8> rbuf{};
                     const auto rn = co_await peer->async_read_some(std::span<std::byte>(rbuf), ec);
                     EXPECT_EQ(rn, 8u);
                     if (rn == 8u)
                     {
                         EXPECT_EQ(static_cast<std::uint8_t>(rbuf[0]), 0x42);
                     }
                 });

        CheckDecorator(Conn, ioc);
    }

    TEST(ConnDecorator, RealityConn)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Reality::Conn<>>(
            std::make_shared<MemoryStream>(std::move(a)), std::array<std::uint8_t, 32>{});
        CheckDecorator(Conn, ioc);
    }

    TEST(ConnDecorator, AnyTlsConn)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn =
            std::make_shared<Anytls::Conn<>>(std::make_shared<MemoryStream>(std::move(a)), "Secret");
        CheckDecorator(Conn, ioc);
    }

    TEST(ConnDecorator, TuicConn)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Conn = std::make_shared<Tuic::Conn<>>(std::make_shared<MemoryStream>(std::move(a)),
                                                 std::array<std::uint8_t, 16>{});
        CheckDecorator(Conn, ioc);
    }

    TEST(ConnDecorator, StreamTransmission)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        // 空句柄：Executor 返回默认执行器，Cancel 空操作
        auto Empty = std::make_shared<Mux::StreamTransmission>(nullptr);
        (void)Empty->Executor();
        Empty->Cancel();
        EXPECT_FALSE(Empty->IsOpen());
        EXPECT_EQ(Empty->Handle(), nullptr);
        Empty->Close();
        Empty->Reset();
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::error_code ec;
                     std::array<std::byte, 4> buf{};
                     const auto r = co_await Empty->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                     ec.clear();
                     const auto w = co_await Empty->async_write_some(std::span<const std::byte>(buf), ec);
                     EXPECT_EQ(w, 0u);
                     EXPECT_EQ(ec, make_error_code(Error::NotOpen));
                 });

        // 非空句柄：Cancel 生效
        auto Client = Mux::Smux::Connect(std::make_shared<MemoryStream>(std::move(a)));
        auto Session = Client.Session();
        EXPECT_TRUE(Client.IsOpen());
        RunCoroutine(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Handle = co_await Session->OpenStream();
                     if (!Handle)
                     {
                         EXPECT_TRUE(false) << "OpenStream Failed";
                         co_return;
                     }
                     auto Stream = std::make_shared<Mux::StreamTransmission>(Handle);
                     EXPECT_TRUE(Stream->IsOpen());
                     EXPECT_EQ(Stream->Handle(), Handle);
                     Stream->Cancel();
                     std::array<std::byte, 4> buf{};
                     std::error_code ec;
                     const auto r = co_await Stream->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     // 非空句柄 Close / Reset（co_spawn 投递）
                     Stream->Close();
                     Stream->Reset();
                     co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Stream->IsOpen());
                 });
    }

} // namespace
