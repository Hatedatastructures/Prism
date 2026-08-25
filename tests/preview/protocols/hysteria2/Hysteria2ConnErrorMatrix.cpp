/**
 * @file Hysteria2ConnErrorMatrix.cpp
 * @brief Hysteria2 Conn/Dgram 错误分支矩阵测试（覆盖率第 2 轮）
 * @details 针对 Hysteria2ConnSession 未覆盖的分支点逐项补齐：
 * 1. Conn：握手发送失败（认证帧 / TCP 帧）、握手各阶段 EOF、
 *    数据报发送 I/O 错误、数据报接收帧错误（EOF / 非法 ATYP /
 *    载荷 I/O 错误）、地址体截断、握手后对端关闭透传
 * 2. Dgram：发送 I/O 错误、接收各阶段 EOF（端口 / 载荷）、
 *    载荷 I/O 错误、地址体截断、透传写错误
 * @note 使用 scripted_transmission 桩注入读取/写入错误与截断数据，
 *      无需依赖对端行为即可覆盖全部错误分支。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Protocols/Hysteria2/Hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;
    namespace net = boost::asio;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto run_coro(net::io_context &ioc, A coro) -> void
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro),
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }

    /// 构造 hysteria2 目标地址
    auto make_addr(Hysteria2::AddressType Type, std::string host, std::uint16_t port)
        -> Hysteria2::Address
    {
        Hysteria2::Address addr{};
        addr.Type = Type;
        addr.Host = std::move(host);
        addr.Port = port;
        return addr;
    }

    /// 可编程传输桩：注入读取数据、捕获写入、按需模拟读写错误与写入限额
    class scripted_transmission final : public Preview::Transmission
    {
    public:
        /**
         * @brief 构造桩
         * @param ex 执行器
         */
        explicit scripted_transmission(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        /** @brief 获取执行器 */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 读取：注入队列消费，耗尽返回 EOF，可注入错误
         * @details 每次读取前经 post 挂起一次，覆盖协程挂起/恢复分支。
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_await net::post(ex_, net::use_awaitable);
            ++reads_done;
            if (reads_done >= read_fail_at)
            {
                ec = make_error_code(Error::io_error);
                co_return 0;
            }
            if (read_pos >= to_read.size())
            {
                co_return 0; // EOF
            }
            const auto n = std::min(Buffer.size(), to_read.size() - read_pos);
            std::memcpy(Buffer.data(), to_read.data() + read_pos, n);
            read_pos += n;
            co_return n;
        }

        /**
         * @brief 写入：捕获数据，超限额返回错误，可注入错误与异常
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (write_throw)
            {
                throw std::runtime_error("scripted Write throw");
            }
            if (write_fail || writes_done >= write_limit)
            {
                ec = make_error_code(Error::io_error);
                co_return 0;
            }
            const auto *src = reinterpret_cast<const std::uint8_t *>(Buffer.data());
            written.insert(written.end(), src, src + Buffer.size());
            ++writes_done;
            co_return Buffer.size();
        }

        /** @brief 关闭桩（后续读返回 EOF） */
        void Close() override
        {
            closed = true;
        }

        /** @brief 取消挂起操作 */
        void Cancel() override
        {
        }

        std::vector<std::uint8_t> to_read; ///< 注入读取数据
        std::vector<std::uint8_t> written; ///< 捕获写入数据
        bool write_fail{false};            ///< 下次写入返回 io_error
        bool write_throw{false};           ///< 写入抛异常（协程异常路径）
        std::size_t write_limit{SIZE_MAX}; ///< 允许成功写入次数上限
        std::size_t writes_done{0};        ///< 已成功写入次数
        std::size_t read_fail_at{SIZE_MAX}; ///< 第 N 次读取返回 io_error
        std::size_t reads_done{0};          ///< 已执行读取次数
        bool closed{false};                 ///< 关闭标志

    private:
        net::any_io_executor ex_;
        std::size_t read_pos{0};
    };

    /// 构造服务端握手输入（认证帧 + TCP 目标帧）
    auto make_server_handshake_bytes(const std::string &password, const Hysteria2::Address &Target)
        -> std::vector<std::uint8_t>
    {
        const auto Auth = Hysteria2::MakeAuthRequest(password);
        const auto Tcp = Hysteria2::BuildTcp(Target, {});
        std::vector<std::uint8_t> wire(Auth.begin(), Auth.end());
        wire.insert(wire.end(), Tcp.begin(), Tcp.end());
        return wire;
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->write_fail = true;
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     const auto err = co_await c->WriteHandshake(
                         make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2ConnError, WriteHandshakeAuthSendThrow)
    {
        net::io_context ioc;

        // 底层写入抛异常 → 异常穿透协程边界
        std::exception_ptr ep;
        net::co_spawn(ioc,
                      [&]() -> net::awaitable<void>
                      {
                          auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                          raw->write_throw = true;
                          auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                          const auto err = co_await c->WriteHandshake(
                              make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80));
                          (void)err;
                      },
                      [&](std::exception_ptr e)
                      {
                          ep = e;
                          ioc.stop();
                      });
        ioc.run();
        EXPECT_TRUE(ep != nullptr);
    }

    TEST(Hysteria2ConnError, WriteHandshakeTcpFrameSendFail)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 认证帧写成功（限额 1），TCP 帧写失败 → io_error
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->write_limit = 1;
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     const auto err = co_await c->WriteHandshake(
                         make_addr(Hysteria2::AddressType::Domain, "example.com", 443));
                     EXPECT_EQ(err, Error::io_error);
                     EXPECT_FALSE(raw->written.empty());
                 });
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthHead)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 对端立即关闭 → 读认证帧头失败 → io_error
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(err, Error::io_error);
                     (void)msg;
                 });
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnAuthBody)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 认证帧头合法但长度字段后的正文缺失 → io_error
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = {0x01, 0x10};
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(err, Error::io_error);
                     (void)msg;
                 });
    }

    TEST(Hysteria2ConnError, ReadHandshakeEofOnTargetAddress)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 认证帧合法，TCP 帧只有 Kind + ATYP + 1 字节地址 → io_error
                     const auto Auth = Hysteria2::MakeAuthRequest("pw");
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read.assign(Auth.begin(), Auth.end());
                     raw->to_read.insert(raw->to_read.end(), {0x01, 0x01, 0xAA});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(err, Error::io_error);
                     (void)msg;
                 });
    }

    TEST(Hysteria2ConnError, ReadHandshakeBadAtypTargetFrame)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 认证帧合法，TCP 帧 ATYP 非法（0x99）→ bad_message
                     const auto Auth = Hysteria2::MakeAuthRequest("pw");
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read.assign(Auth.begin(), Auth.end());
                     raw->to_read.insert(raw->to_read.end(), {0x01, 0x99});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(err, Error::bad_message);
                     (void)msg;
                 });
    }

    TEST(Hysteria2ConnError, SendDatagramIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手成功后写失败 → 数据报发送 io_error
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto herr = co_await c->WriteHandshake(
                         make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, Error::none);
                     raw->write_fail = true;
                     const std::string p = "x";
                     const auto err = co_await c->AsyncSendDatagram(
                         make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnFrame)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手合法，随后对端关闭 → 数据报接收帧头 EOF → unexpected_eof
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", Target);
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(herr, Error::none);
                     (void)msg;
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手合法，UDP 帧 ATYP 非法 → bad_message
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", Target);
                     raw->to_read.insert(raw->to_read.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(herr, Error::none);
                     (void)msg;
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(err, Error::bad_message);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnIds)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧 Kind 后 Id 只有 3 字节 → unexpected_eof
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", Target);
                     raw->to_read.insert(raw->to_read.end(), {0x02, 1, 2, 3});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(herr, Error::none);
                     (void)msg;
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧 Id 完整但 ATYP 缺失 → unexpected_eof
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", Target);
                     raw->to_read.insert(raw->to_read.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(herr, Error::none);
                     (void)msg;
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnPort)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧地址体完整但端口缺失 → unexpected_eof
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", Target);
                     raw->to_read.insert(raw->to_read.end(),
                                         {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(herr, Error::none);
                     (void)msg;
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramPayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧头完整，载荷读取注入错误 → io_error
                     const auto Target = make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", Target);
                     raw->to_read.insert(raw->to_read.end(),
                                         {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(herr, Error::none);
                     (void)msg;
                     // 第 12 次读取（握手 6 次 + 帧头 5 次后）为载荷读取 → io_error
                     raw->read_fail_at = 12;
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->AsyncReceiveDatagram(src, out);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2ConnError, ReadHandshakeAddressBodyEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 域名地址：长度 5 但仅注入 2 字节 → 地址体截断 io_error
                     const auto Auth = Hysteria2::MakeAuthRequest("pw");
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read.assign(Auth.begin(), Auth.end());
                     raw->to_read.insert(raw->to_read.end(), {0x01, 0x02, 0x05, 'a', 'b'});
                     auto c = std::make_shared<Hysteria2::Conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->ReadHandshake();
                     EXPECT_EQ(err, Error::io_error);
                     (void)msg;
                 });
    }

    TEST(Hysteria2ConnError, PassthroughPeerClosed)
    {
        net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手成功后对端关闭：读返回 0，写返回 broken_pipe
                     auto c = std::make_shared<Hysteria2::Conn<>>(
                         std::make_shared<MemoryStream>(std::move(a)), "pw");
                     auto herr = co_await c->WriteHandshake(
                         make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, Error::none);
                     b.Close();
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->AsyncReadSome(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_FALSE(ec);
                     co_await c->AsyncWriteSome(std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_TRUE(ec);
                 });
    }

    TEST(Hysteria2DgramError, SendToIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->write_fail = true;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->AsyncSendTo(
                         make_addr(Hysteria2::AddressType::Ipv4, "1.2.3.4", 80),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramError, ReceiveEofOnPort)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 头 + 地址体完整，端口缺失 → unexpected_eof
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2DgramError, ReceiveEofOnPayload)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 帧头完整，载荷缺失（EOF）→ unexpected_eof
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::unexpected_eof);
                 });
    }

    TEST(Hysteria2DgramError, ReceivePayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 帧头完整，载荷读取注入错误 → io_error（第 4 次读取为载荷）
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50};
                     raw->read_fail_at = 4;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramError, ReceiveAddressBodyEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 域名地址：长度 5 但仅注入 2 字节 → 地址体截断 io_error
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = {0x02, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x05, 'a', 'b'};
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     Hysteria2::Address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->AsyncReceiveFrom(src, payload);
                     EXPECT_EQ(err, Error::io_error);
                 });
    }

    TEST(Hysteria2DgramError, PassthroughWriteBrokenPipe)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 透传写注入错误 → ec 置位
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->write_fail = true;
                     auto dg = std::make_shared<Hysteria2::Dgram<>>(raw);
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto n = co_await dg->AsyncWriteSome(
                         std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                 });
    }

} // namespace
