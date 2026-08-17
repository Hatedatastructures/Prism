/**
 * @file Hysteria2ConnErrorMatrix.cpp
 * @brief Hysteria2 conn/dgram 错误分支矩阵测试（覆盖率第 2 轮）
 * @details 针对 Hysteria2ConnSession 未覆盖的分支点逐项补齐：
 * 1. conn：握手发送失败（认证帧 / TCP 帧）、握手各阶段 EOF、
 *    数据报发送 I/O 错误、数据报接收帧错误（EOF / 非法 ATYP /
 *    载荷 I/O 错误）、地址体截断、握手后对端关闭透传
 * 2. dgram：发送 I/O 错误、接收各阶段 EOF（端口 / 载荷）、
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

#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/hysteria2/hysteria2.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace preview;
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
    auto make_addr(hysteria2::address_type type, std::string host, std::uint16_t port)
        -> hysteria2::address
    {
        hysteria2::address addr{};
        addr.type = type;
        addr.host = std::move(host);
        addr.port = port;
        return addr;
    }

    /// 可编程传输桩：注入读取数据、捕获写入、按需模拟读写错误与写入限额
    class scripted_transmission final : public preview::transmission
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
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 读取：注入队列消费，耗尽返回 EOF，可注入错误
         * @details 每次读取前经 post 挂起一次，覆盖协程挂起/恢复分支。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_await net::post(ex_, net::use_awaitable);
            ++reads_done;
            if (reads_done >= read_fail_at)
            {
                ec = make_error_code(error::io_error);
                co_return 0;
            }
            if (read_pos >= to_read.size())
            {
                co_return 0; // EOF
            }
            const auto n = std::min(buffer.size(), to_read.size() - read_pos);
            std::memcpy(buffer.data(), to_read.data() + read_pos, n);
            read_pos += n;
            co_return n;
        }

        /**
         * @brief 写入：捕获数据，超限额返回错误，可注入错误与异常
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (write_throw)
            {
                throw std::runtime_error("scripted write throw");
            }
            if (write_fail || writes_done >= write_limit)
            {
                ec = make_error_code(error::io_error);
                co_return 0;
            }
            const auto *src = reinterpret_cast<const std::uint8_t *>(buffer.data());
            written.insert(written.end(), src, src + buffer.size());
            ++writes_done;
            co_return buffer.size();
        }

        /** @brief 关闭桩（后续读返回 EOF） */
        void close() override
        {
            closed = true;
        }

        /** @brief 取消挂起操作 */
        void cancel() override
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
    auto make_server_handshake_bytes(const std::string &password, const hysteria2::address &target)
        -> std::vector<std::uint8_t>
    {
        const auto auth = hysteria2::make_auth_request(password);
        const auto tcp = hysteria2::build_tcp(target, {});
        std::vector<std::uint8_t> wire(auth.begin(), auth.end());
        wire.insert(wire.end(), tcp.begin(), tcp.end());
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
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     const auto err = co_await c->write_handshake(
                         make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(err, error::io_error);
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
                          auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                          const auto err = co_await c->write_handshake(
                              make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80));
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
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     const auto err = co_await c->write_handshake(
                         make_addr(hysteria2::address_type::domain, "example.com", 443));
                     EXPECT_EQ(err, error::io_error);
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
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->read_handshake();
                     EXPECT_EQ(err, error::io_error);
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
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->read_handshake();
                     EXPECT_EQ(err, error::io_error);
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
                     const auto auth = hysteria2::make_auth_request("pw");
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read.assign(auth.begin(), auth.end());
                     raw->to_read.insert(raw->to_read.end(), {0x01, 0x01, 0xAA});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->read_handshake();
                     EXPECT_EQ(err, error::io_error);
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
                     const auto auth = hysteria2::make_auth_request("pw");
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read.assign(auth.begin(), auth.end());
                     raw->to_read.insert(raw->to_read.end(), {0x01, 0x99});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->read_handshake();
                     EXPECT_EQ(err, error::bad_message);
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
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto herr = co_await c->write_handshake(
                         make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, error::none);
                     raw->write_fail = true;
                     const std::string p = "x";
                     const auto err = co_await c->async_send_datagram(
                         make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnFrame)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手合法，随后对端关闭 → 数据报接收帧头 EOF → unexpected_eof
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", target);
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->read_handshake();
                     EXPECT_EQ(herr, error::none);
                     (void)msg;
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramBadAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手合法，UDP 帧 ATYP 非法 → bad_message
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", target);
                     raw->to_read.insert(raw->to_read.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x99});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->read_handshake();
                     EXPECT_EQ(herr, error::none);
                     (void)msg;
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(err, error::bad_message);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnIds)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧 kind 后 id 只有 3 字节 → unexpected_eof
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", target);
                     raw->to_read.insert(raw->to_read.end(), {0x02, 1, 2, 3});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->read_handshake();
                     EXPECT_EQ(herr, error::none);
                     (void)msg;
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnAtyp)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧 id 完整但 ATYP 缺失 → unexpected_eof
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", target);
                     raw->to_read.insert(raw->to_read.end(), {0x02, 0, 0, 0, 0, 0, 0, 0, 0});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->read_handshake();
                     EXPECT_EQ(herr, error::none);
                     (void)msg;
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramEofOnPort)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧地址体完整但端口缺失 → unexpected_eof
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", target);
                     raw->to_read.insert(raw->to_read.end(),
                                         {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->read_handshake();
                     EXPECT_EQ(herr, error::none);
                     (void)msg;
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(err, error::unexpected_eof);
                 });
    }

    TEST(Hysteria2ConnError, ReceiveDatagramPayloadIoError)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // UDP 帧头完整，载荷读取注入错误 → io_error
                     const auto target = make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80);
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read = make_server_handshake_bytes("pw", target);
                     raw->to_read.insert(raw->to_read.end(),
                                         {0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 1, 2, 3, 4, 0x00, 0x50});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [herr, msg] = co_await c->read_handshake();
                     EXPECT_EQ(herr, error::none);
                     (void)msg;
                     // 第 12 次读取（握手 6 次 + 帧头 5 次后）为载荷读取 → io_error
                     raw->read_fail_at = 12;
                     hysteria2::address src;
                     std::vector<std::uint8_t> out;
                     const auto err = co_await c->async_receive_datagram(src, out);
                     EXPECT_EQ(err, error::io_error);
                 });
    }

    TEST(Hysteria2ConnError, ReadHandshakeAddressBodyEof)
    {
        net::io_context ioc;

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 域名地址：长度 5 但仅注入 2 字节 → 地址体截断 io_error
                     const auto auth = hysteria2::make_auth_request("pw");
                     auto raw = std::make_shared<scripted_transmission>(ioc.get_executor());
                     raw->to_read.assign(auth.begin(), auth.end());
                     raw->to_read.insert(raw->to_read.end(), {0x01, 0x02, 0x05, 'a', 'b'});
                     auto c = std::make_shared<hysteria2::conn<>>(raw, "pw");
                     auto [err, msg] = co_await c->read_handshake();
                     EXPECT_EQ(err, error::io_error);
                     (void)msg;
                 });
    }

    TEST(Hysteria2ConnError, PassthroughPeerClosed)
    {
        net::io_context ioc;
        auto [a, b] = make_memory_pair(ioc.get_executor());

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     // 握手成功后对端关闭：读返回 0，写返回 broken_pipe
                     auto c = std::make_shared<hysteria2::conn<>>(
                         std::make_shared<memory_stream>(std::move(a)), "pw");
                     auto herr = co_await c->write_handshake(
                         make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80));
                     EXPECT_EQ(herr, error::none);
                     b.close();
                     std::array<std::byte, 64> buf{};
                     std::error_code ec;
                     const auto n = co_await c->async_read_some(buf, ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_FALSE(ec);
                     co_await c->async_write_some(std::span<const std::byte>(buf.data(), 4), ec);
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
                     auto dg = std::make_shared<hysteria2::dgram<>>(raw);
                     const std::string p = "x";
                     const auto err = co_await dg->async_send_to(
                         make_addr(hysteria2::address_type::ipv4, "1.2.3.4", 80),
                         std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(p.data()),
                                                       p.size()));
                     EXPECT_EQ(err, error::io_error);
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
                     auto dg = std::make_shared<hysteria2::dgram<>>(raw);
                     hysteria2::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::unexpected_eof);
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
                     auto dg = std::make_shared<hysteria2::dgram<>>(raw);
                     hysteria2::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::unexpected_eof);
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
                     auto dg = std::make_shared<hysteria2::dgram<>>(raw);
                     hysteria2::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::io_error);
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
                     auto dg = std::make_shared<hysteria2::dgram<>>(raw);
                     hysteria2::address src;
                     std::vector<std::uint8_t> payload;
                     const auto err = co_await dg->async_receive_from(src, payload);
                     EXPECT_EQ(err, error::io_error);
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
                     auto dg = std::make_shared<hysteria2::dgram<>>(raw);
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto n = co_await dg->async_write_some(
                         std::span<const std::byte>(buf.data(), 4), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_TRUE(ec);
                 });
    }

} // namespace
