/**
 * @file TransportDecoratorCoverage.cpp
 * @brief tests/common/core/transport/ 装饰器模块覆盖率测试
 * @details 覆盖八个传输装饰器/叶子模块：
 * - pad_transport：填充启用/禁用、最小/最大边界、数据透传、大块透传兜底、
 *   随机填充确定性（不破坏数据）、stop_after 透传
 * - preview：预读字节优先返回、耗尽后透传底层、EOF、wrap_with_preview
 * - snapshot：捕获/回滚重放、回滚后继续读取、写入后禁止回滚
 * - reliable：真实 TCP 读满/写满、EOF、对端关闭写错误、错误中断返回已读字节
 * - encrypted：内存管道上的真实 TLS 握手 + 加解密往返、握手失败恢复、
 *   null 入站、访问器/关闭/取消
 * - connector：预读注入、委托底层、移动语义、release、成员 async_read/write
 * - unreliable：UDP 往返、未设远程写错误、来源过滤、访问器
 * - unreliable：往返、未打开写/读错误、close/cancel
 * @note 底层一律使用 memory_stream（make_memory_pair）或真实 loopback socket。
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/transport/connector.hpp>
#include <common/core/transport/encrypted.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/core/transport/pad.hpp>
#include <common/core/transport/preview.hpp>
#include <common/core/transport/reliable.hpp>
#include <common/core/transport/snapshot.hpp>
#include <common/core/transport/unreliable.hpp>
#include <common/core/transport/unreliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using namespace preview::transport;

    /**
     * @brief 驱动协程运行，异常透传
     * @param ioc io_context
     * @param coro 协程
     */
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

    /**
     * @brief 捕获写入字节的内存 sink（pad 测试用）
     */
    class fake_sink final : public preview::transmission
    {
    public:
        explicit fake_sink(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buf, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            written_.insert(written_.end(), buf.begin(), buf.end());
            co_return buf.size();
        }

        void close() override
        {
        }

        void cancel() override
        {
        }

        std::vector<std::byte> written_; ///< 捕获的写入字节

    private:
        net::any_io_executor ex_;
    };

    /**
     * @brief 可编程行为 mock（reliable 组合操作错误路径用）
     */
    class programmable_mock final : public preview::transmission
    {
    public:
        explicit programmable_mock(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto executor() const -> executor_type override
        {
            return ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (read_calls_++ == 0)
            {
                ec.clear();
                co_return read_first_n_;
            }
            ec = read_ec_;
            co_return 0;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            co_return write_n_;
        }

        void close() override
        {
        }

        void cancel() override
        {
        }

        std::size_t read_first_n_{0};  ///< 首次读返回字节数
        std::error_code read_ec_{};    ///< 后续读错误
        std::size_t write_n_{0};       ///< 每次写返回字节数

    private:
        net::any_io_executor ex_;
        std::size_t read_calls_{0};
    };

    /**
     * @brief 生成自签名证书并加载到服务端 SSL 上下文
     * @details RSA 2048 而非 Ed25519，避免 BoringSSL TLS 1.3
     * "NO_COMMON_SIGNATURE_ALGORITHMS" 错误
     * @param ctx 目标上下文
     */
    void load_self_signed_cert(ssl::context &ctx)
    {
        auto *pkey = EVP_PKEY_new();
        auto *bn = BN_new();
        BN_set_word(bn, RSA_F4);
        auto *rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        BN_free(bn);

        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

        auto *name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Test"),
                                   -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_NAME_free(name);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(ctx.native_handle(), x509);
        SSL_CTX_use_PrivateKey(ctx.native_handle(), pkey);

        X509_free(x509);
        EVP_PKEY_free(pkey);
    }

    /**
     * @brief 将 string_view 转为 byte span
     * @param s 源数据
     * @return byte span
     */
    [[nodiscard]] auto sv_bytes(std::string_view s) -> std::span<const std::byte>
    {
        return preview::as_bytes_span(s);
    }

    // ══════════════════════ pad_transport ══════════════════════

    TEST(PadTransport, EnabledDisabled)
    {
        preview::transport::pad_config def;
        EXPECT_TRUE(def.enabled());

        preview::transport::pad_config off;
        off.pad_targets = "";
        EXPECT_FALSE(off.enabled());

        // 禁用填充：透传零开销（写入字节数 == 数据长度）
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        preview::transport::pad_transport pad(sink, off);
        const std::string_view msg = "raw-passthrough";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await pad.async_write_some(sv_bytes(msg), ec);
                EXPECT_EQ(n, msg.size());
                EXPECT_FALSE(ec);
            },
            net::detached);
        ioc.run();
        EXPECT_EQ(sink->written_.size(), msg.size());
        EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<const std::byte>(sink->written_))), msg);
    }

    TEST(PadTransport, MinBoundaryPadToTarget)
    {
        // 固定目标 "5"：小数据补齐到 5 字节，大数据零填充
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        preview::transport::pad_config cfg;
        cfg.pad_targets = "5";
        cfg.max_pad_bytes = 0; // 数据 >= 目标时零填充，保证确定性
        preview::transport::pad_transport pad(sink, cfg);

        std::array<std::byte, 3> small{std::byte{1}, std::byte{2}, std::byte{3}};
        std::array<std::byte, 8> large{};
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n1 = co_await pad.async_write_some(std::span<const std::byte>(small), ec);
                EXPECT_FALSE(ec);
                EXPECT_EQ(n1, 3u); // 返回值 = 原始数据长度
                EXPECT_EQ(sink->written_.size(), 5u); // 补齐到目标 5

                const auto n2 = co_await pad.async_write_some(std::span<const std::byte>(large), ec);
                EXPECT_FALSE(ec);
                EXPECT_EQ(n2, 8u);
                EXPECT_EQ(sink->written_.size(), 13u); // 数据 >= 目标 → 零填充
            },
            net::detached);
        ioc.run();
    }

    TEST(PadTransport, MaxBoundaryRange)
    {
        // 区间 "80-150"：填充后总大小必须落在区间内
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        preview::transport::pad_config cfg;
        cfg.pad_targets = "80-150";
        preview::transport::pad_transport pad(sink, cfg);

        const std::string_view msg = "ten-bytes";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await pad.async_write_some(sv_bytes(msg), ec);
                EXPECT_FALSE(ec);
                EXPECT_EQ(n, msg.size());
            },
            net::detached);
        ioc.run();
        ASSERT_GE(sink->written_.size(), 80u);
        ASSERT_LE(sink->written_.size(), 150u);
        // 数据前缀完好
        const auto wire = preview::as_str_view(preview::as_u8(std::span<const std::byte>(sink->written_)));
        EXPECT_EQ(wire.substr(0, msg.size()), msg);
    }

    TEST(PadTransport, DataPassthroughOverPipe)
    {
        // 经 memory pair 往返：填充不破坏数据
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     preview::transport::pad_config cfg;
                     preview::transport::pad_transport pad(sa, cfg);

                     const std::string_view msg = "hello world, padding must not corrupt me";
                     std::error_code ec;
                     const auto n = co_await pad.async_write_some(sv_bytes(msg), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(n, msg.size());

                     // 对端只读原始数据长度字节，验证逐字节一致
                     std::vector<std::byte> rbuf(msg.size());
                     const auto r = co_await sb->async_read(std::span<std::byte>(rbuf), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(r, msg.size());
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<const std::byte>(rbuf))), msg);
                 });
    }

    TEST(PadTransport, LargeChunkBypass)
    {
        // 数据 + 填充 > pad_buf_（16384+256）→ 直接透传
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        preview::transport::pad_config cfg;
        preview::transport::pad_transport pad(sink, cfg);

        constexpr std::size_t big = 17000;
        std::vector<std::byte> payload(big, std::byte{0x5A});
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await pad.async_write_some(std::span<const std::byte>(payload), ec);
                EXPECT_FALSE(ec);
                EXPECT_EQ(n, big);
            },
            net::detached);
        ioc.run();
        ASSERT_EQ(sink->written_.size(), big);
        EXPECT_EQ(sink->written_[0], std::byte{0x5A});
        EXPECT_EQ(sink->written_[big - 1], std::byte{0x5A});
    }

    TEST(PadTransport, RandomPaddingDeterminism)
    {
        // 两个独立 pad（不同 CSPRNG 密钥）写相同数据：填充内容不同但数据不破坏
        net::io_context ioc;
        auto sink1 = std::make_shared<fake_sink>(ioc.get_executor());
        auto sink2 = std::make_shared<fake_sink>(ioc.get_executor());
        preview::transport::pad_config cfg;
        cfg.pad_targets = "30-50";
        preview::transport::pad_transport pad1(sink1, cfg);
        preview::transport::pad_transport pad2(sink2, cfg);

        const std::string_view msg = "0123456789";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n1 = co_await pad1.async_write_some(sv_bytes(msg), ec);
                EXPECT_EQ(n1, msg.size());
                EXPECT_FALSE(ec);
                const auto n2 = co_await pad2.async_write_some(sv_bytes(msg), ec);
                EXPECT_EQ(n2, msg.size());
                EXPECT_FALSE(ec);
            },
            net::detached);
        ioc.run();

        ASSERT_GE(sink1->written_.size(), 30u);
        ASSERT_LE(sink1->written_.size(), 50u);
        ASSERT_GE(sink2->written_.size(), 30u);
        ASSERT_LE(sink2->written_.size(), 50u);
        const auto w1 = preview::as_str_view(preview::as_u8(std::span<const std::byte>(sink1->written_)));
        const auto w2 = preview::as_str_view(preview::as_u8(std::span<const std::byte>(sink2->written_)));
        EXPECT_EQ(w1.substr(0, msg.size()), msg);
        EXPECT_EQ(w2.substr(0, msg.size()), msg);
        EXPECT_NE(w1, w2); // 不同密钥 → 不同填充
    }

    TEST(PadTransport, StopAfterPassthrough)
    {
        // stop_after = 2：前两次填充，之后透传
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        preview::transport::pad_config cfg;
        cfg.pad_targets = "20";
        cfg.stop_after = 2;
        preview::transport::pad_transport pad(sink, cfg);

        const std::string_view msg = "abc";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                for (std::size_t i = 0; i < 3; ++i)
                {
                    const auto n = co_await pad.async_write_some(sv_bytes(msg), ec);
                    EXPECT_EQ(n, 3u);
                    EXPECT_FALSE(ec);
                }
            },
            net::detached);
        ioc.run();

        ASSERT_EQ(sink->written_.size(), 20u + 20u + 3u); // 2 次补齐到 20 + 1 次透传
        const auto wire = preview::as_str_view(preview::as_u8(std::span<const std::byte>(sink->written_)));
        EXPECT_EQ(wire.substr(0, 3), "abc");
        EXPECT_EQ(wire.substr(20, 3), "abc");
        EXPECT_EQ(wire.substr(40, 3), "abc");
    }

    // ══════════════════════ preview ══════════════════════

    TEST(Preview, PrereadReturnedFirst)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     const std::string_view preread = "ABCDEF";
                     preview::transport::preview pv(sb, sv_bytes(preread));

                     std::array<std::byte, 3> buf{};
                     std::error_code ec;
                     auto n = co_await pv.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "ABC");
                     n = co_await pv.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "DEF");
                 });
    }

    TEST(Preview, ExhaustedDelegatesToInner)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     // 预读 4 字节，底层还有 3 字节
                     std::error_code ec;
                     co_await sa->async_write_some(sv_bytes("XYZ"), ec);

                     const std::string_view preread = "PRE-";
                     preview::transport::preview pv(sb, sv_bytes(preread));

                     std::array<std::byte, 4> buf{};
                     auto n = co_await pv.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "PRE-");

                     // 预读耗尽 → 委托底层
                     n = co_await pv.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(3))), "XYZ");
                 });
    }

    TEST(Preview, EofAfterPreread)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     sa->shutdown(); // 对端半关（EOF）

                     preview::transport::preview pv(sb, sv_bytes("ab"));
                     std::array<std::byte, 4> buf{};
                     std::error_code ec;
                     auto n = co_await pv.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 2u);
                     EXPECT_FALSE(ec);
                     // 预读耗尽后读取底层 → EOF
                     n = co_await pv.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_FALSE(ec);
                 });
    }

    TEST(Preview, WrapWithPreviewBehavior)
    {
        net::io_context ioc;
        auto [a, b] = preview::make_memory_pair(ioc.get_executor());
        auto sa = std::make_shared<preview::memory_stream>(std::move(a));
        auto sb = std::make_shared<preview::memory_stream>(std::move(b));

        // 空预读 → 不包装
        auto not_wrapped = preview::transport::wrap_with_preview(sa, {});
        EXPECT_EQ(not_wrapped.get(), sa.get());

        // 非空预读 → 包装为 preview
        auto wrapped = preview::transport::wrap_with_preview(sb, sv_bytes("hello"));
        auto *pv = dynamic_cast<preview::transport::preview *>(wrapped.get());
        ASSERT_NE(pv, nullptr);
        EXPECT_EQ(pv->next_layer(), sb.get());
        EXPECT_EQ(wrapped->transport_type(), preview::transmission::type::tcp);

        // completion-handler 风格预读路径
        net::io_context ioc2;
        std::promise<std::pair<boost::system::error_code, std::size_t>> done;
        auto fut = done.get_future();
        preview::transport::preview pv2(sb, sv_bytes("hi"));
        std::array<std::byte, 8> buf{};
        pv2.async_read_some(std::span<std::byte>(buf), [&](boost::system::error_code ec, std::size_t n)
                            { done.set_value({ec, n}); });
        ioc2.run();
        const auto [ec, n] = fut.get();
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, 2u);
        EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(2))), "hi");
    }

    // ══════════════════════ snapshot ══════════════════════

    TEST(Snapshot, CaptureRewindReplay)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     std::error_code ec;
                     co_await sa->async_write_some(sv_bytes("0123456789"), ec);

                     auto snap = std::make_shared<preview::transport::snapshot>(sb);
                     EXPECT_TRUE(snap->can_rewind());
                     EXPECT_EQ(snap->next_layer(), sb.get());

                     std::array<std::byte, 4> buf{};
                     auto n = co_await snap->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "0123");

                     snap->rewind();
                     EXPECT_TRUE(snap->can_rewind());

                     n = co_await snap->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "0123");
                 });
    }

    TEST(Snapshot, ContinueAfterRewind)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     std::error_code ec;
                     co_await sa->async_write_some(sv_bytes("0123456789"), ec);

                     auto snap = std::make_shared<preview::transport::snapshot>(sb);

                     // 读 6 字节，回滚，再读完
                     std::array<std::byte, 6> buf{};
                     auto n = co_await snap->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 6u);
                     snap->rewind();
                     n = co_await snap->async_read(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 6u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "012345");

                     // 回放完剩余捕获，再读新数据
                     std::array<std::byte, 8> buf2{};
                     n = co_await snap->async_read_some(std::span<std::byte>(buf2), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf2).first(4))),
                               "6789");

                     co_await sa->async_write_some(sv_bytes("abcd"), ec);
                     n = co_await snap->async_read_some(std::span<std::byte>(buf2), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf2).first(4))),
                               "abcd");
                 });
    }

    TEST(Snapshot, WriteDisablesRewind)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     auto snap = std::make_shared<preview::transport::snapshot>(sb);

                     // 写入委托给底层
                     std::error_code ec;
                     const auto n = co_await snap->async_write_some(sv_bytes("out"), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(n, 3u);
                     // 写入后禁止回滚
                     EXPECT_FALSE(snap->can_rewind());

                     // 对端收到写入数据
                     std::array<std::byte, 8> buf{};
                     const auto r = co_await sa->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 3u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(3))),
                               "out");

                     // close/cancel 委托底层
                     snap->close();
                     snap->cancel();
                     EXPECT_FALSE(sb->is_open());
                     EXPECT_TRUE(sa->is_open()); // 对端不受本端全关影响
                 });
    }

    // ══════════════════════ encrypted ══════════════════════

    TEST(Encrypted, SslHandshakeNullInbound)
    {
        net::io_context ioc;
        ssl::context ctx(ssl::context::tls_server);
        std::tuple<preview::fault::code, encrypted::shared_stream, preview::shared_transmission> result;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     result = co_await encrypted::ssl_handshake(nullptr, ctx);
                 });
        auto &[code, stream, recovered] = result;
        EXPECT_EQ(code, preview::fault::code::io_error);
        EXPECT_EQ(stream, nullptr);
        EXPECT_EQ(recovered, nullptr);
    }

    TEST(Encrypted, HandshakeFailureRecoversTransport)
    {
        net::io_context ioc;
        ssl::context server_ctx(ssl::context::tls_server);
        load_self_signed_cert(server_ctx);

        std::tuple<preview::fault::code, encrypted::shared_stream, preview::shared_transmission> result;
        std::exception_ptr coro_ep;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                // 客户端发送非 TLS 垃圾数据
                std::error_code ec;
                co_await sa->async_write_some(sv_bytes("GARBAGE-not-a-client-hello"), ec);

                result = co_await encrypted::ssl_handshake(sb, server_ctx);
            },
            [&](std::exception_ptr e)
            {
                coro_ep = e;
                ioc.stop();
            });
        ioc.run();

        if (coro_ep)
        {
            try
            {
                std::rethrow_exception(coro_ep);
            }
            catch (const std::exception &e)
            {
                printf("DBG coroutine exception: %s\n", e.what());
            }
        }
        printf("DBG code=%d stream=%p recovered=%p\n",
               static_cast<int>(std::get<0>(result)), (void *)std::get<1>(result).get(),
               (void *)std::get<2>(result).get());

        auto &[code, stream, recovered] = result;
        EXPECT_NE(code, preview::fault::code::success);
        EXPECT_EQ(stream, nullptr);
        ASSERT_NE(recovered, nullptr); // 失败后从 connector 恢复底层传输
        EXPECT_EQ(recovered->transport_type(), preview::transmission::type::tcp);
    }

    TEST(Encrypted, TlsRoundTripOverMemoryPipe)
    {
        using namespace boost::asio::experimental::awaitable_operators;

        net::io_context ioc;
        ssl::context server_ctx(ssl::context::tls_server);
        load_self_signed_cert(server_ctx);
        ssl::context client_ctx(ssl::context::tls_client);
        client_ctx.set_verify_mode(ssl::verify_none);

        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     // 服务端握手
                     auto server_handshake = [&]() -> net::awaitable<encrypted::shared_stream>
                     {
                         auto [code, stream, recovered] = co_await encrypted::ssl_handshake(sb, server_ctx);
                         EXPECT_EQ(code, preview::fault::code::success);
                         co_return stream;
                     };

                     // 客户端握手
                     auto client_handshake = [&]() -> net::awaitable<encrypted::shared_stream>
                     {
                         preview::transport::connector c(sa);
                         auto stream = std::make_shared<encrypted::stream_type>(std::move(c), client_ctx);
                         boost::system::error_code ec;
                         co_await stream->async_handshake(ssl::stream_base::client,
                                                           net::redirect_error(net::use_awaitable, ec));
                         EXPECT_FALSE(ec) << ec.message();
                         co_return stream;
                     };

                     auto [s_stream, c_stream] = co_await (server_handshake() && client_handshake());
                     if (!s_stream || !c_stream)
                     {
                         EXPECT_TRUE(false) << "TLS handshake failed";
                         co_return;
                     }

                     auto server_t = std::make_shared<encrypted>(s_stream);
                     auto client_t = std::make_shared<encrypted>(c_stream);

                     // 装饰器访问器（next_layer 穿透 ssl::stream → connector 到底层）
                     EXPECT_EQ(client_t->transport_type(), preview::transmission::type::tcp);
                     EXPECT_NE(client_t->next_layer(), nullptr);

                     // 客户端 → 服务端（加密写 → 解密读）
                     std::error_code ec;
                     const auto w1 = co_await client_t->async_write_some(sv_bytes("hello"), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(w1, 5u);
                     std::array<std::byte, 16> buf{};
                     auto r = co_await server_t->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 5u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(5))),
                               "hello");

                     // 服务端 → 客户端
                     const auto w2 = co_await server_t->async_write_some(sv_bytes("world"), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(w2, 5u);
                     r = co_await client_t->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 5u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(5))),
                               "world");

                     // 大块往返
                     std::vector<std::byte> big(4096, std::byte{0x77});
                     const auto w3 = co_await client_t->async_write(std::span<const std::byte>(big), ec);
                     EXPECT_EQ(w3, big.size());
                     std::vector<std::byte> rbig(big.size());
                     const auto r3 = co_await server_t->async_read(std::span<std::byte>(rbig), ec);
                     EXPECT_EQ(r3, big.size());
                     EXPECT_EQ(std::memcmp(rbig.data(), big.data(), big.size()), 0);

                     // close/cancel 不崩溃（SSL_shutdown + 底层关闭）
                     client_t->cancel();
                     server_t->cancel();
                     client_t->close();
                     server_t->close();
                 });
    }

    TEST(Encrypted, AccessorsAndRelease)
    {
        net::io_context ioc;
        ssl::context ctx(ssl::context::tls_server);

        auto [a, b] = preview::make_memory_pair(ioc.get_executor());
        auto sa = std::make_shared<preview::memory_stream>(std::move(a));
        preview::transport::connector c(sa);
        auto stream = std::make_shared<encrypted::stream_type>(std::move(c), ctx);

        auto t = std::make_shared<encrypted>(stream);
        EXPECT_EQ(t->transport_type(), preview::transmission::type::tcp);
        EXPECT_NE(t->next_layer(), nullptr);
        EXPECT_EQ(t->stream().native_handle(), stream->native_handle());
        EXPECT_NO_THROW((void)t->executor());

        // close/cancel（未握手流上安全）
        EXPECT_NO_THROW(t->cancel());
        EXPECT_NO_THROW(t->close());

        auto released = t->release_stream();
        EXPECT_EQ(released.get(), stream.get());
    }

    // ══════════════════════ connector ══════════════════════

    TEST(Connector, PrereadInjectionThenDelegate)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     // 底层先有数据（预读注入应优先返回）
                     std::error_code ec;
                     co_await sa->async_write_some(sv_bytes("inner-data"), ec);

                     preview::transport::connector conn(sb, sv_bytes("PRE"));
                     std::array<std::byte, 8> buf{};
                     boost::system::error_code c_ec;
                     auto n = co_await conn.async_read_some(net::buffer(buf),
                                                            net::redirect_error(net::use_awaitable, c_ec));
                     EXPECT_FALSE(c_ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(3))),
                               "PRE");

                     // 预读耗尽 → 委托底层
                     c_ec.clear();
                     n = co_await conn.async_read_some(net::buffer(buf),
                                                       net::redirect_error(net::use_awaitable, c_ec));
                     EXPECT_FALSE(c_ec);
                     EXPECT_EQ(n, 8u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), "inner-da");
                 });
    }

    TEST(Connector, WriteDelegation)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     preview::transport::connector conn(sb);
                     const std::string_view msg = "write-me";
                     boost::system::error_code w_ec;
                     const auto n = co_await conn.async_write_some(
                         net::buffer(msg.data(), msg.size()), net::redirect_error(net::use_awaitable, w_ec));
                     EXPECT_FALSE(w_ec);
                     EXPECT_EQ(n, msg.size());

                     std::array<std::byte, 16> buf{};
                     std::error_code ec;
                     const auto r = co_await sa->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, msg.size());
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(r))), msg);
                 });
    }

    TEST(Connector, MemberAsyncReadWrite)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = preview::make_memory_pair(ioc.get_executor());
                     auto sa = std::make_shared<preview::memory_stream>(std::move(a));
                     auto sb = std::make_shared<preview::memory_stream>(std::move(b));

                     preview::transport::connector conn(sb);
                     const std::string_view msg = "member-loop";
                     std::error_code ec;
                     const auto w = co_await conn.async_write(std::span<const std::byte>(sv_bytes(msg)), ec);
                     EXPECT_EQ(w, msg.size());
                     EXPECT_FALSE(ec);

                     preview::transport::connector conn_reader(sa);
                     std::vector<std::byte> buf(msg.size());
                     const auto r = co_await conn_reader.async_read(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, msg.size());
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf))), msg);
                 });
    }

    TEST(Connector, MoveReleaseAccessors)
    {
        net::io_context ioc;
        auto [a, b] = preview::make_memory_pair(ioc.get_executor());
        auto sa = std::make_shared<preview::memory_stream>(std::move(a));
        auto sb = std::make_shared<preview::memory_stream>(std::move(b));

        preview::transport::connector conn(sb);
        EXPECT_EQ(&conn.transmission(), sb.get());
        EXPECT_EQ(conn.executor(), conn.get_executor());

        // 移动构造
        preview::transport::connector moved(std::move(conn));
        // 移动赋值
        preview::transport::connector assigned(
            std::make_shared<preview::memory_stream>(ioc.get_executor()));
        assigned = std::move(moved);

        // release 返回底层传输
        auto released = assigned.release();
        EXPECT_EQ(released.get(), sb.get());
    }

    // ══════════════════════ reliable ══════════════════════

    TEST(Reliable, LoopbackReadWriteFull)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::ip::tcp::acceptor acceptor(ioc, {net::ip::tcp::v4(), 0});
                     const auto ep = acceptor.local_endpoint();
                     const auto connect_ep =
                         net::ip::tcp::endpoint(net::ip::address_v4::loopback(), ep.port());

                     std::shared_ptr<preview::transport::reliable> server;
                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         server = std::make_shared<preview::transport::reliable>(std::move(sock));
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     preview::transport::reliable client(ioc.get_executor());
                     boost::system::error_code oec;
                     client.native_socket().open(net::ip::tcp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "open failed: " << oec.message();
                         co_return;
                     }
                     co_await client.native_socket().async_connect(connect_ep, net::use_awaitable);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     if (!server)
                     {
                         EXPECT_TRUE(false) << "accept failed";
                         co_return;
                     }

                     // 客户端写满 5 字节，服务端读满 5 字节
                     std::error_code ec;
                     const auto w = co_await client.async_write(sv_bytes("hello"), ec);
                     EXPECT_EQ(w, 5u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 8> buf{};
                     const auto r = co_await server->async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 5u);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(5))),
                               "hello");

                     // 反向：服务端写 3，客户端读满 3
                     const auto w2 = co_await server->async_write(sv_bytes("xyz"), ec);
                     EXPECT_EQ(w2, 3u);
                     const auto r2 = co_await client.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r2, 3u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(3))),
                               "xyz");

                     client.close();
                     server->close();
                 });
    }

    TEST(Reliable, ReadEofOnShutdown)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::ip::tcp::acceptor acceptor(ioc, {net::ip::tcp::v4(), 0});
                     const auto ep = acceptor.local_endpoint();
                     const auto connect_ep =
                         net::ip::tcp::endpoint(net::ip::address_v4::loopback(), ep.port());

                     std::shared_ptr<preview::transport::reliable> server;
                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         server = std::make_shared<preview::transport::reliable>(std::move(sock));
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     preview::transport::reliable client(ioc.get_executor());
                     boost::system::error_code oec;
                     client.native_socket().open(net::ip::tcp::v4(), oec);
                     co_await client.native_socket().async_connect(connect_ep, net::use_awaitable);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);

                     // 半关写方向 → 对端读返回 0（EOF；TCP EOF 以 eof 错误码呈现）
                     client.shutdown_write();
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto r = co_await server->async_read(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(!ec || ec.message() == "eof") << ec.message();
                     client.close();
                     server->close();
                 });
    }

    TEST(Reliable, BrokenPipeOnPeerClose)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     net::ip::tcp::acceptor acceptor(ioc, {net::ip::tcp::v4(), 0});
                     const auto ep = acceptor.local_endpoint();
                     const auto connect_ep =
                         net::ip::tcp::endpoint(net::ip::address_v4::loopback(), ep.port());

                     std::shared_ptr<preview::transport::reliable> server;
                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         server = std::make_shared<preview::transport::reliable>(std::move(sock));
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     preview::transport::reliable client(ioc.get_executor());
                     boost::system::error_code oec;
                     client.native_socket().open(net::ip::tcp::v4(), oec);
                     co_await client.native_socket().async_connect(connect_ep, net::use_awaitable);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);

                     // 对端先半关（发送 FIN）再全关
                     server->shutdown_write();
                     server->close();

                     // 本端读：EOF 或错误均可（FIN/RST 到达顺序不定）
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto r = co_await client.async_read(std::span<std::byte>(buf), ec);
                     EXPECT_TRUE(r == 0u || ec) << "对端关闭后读应返回 EOF 或错误";

                     // 写 → 必须出错（RST/broken pipe）
                     std::error_code werr;
                     bool failed = false;
                     for (int i = 0; i < 20 && !failed; ++i)
                     {
                         const auto w = co_await client.async_write(sv_bytes("data"), werr);
                         if (werr || w == 0)
                         {
                             failed = true;
                         }
                     }
                     EXPECT_TRUE(failed) << "对端关闭后写入应失败";

                     client.close();
                 });
    }

    TEST(Reliable, ErrorInterruptReturnsPartial)
    {
        // 组合操作：先读 3 字节，再遇错误 → 返回已读字节
        net::io_context ioc;
        auto mock = std::make_shared<programmable_mock>(ioc.get_executor());
        mock->read_first_n_ = 3;
        mock->read_ec_ = std::make_error_code(std::errc::io_error);

        std::error_code ec;
        std::size_t got = 0;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                std::array<std::byte, 8> buf{};
                got = co_await mock->async_read(std::span<std::byte>(buf), ec);
            },
            net::detached);
        ioc.run();
        EXPECT_EQ(got, 3u);
        EXPECT_TRUE(ec);
    }

    TEST(Reliable, WriteZeroMeansBrokenPipe)
    {
        // async_write 循环中 n==0 且无错误 → 置 broken_pipe
        net::io_context ioc;
        auto mock = std::make_shared<programmable_mock>(ioc.get_executor());
        mock->write_n_ = 0;

        std::error_code ec;
        std::size_t got = 0;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                std::array<std::byte, 8> buf{};
                got = co_await mock->async_write(std::span<const std::byte>(buf), ec);
            },
            net::detached);
        ioc.run();
        EXPECT_EQ(got, 0u);
        ASSERT_TRUE(ec);
        EXPECT_EQ(ec, preview::make_error_code(preview::error::broken_pipe));
    }

    TEST(Reliable, AccessorsAndRelease)
    {
        net::io_context ioc;
        preview::transport::reliable t(ioc.get_executor());

        EXPECT_EQ(t.transport_type(), preview::transmission::type::tcp);
        EXPECT_EQ(t.next_layer(), nullptr);
        EXPECT_EQ(t.lowest_layer<preview::transport::reliable>(), &t);
        EXPECT_NO_THROW((void)t.executor());

        // 构造后 socket 未打开：release 返回未打开的 socket
        auto sock = t.release_socket();
        ASSERT_TRUE(sock.has_value());
        EXPECT_FALSE(sock->is_open());
        // 二次 release：无 socket → nullopt
        EXPECT_FALSE(t.release_socket().has_value());

        preview::transport::reliable t2(ioc.get_executor());
        EXPECT_NO_THROW(t2.close());
        EXPECT_NO_THROW(t2.cancel());
    }

    // ══════════════════════ unreliable ══════════════════════

    TEST(Unreliable, DatagramRoundTrip)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     preview::transport::unreliable server(ioc.get_executor());
                     preview::transport::unreliable client(ioc.get_executor());

                     boost::system::error_code oec;
                     server.native_socket().open(net::ip::udp::v4(), oec);
                     server.native_socket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "server open/bind failed: " << oec.message();
                         co_return;
                     }
                     client.native_socket().open(net::ip::udp::v4(), oec);
                     client.native_socket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "client open/bind failed: " << oec.message();
                         co_return;
                     }

                     client.set_remote(server.native_socket().local_endpoint());
                     EXPECT_TRUE(client.remote_endpoint().has_value());

                     // 客户端 → 服务端（服务端首次接收自动记录远程）
                     std::error_code ec;
                     const auto w = co_await client.async_write_some(sv_bytes("ping"), ec);
                     EXPECT_EQ(w, 4u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 16> buf{};
                     auto r = co_await server.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(4))),
                               "ping");
                     EXPECT_TRUE(server.remote_endpoint().has_value());

                     // 服务端回写（远程已记录）
                     const auto w2 = co_await server.async_write_some(sv_bytes("pong"), ec);
                     EXPECT_EQ(w2, 4u);
                     r = co_await client.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(4))),
                               "pong");

                     server.close();
                     client.close();
                 });
    }

    TEST(Unreliable, WriteWithoutRemoteFails)
    {
        net::io_context ioc;
        preview::transport::unreliable u(ioc.get_executor());
        boost::system::error_code oec;
        u.native_socket().open(net::ip::udp::v4(), oec);
        u.native_socket().bind({net::ip::udp::v4(), 0}, oec);
        ASSERT_FALSE(oec);
        EXPECT_FALSE(u.remote_endpoint().has_value());

        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await u.async_write_some(sv_bytes("nope"), ec);
                EXPECT_EQ(n, 0u);
            },
            net::detached);
        ioc.run();
        ASSERT_TRUE(ec);
        EXPECT_EQ(ec, preview::fault::make_error_code(preview::fault::code::io_error));
    }

    TEST(Unreliable, SourceFiltering)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     preview::transport::unreliable server(ioc.get_executor());
                     preview::transport::unreliable client_a(ioc.get_executor());
                     preview::transport::unreliable client_b(ioc.get_executor());

                     boost::system::error_code oec;
                     server.native_socket().open(net::ip::udp::v4(), oec);
                     server.native_socket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     client_a.native_socket().open(net::ip::udp::v4(), oec);
                     client_a.native_socket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     client_b.native_socket().open(net::ip::udp::v4(), oec);
                     client_b.native_socket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "open/bind failed: " << oec.message();
                         co_return;
                     }

                     const auto server_ep = server.native_socket().local_endpoint();
                     client_a.set_remote(server_ep);
                     client_b.set_remote(server_ep);
                     // 服务端只信任 client_a 的来源
                     server.set_remote(client_a.native_socket().local_endpoint());

                     // B 的包先到 → 被丢弃；A 的包后到 → 被接收
                     std::error_code ec;
                     co_await client_b.async_write_some(sv_bytes("intruder"), ec);
                     co_await client_a.async_write_some(sv_bytes("trusted"), ec);

                     std::array<std::byte, 16> buf{};
                     const auto r = co_await server.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 7u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(7))),
                               "trusted");

                     server.close();
                     client_a.close();
                     client_b.close();
                 });
    }

    TEST(Unreliable, AccessorsCloseCancel)
    {
        net::io_context ioc;
        preview::transport::unreliable u(ioc.get_executor());
        EXPECT_EQ(u.transport_type(), preview::transmission::type::udp);
        EXPECT_EQ(u.next_layer(), nullptr);
        EXPECT_FALSE(u.remote_endpoint().has_value());

        const net::ip::udp::endpoint ep(net::ip::address_v4::loopback(), 9999);
        u.set_remote(ep);
        ASSERT_TRUE(u.remote_endpoint().has_value());
        EXPECT_EQ(*u.remote_endpoint(), ep);

        EXPECT_NO_THROW((void)u.executor());
        EXPECT_NO_THROW(u.cancel());
        EXPECT_NO_THROW(u.close());
    }

    // ══════════════════════ unreliable ══════════════════════

    TEST(UdpTransmission, DatagramRoundTrip)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     preview::transport::unreliable client(ioc.get_executor());
                     preview::transport::unreliable server(ioc.get_executor());

                     boost::system::error_code oec;
                     server.native_socket().open(net::ip::udp::v4(), oec);
                     if (oec || !server.bind(0))
                     {
                         EXPECT_TRUE(false) << "server open/bind failed";
                         co_return;
                     }
                     client.native_socket().open(net::ip::udp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "client open failed";
                         co_return;
                     }

                     const auto local = server.native_socket().local_endpoint();
                     const auto local_addr = local.address().is_unspecified()
                                                 ? std::string("127.0.0.1")
                                                 : local.address().to_string();
                     if (!client.connect(local_addr + ":" + std::to_string(local.port())))
                     {
                         EXPECT_TRUE(false) << "connect failed";
                         co_return;
                     }

                     // 客户端 → 服务端
                     std::error_code ec;
                     const auto w = co_await client.async_write_some(sv_bytes("udp!"), ec);
                     EXPECT_EQ(w, 4u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 16> buf{};
                     auto r = co_await server.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(4))),
                               "udp!");

                     // 服务端 → 客户端
                     const auto w2 = co_await server.async_write_some(sv_bytes("back"), ec);
                     EXPECT_EQ(w2, 4u);
                     r = co_await client.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_EQ(preview::as_str_view(preview::as_u8(std::span<std::byte>(buf).first(4))),
                               "back");

                     server.cancel();
                     server.close();
                     client.close();
                 });
    }

    TEST(UdpTransmission, WriteWithoutOpenFails)
    {
        net::io_context ioc;
        preview::transport::unreliable u(ioc.get_executor()); // socket 未打开

        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await u.async_write_some(sv_bytes("x"), ec);
                EXPECT_EQ(n, 0u);
            },
            net::detached);
        ioc.run();
        EXPECT_TRUE(ec); // 未绑定/未打开 → 写错误
    }

    TEST(UdpTransmission, ReadAfterCloseFails)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     preview::transport::unreliable u(ioc.get_executor());
                     boost::system::error_code oec;
                     u.native_socket().open(net::ip::udp::v4(), oec);
                     if (oec || !u.bind(0))
                     {
                         EXPECT_TRUE(false) << "open/bind failed";
                         co_return;
                     }
                     u.close(); // 关闭后读 → 错误

                     std::error_code ec;
                     std::array<std::byte, 8> buf{};
                     const auto r = co_await u.async_read_some(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                 });
    }

} // namespace
