/**
 * @file TransportDecoratorCoverage.cpp
 * @brief tests/common/core/transport/ 装饰器模块覆盖率测试
 * @details 覆盖八个传输装饰器/叶子模块：
 * - PadTransport：填充启用/禁用、最小/最大边界、数据透传、大块透传兜底、
 *   随机填充确定性（不破坏数据）、StopAfter 透传
 * - make_error_code：预读字节优先返回、耗尽后透传底层、EOF、WrapWithPreview
 * - Snapshot：捕获/回滚重放、回滚后继续读取、写入后禁止回滚
 * - Reliable：真实 TCP 读满/写满、EOF、对端关闭写错误、错误中断返回已读字节
 * - Encrypted：内存管道上的真实 TLS 握手 + 加解密往返、握手失败恢复、
 *   null 入站、访问器/关闭/取消
 * - Connector：预读注入、委托底层、移动语义、Release、成员 AsyncRead/Write
 * - Unreliable：UDP 往返、未设远程写错误、来源过滤、访问器
 * - Unreliable：往返、未打开写/读错误、Close/Cancel
 * @note 底层一律使用 MemoryStream（MakeMemoryPair）或真实 loopback socket。
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

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Transport/Connector.hpp>
#include <common/Core/Transport/Encrypted.hpp>
#include <common/Core/Transport/MemoryStream.hpp>
#include <common/Core/Transport/Pad.hpp>
#include <common/Core/Transport/make_error_code.hpp>
#include <common/Core/Transport/Reliable.hpp>
#include <common/Core/Transport/Snapshot.hpp>
#include <common/Core/Transport/Unreliable.hpp>
#include <common/Core/Transport/Unreliable.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    namespace ssl = boost::asio::ssl;
    using namespace std::Transport;

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
    class fake_sink final : public std::Transmission
    {
    public:
        explicit fake_sink(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return ex_;
        }

        [[nodiscard]] auto AsyncReadSome(std::span<std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            co_return 0;
        }

        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> buf, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            written_.insert(written_.end(), buf.begin(), buf.end());
            co_return buf.size();
        }

        void Close() override
        {
        }

        void Cancel() override
        {
        }

        std::vector<std::byte> written_; ///< 捕获的写入字节

    private:
        net::any_io_executor ex_;
    };

    /**
     * @brief 可编程行为 mock（Reliable 组合操作错误路径用）
     */
    class programmable_mock final : public std::Transmission
    {
    public:
        explicit programmable_mock(net::any_io_executor ex) : ex_(std::move(ex))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return ex_;
        }

        [[nodiscard]] auto AsyncReadSome(std::span<std::byte>, std::error_code &ec)
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

        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte>, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            co_return write_n_;
        }

        void Close() override
        {
        }

        void Cancel() override
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

        auto *Name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Test"),
                                   -1, -1, 0);
        X509_set_subject_name(x509, Name);
        X509_set_issuer_name(x509, Name);
        X509_NAME_free(Name);

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
        return std::AsBytesSpan(s);
    }

    // ══════════════════════ PadTransport ══════════════════════

    TEST(PadTransport, EnabledDisabled)
    {
        std::Transport::PadConfig def;
        EXPECT_TRUE(def.Enabled());

        std::Transport::PadConfig off;
        off.PadTargets = "";
        EXPECT_FALSE(off.Enabled());

        // 禁用填充：透传零开销（写入字节数 == 数据长度）
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        std::Transport::PadTransport pad(sink, off);
        const std::string_view msg = "raw-passthrough";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await pad.AsyncWriteSome(sv_bytes(msg), ec);
                EXPECT_EQ(n, msg.size());
                EXPECT_FALSE(ec);
            },
            net::detached);
        ioc.run();
        EXPECT_EQ(sink->written_.size(), msg.size());
        EXPECT_EQ(std::AsStrView(std::AsU8(std::span<const std::byte>(sink->written_))), msg);
    }

    TEST(PadTransport, MinBoundaryPadToTarget)
    {
        // 固定目标 "5"：小数据补齐到 5 字节，大数据零填充
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        std::Transport::PadConfig cfg;
        cfg.PadTargets = "5";
        cfg.MaxPadBytes = 0; // 数据 >= 目标时零填充，保证确定性
        std::Transport::PadTransport pad(sink, cfg);

        std::array<std::byte, 3> small{std::byte{1}, std::byte{2}, std::byte{3}};
        std::array<std::byte, 8> large{};
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n1 = co_await pad.AsyncWriteSome(std::span<const std::byte>(small), ec);
                EXPECT_FALSE(ec);
                EXPECT_EQ(n1, 3u); // 返回值 = 原始数据长度
                EXPECT_EQ(sink->written_.size(), 5u); // 补齐到目标 5

                const auto n2 = co_await pad.AsyncWriteSome(std::span<const std::byte>(large), ec);
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
        std::Transport::PadConfig cfg;
        cfg.PadTargets = "80-150";
        std::Transport::PadTransport pad(sink, cfg);

        const std::string_view msg = "ten-Bytes";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await pad.AsyncWriteSome(sv_bytes(msg), ec);
                EXPECT_FALSE(ec);
                EXPECT_EQ(n, msg.size());
            },
            net::detached);
        ioc.run();
        ASSERT_GE(sink->written_.size(), 80u);
        ASSERT_LE(sink->written_.size(), 150u);
        // 数据前缀完好
        const auto wire = std::AsStrView(std::AsU8(std::span<const std::byte>(sink->written_)));
        EXPECT_EQ(wire.substr(0, msg.size()), msg);
    }

    TEST(PadTransport, DataPassthroughOverPipe)
    {
        // 经 memory pair 往返：填充不破坏数据
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     std::Transport::PadConfig cfg;
                     std::Transport::PadTransport pad(sa, cfg);

                     const std::string_view msg = "hello world, padding must not corrupt me";
                     std::error_code ec;
                     const auto n = co_await pad.AsyncWriteSome(sv_bytes(msg), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(n, msg.size());

                     // 对端只读原始数据长度字节，验证逐字节一致
                     std::vector<std::byte> rbuf(msg.size());
                     const auto r = co_await sb->AsyncRead(std::span<std::byte>(rbuf), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(r, msg.size());
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<const std::byte>(rbuf))), msg);
                 });
    }

    TEST(PadTransport, LargeChunkBypass)
    {
        // 数据 + 填充 > pad_buf_（16384+256）→ 直接透传
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        std::Transport::PadConfig cfg;
        std::Transport::PadTransport pad(sink, cfg);

        constexpr std::size_t big = 17000;
        std::vector<std::byte> payload(big, std::byte{0x5A});
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await pad.AsyncWriteSome(std::span<const std::byte>(payload), ec);
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
        std::Transport::PadConfig cfg;
        cfg.PadTargets = "30-50";
        std::Transport::PadTransport pad1(sink1, cfg);
        std::Transport::PadTransport pad2(sink2, cfg);

        const std::string_view msg = "0123456789";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n1 = co_await pad1.AsyncWriteSome(sv_bytes(msg), ec);
                EXPECT_EQ(n1, msg.size());
                EXPECT_FALSE(ec);
                const auto n2 = co_await pad2.AsyncWriteSome(sv_bytes(msg), ec);
                EXPECT_EQ(n2, msg.size());
                EXPECT_FALSE(ec);
            },
            net::detached);
        ioc.run();

        ASSERT_GE(sink1->written_.size(), 30u);
        ASSERT_LE(sink1->written_.size(), 50u);
        ASSERT_GE(sink2->written_.size(), 30u);
        ASSERT_LE(sink2->written_.size(), 50u);
        const auto w1 = std::AsStrView(std::AsU8(std::span<const std::byte>(sink1->written_)));
        const auto w2 = std::AsStrView(std::AsU8(std::span<const std::byte>(sink2->written_)));
        EXPECT_EQ(w1.substr(0, msg.size()), msg);
        EXPECT_EQ(w2.substr(0, msg.size()), msg);
        EXPECT_NE(w1, w2); // 不同密钥 → 不同填充
    }

    TEST(PadTransport, StopAfterPassthrough)
    {
        // StopAfter = 2：前两次填充，之后透传
        net::io_context ioc;
        auto sink = std::make_shared<fake_sink>(ioc.get_executor());
        std::Transport::PadConfig cfg;
        cfg.PadTargets = "20";
        cfg.StopAfter = 2;
        std::Transport::PadTransport pad(sink, cfg);

        const std::string_view msg = "abc";
        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                for (std::size_t i = 0; i < 3; ++i)
                {
                    const auto n = co_await pad.AsyncWriteSome(sv_bytes(msg), ec);
                    EXPECT_EQ(n, 3u);
                    EXPECT_FALSE(ec);
                }
            },
            net::detached);
        ioc.run();

        ASSERT_EQ(sink->written_.size(), 20u + 20u + 3u); // 2 次补齐到 20 + 1 次透传
        const auto wire = std::AsStrView(std::AsU8(std::span<const std::byte>(sink->written_)));
        EXPECT_EQ(wire.substr(0, 3), "abc");
        EXPECT_EQ(wire.substr(20, 3), "abc");
        EXPECT_EQ(wire.substr(40, 3), "abc");
    }

    // ══════════════════════ make_error_code ══════════════════════

    TEST(make_error_code, PrereadReturnedFirst)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     const std::string_view preread = "ABCDEF";
                     std::Transport::make_error_code pv(sb, sv_bytes(preread));

                     std::array<std::byte, 3> buf{};
                     std::error_code ec;
                     auto n = co_await pv.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "ABC");
                     n = co_await pv.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "DEF");
                 });
    }

    TEST(make_error_code, ExhaustedDelegatesToInner)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     // 预读 4 字节，底层还有 3 字节
                     std::error_code ec;
                     co_await sa->AsyncWriteSome(sv_bytes("XYZ"), ec);

                     const std::string_view preread = "PRE-";
                     std::Transport::make_error_code pv(sb, sv_bytes(preread));

                     std::array<std::byte, 4> buf{};
                     auto n = co_await pv.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "PRE-");

                     // 预读耗尽 → 委托底层
                     n = co_await pv.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(3))), "XYZ");
                 });
    }

    TEST(make_error_code, EofAfterPreread)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     sa->Shutdown(); // 对端半关（EOF）

                     std::Transport::make_error_code pv(sb, sv_bytes("ab"));
                     std::array<std::byte, 4> buf{};
                     std::error_code ec;
                     auto n = co_await pv.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 2u);
                     EXPECT_FALSE(ec);
                     // 预读耗尽后读取底层 → EOF
                     n = co_await pv.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 0u);
                     EXPECT_FALSE(ec);
                 });
    }

    TEST(make_error_code, WrapWithPreviewBehavior)
    {
        net::io_context ioc;
        auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
        auto sa = std::make_shared<std::MemoryStream>(std::move(a));
        auto sb = std::make_shared<std::MemoryStream>(std::move(b));

        // 空预读 → 不包装
        auto not_wrapped = std::Transport::WrapWithPreview(sa, {});
        EXPECT_EQ(not_wrapped.get(), sa.get());

        // 非空预读 → 包装为 make_error_code
        auto wrapped = std::Transport::WrapWithPreview(sb, sv_bytes("hello"));
        auto *pv = dynamic_cast<std::Transport::make_error_code *>(wrapped.get());
        ASSERT_NE(pv, nullptr);
        EXPECT_EQ(pv->NextLayer(), sb.get());
        EXPECT_EQ(wrapped->TransportType(), std::Transmission::Type::Tcp);

        // completion-handler 风格预读路径
        net::io_context ioc2;
        std::promise<std::pair<boost::system::error_code, std::size_t>> Done;
        auto fut = Done.get_future();
        std::Transport::make_error_code pv2(sb, sv_bytes("hi"));
        std::array<std::byte, 8> buf{};
        pv2.AsyncReadSome(std::span<std::byte>(buf), [&](boost::system::error_code ec, std::size_t n)
                            { Done.set_value({ec, n}); });
        ioc2.run();
        const auto [ec, n] = fut.get();
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, 2u);
        EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(2))), "hi");
    }

    // ══════════════════════ Snapshot ══════════════════════

    TEST(Snapshot, CaptureRewindReplay)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     std::error_code ec;
                     co_await sa->AsyncWriteSome(sv_bytes("0123456789"), ec);

                     auto snap = std::make_shared<std::Transport::Snapshot>(sb);
                     EXPECT_TRUE(snap->CanRewind());
                     EXPECT_EQ(snap->NextLayer(), sb.get());

                     std::array<std::byte, 4> buf{};
                     auto n = co_await snap->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "0123");

                     snap->Rewind();
                     EXPECT_TRUE(snap->CanRewind());

                     n = co_await snap->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "0123");
                 });
    }

    TEST(Snapshot, ContinueAfterRewind)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     std::error_code ec;
                     co_await sa->AsyncWriteSome(sv_bytes("0123456789"), ec);

                     auto snap = std::make_shared<std::Transport::Snapshot>(sb);

                     // 读 6 字节，回滚，再读完
                     std::array<std::byte, 6> buf{};
                     auto n = co_await snap->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 6u);
                     snap->Rewind();
                     n = co_await snap->AsyncRead(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(n, 6u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "012345");

                     // 回放完剩余捕获，再读新数据
                     std::array<std::byte, 8> buf2{};
                     n = co_await snap->AsyncReadSome(std::span<std::byte>(buf2), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf2).first(4))),
                               "6789");

                     co_await sa->AsyncWriteSome(sv_bytes("abcd"), ec);
                     n = co_await snap->AsyncReadSome(std::span<std::byte>(buf2), ec);
                     EXPECT_EQ(n, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf2).first(4))),
                               "abcd");
                 });
    }

    TEST(Snapshot, WriteDisablesRewind)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     auto snap = std::make_shared<std::Transport::Snapshot>(sb);

                     // 写入委托给底层
                     std::error_code ec;
                     const auto n = co_await snap->AsyncWriteSome(sv_bytes("out"), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(n, 3u);
                     // 写入后禁止回滚
                     EXPECT_FALSE(snap->CanRewind());

                     // 对端收到写入数据
                     std::array<std::byte, 8> buf{};
                     const auto r = co_await sa->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 3u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(3))),
                               "out");

                     // Close/Cancel 委托底层
                     snap->Close();
                     snap->Cancel();
                     EXPECT_FALSE(sb->IsOpen());
                     EXPECT_TRUE(sa->IsOpen()); // 对端不受本端全关影响
                 });
    }

    // ══════════════════════ Encrypted ══════════════════════

    TEST(Encrypted, SslHandshakeNullInbound)
    {
        net::io_context ioc;
        ssl::context ctx(ssl::context::tls_server);
        std::tuple<std::Fault::Code, Encrypted::SharedStream, std::SharedTransmission> Result;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     Result = co_await Encrypted::SslHandshake(nullptr, ctx);
                 });
        auto &[Code, Stream, recovered] = Result;
        EXPECT_EQ(Code, std::Fault::Code::io_error);
        EXPECT_EQ(Stream, nullptr);
        EXPECT_EQ(recovered, nullptr);
    }

    TEST(Encrypted, HandshakeFailureRecoversTransport)
    {
        net::io_context ioc;
        ssl::context server_ctx(ssl::context::tls_server);
        load_self_signed_cert(server_ctx);

        std::tuple<std::Fault::Code, Encrypted::SharedStream, std::SharedTransmission> Result;
        std::exception_ptr coro_ep;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                // 客户端发送非 TLS 垃圾数据
                std::error_code ec;
                co_await sa->AsyncWriteSome(sv_bytes("GARBAGE-not-a-Client-hello"), ec);

                Result = co_await Encrypted::SslHandshake(sb, server_ctx);
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
        printf("DBG Code=%d Stream=%p recovered=%p\n",
               static_cast<int>(std::get<0>(Result)), (void *)std::get<1>(Result).get(),
               (void *)std::get<2>(Result).get());

        auto &[Code, Stream, recovered] = Result;
        EXPECT_NE(Code, std::Fault::Code::success);
        EXPECT_EQ(Stream, nullptr);
        ASSERT_NE(recovered, nullptr); // 失败后从 Connector 恢复底层传输
        EXPECT_EQ(recovered->TransportType(), std::Transmission::Type::Tcp);
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
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     // 服务端握手
                     auto server_handshake = [&]() -> net::awaitable<Encrypted::SharedStream>
                     {
                         auto [Code, Stream, recovered] = co_await Encrypted::SslHandshake(sb, server_ctx);
                         EXPECT_EQ(Code, std::Fault::Code::success);
                         co_return Stream;
                     };

                     // 客户端握手
                     auto client_handshake = [&]() -> net::awaitable<Encrypted::SharedStream>
                     {
                         std::Transport::Connector c(sa);
                         auto Stream = std::make_shared<Encrypted::StreamType>(std::move(c), client_ctx);
                         boost::system::error_code ec;
                         co_await Stream->async_handshake(ssl::stream_base::client,
                                                           net::redirect_error(net::use_awaitable, ec));
                         EXPECT_FALSE(ec) << ec.message();
                         co_return Stream;
                     };

                     auto [s_stream, c_stream] = co_await (server_handshake() && client_handshake());
                     if (!s_stream || !c_stream)
                     {
                         EXPECT_TRUE(false) << "TLS handshake Failed";
                         co_return;
                     }

                     auto server_t = std::make_shared<Encrypted>(s_stream);
                     auto client_t = std::make_shared<Encrypted>(c_stream);

                     // 装饰器访问器（NextLayer 穿透 ssl::Stream → Connector 到底层）
                     EXPECT_EQ(client_t->TransportType(), std::Transmission::Type::Tcp);
                     EXPECT_NE(client_t->NextLayer(), nullptr);

                     // 客户端 → 服务端（加密写 → 解密读）
                     std::error_code ec;
                     const auto w1 = co_await client_t->AsyncWriteSome(sv_bytes("hello"), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(w1, 5u);
                     std::array<std::byte, 16> buf{};
                     auto r = co_await server_t->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 5u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(5))),
                               "hello");

                     // 服务端 → 客户端
                     const auto w2 = co_await server_t->AsyncWriteSome(sv_bytes("world"), ec);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(w2, 5u);
                     r = co_await client_t->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 5u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(5))),
                               "world");

                     // 大块往返
                     std::vector<std::byte> big(4096, std::byte{0x77});
                     const auto w3 = co_await client_t->AsyncWrite(std::span<const std::byte>(big), ec);
                     EXPECT_EQ(w3, big.size());
                     std::vector<std::byte> rbig(big.size());
                     const auto r3 = co_await server_t->AsyncRead(std::span<std::byte>(rbig), ec);
                     EXPECT_EQ(r3, big.size());
                     EXPECT_EQ(std::memcmp(rbig.data(), big.data(), big.size()), 0);

                     // Close/Cancel 不崩溃（SSL_shutdown + 底层关闭）
                     client_t->Cancel();
                     server_t->Cancel();
                     client_t->Close();
                     server_t->Close();
                 });
    }

    TEST(Encrypted, AccessorsAndRelease)
    {
        net::io_context ioc;
        ssl::context ctx(ssl::context::tls_server);

        auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
        auto sa = std::make_shared<std::MemoryStream>(std::move(a));
        std::Transport::Connector c(sa);
        auto Stream = std::make_shared<Encrypted::StreamType>(std::move(c), ctx);

        auto t = std::make_shared<Encrypted>(Stream);
        EXPECT_EQ(t->TransportType(), std::Transmission::Type::Tcp);
        EXPECT_NE(t->NextLayer(), nullptr);
        EXPECT_EQ(t->Stream().native_handle(), Stream->native_handle());
        EXPECT_NO_THROW((void)t->Executor());

        // Close/Cancel（未握手流上安全）
        EXPECT_NO_THROW(t->Cancel());
        EXPECT_NO_THROW(t->Close());

        auto released = t->ReleaseStream();
        EXPECT_EQ(released.get(), Stream.get());
    }

    // ══════════════════════ Connector ══════════════════════

    TEST(Connector, PrereadInjectionThenDelegate)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     // 底层先有数据（预读注入应优先返回）
                     std::error_code ec;
                     co_await sa->AsyncWriteSome(sv_bytes("Inner-Data"), ec);

                     std::Transport::Connector Conn(sb, sv_bytes("PRE"));
                     std::array<std::byte, 8> buf{};
                     boost::system::error_code c_ec;
                     auto n = co_await Conn.AsyncReadSome(net::buffer(buf),
                                                            net::redirect_error(net::use_awaitable, c_ec));
                     EXPECT_FALSE(c_ec);
                     EXPECT_EQ(n, 3u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(3))),
                               "PRE");

                     // 预读耗尽 → 委托底层
                     c_ec.clear();
                     n = co_await Conn.AsyncReadSome(net::buffer(buf),
                                                       net::redirect_error(net::use_awaitable, c_ec));
                     EXPECT_FALSE(c_ec);
                     EXPECT_EQ(n, 8u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), "Inner-da");
                 });
    }

    TEST(Connector, WriteDelegation)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     std::Transport::Connector Conn(sb);
                     const std::string_view msg = "Write-me";
                     boost::system::error_code w_ec;
                     const auto n = co_await Conn.AsyncWriteSome(
                         net::buffer(msg.data(), msg.size()), net::redirect_error(net::use_awaitable, w_ec));
                     EXPECT_FALSE(w_ec);
                     EXPECT_EQ(n, msg.size());

                     std::array<std::byte, 16> buf{};
                     std::error_code ec;
                     const auto r = co_await sa->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, msg.size());
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(r))), msg);
                 });
    }

    TEST(Connector, MemberAsyncReadWrite)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
                     auto sa = std::make_shared<std::MemoryStream>(std::move(a));
                     auto sb = std::make_shared<std::MemoryStream>(std::move(b));

                     std::Transport::Connector Conn(sb);
                     const std::string_view msg = "member-loop";
                     std::error_code ec;
                     const auto w = co_await Conn.AsyncWrite(std::span<const std::byte>(sv_bytes(msg)), ec);
                     EXPECT_EQ(w, msg.size());
                     EXPECT_FALSE(ec);

                     std::Transport::Connector conn_reader(sa);
                     std::vector<std::byte> buf(msg.size());
                     const auto r = co_await conn_reader.AsyncRead(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, msg.size());
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf))), msg);
                 });
    }

    TEST(Connector, MoveReleaseAccessors)
    {
        net::io_context ioc;
        auto [a, b] = std::MakeMemoryPair(ioc.get_executor());
        auto sa = std::make_shared<std::MemoryStream>(std::move(a));
        auto sb = std::make_shared<std::MemoryStream>(std::move(b));

        std::Transport::Connector Conn(sb);
        EXPECT_EQ(&Conn.Transmission(), sb.get());
        EXPECT_EQ(Conn.Executor(), Conn.GetExecutor());

        // 移动构造
        std::Transport::Connector moved(std::move(Conn));
        // 移动赋值
        std::Transport::Connector assigned(
            std::make_shared<std::MemoryStream>(ioc.get_executor()));
        assigned = std::move(moved);

        // Release 返回底层传输
        auto released = assigned.Release();
        EXPECT_EQ(released.get(), sb.get());
    }

    // ══════════════════════ Reliable ══════════════════════

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

                     std::shared_ptr<std::Transport::Reliable> Server;
                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         Server = std::make_shared<std::Transport::Reliable>(std::move(sock));
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     std::Transport::Reliable Client(ioc.get_executor());
                     boost::system::error_code oec;
                     Client.NativeSocket().open(net::ip::tcp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Open Failed: " << oec.message();
                         co_return;
                     }
                     co_await Client.NativeSocket().async_connect(connect_ep, net::use_awaitable);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);
                     if (!Server)
                     {
                         EXPECT_TRUE(false) << "Accept Failed";
                         co_return;
                     }

                     // 客户端写满 5 字节，服务端读满 5 字节
                     std::error_code ec;
                     const auto w = co_await Client.AsyncWrite(sv_bytes("hello"), ec);
                     EXPECT_EQ(w, 5u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 8> buf{};
                     const auto r = co_await Server->AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 5u);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(5))),
                               "hello");

                     // 反向：服务端写 3，客户端读满 3
                     const auto w2 = co_await Server->AsyncWrite(sv_bytes("xyz"), ec);
                     EXPECT_EQ(w2, 3u);
                     const auto r2 = co_await Client.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r2, 3u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(3))),
                               "xyz");

                     Client.Close();
                     Server->Close();
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

                     std::shared_ptr<std::Transport::Reliable> Server;
                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         Server = std::make_shared<std::Transport::Reliable>(std::move(sock));
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     std::Transport::Reliable Client(ioc.get_executor());
                     boost::system::error_code oec;
                     Client.NativeSocket().open(net::ip::tcp::v4(), oec);
                     co_await Client.NativeSocket().async_connect(connect_ep, net::use_awaitable);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);

                     // 半关写方向 → 对端读返回 0（EOF；TCP EOF 以 eof 错误码呈现）
                     Client.ShutdownWrite();
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto r = co_await Server->AsyncRead(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(!ec || ec.message() == "eof") << ec.message();
                     Client.Close();
                     Server->Close();
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

                     std::shared_ptr<std::Transport::Reliable> Server;
                     auto accept_coro = [&]() -> net::awaitable<void>
                     {
                         auto sock = co_await acceptor.async_accept(net::use_awaitable);
                         Server = std::make_shared<std::Transport::Reliable>(std::move(sock));
                     };
                     net::co_spawn(ioc.get_executor(), accept_coro(), net::detached);

                     std::Transport::Reliable Client(ioc.get_executor());
                     boost::system::error_code oec;
                     Client.NativeSocket().open(net::ip::tcp::v4(), oec);
                     co_await Client.NativeSocket().async_connect(connect_ep, net::use_awaitable);
                     co_await net::post(ioc.get_executor(), net::use_awaitable);

                     // 对端先半关（发送 FIN）再全关
                     Server->ShutdownWrite();
                     Server->Close();

                     // 本端读：EOF 或错误均可（FIN/RST 到达顺序不定）
                     std::array<std::byte, 8> buf{};
                     std::error_code ec;
                     const auto r = co_await Client.AsyncRead(std::span<std::byte>(buf), ec);
                     EXPECT_TRUE(r == 0u || ec) << "对端关闭后读应返回 EOF 或错误";

                     // 写 → 必须出错（RST/broken pipe）
                     std::error_code werr;
                     bool Failed = false;
                     for (int i = 0; i < 20 && !Failed; ++i)
                     {
                         const auto w = co_await Client.AsyncWrite(sv_bytes("Data"), werr);
                         if (werr || w == 0)
                         {
                             Failed = true;
                         }
                     }
                     EXPECT_TRUE(Failed) << "对端关闭后写入应失败";

                     Client.Close();
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
                got = co_await mock->AsyncRead(std::span<std::byte>(buf), ec);
            },
            net::detached);
        ioc.run();
        EXPECT_EQ(got, 3u);
        EXPECT_TRUE(ec);
    }

    TEST(Reliable, WriteZeroMeansBrokenPipe)
    {
        // AsyncWrite 循环中 n==0 且无错误 → 置 broken_pipe
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
                got = co_await mock->AsyncWrite(std::span<const std::byte>(buf), ec);
            },
            net::detached);
        ioc.run();
        EXPECT_EQ(got, 0u);
        ASSERT_TRUE(ec);
        EXPECT_EQ(ec, std::make_error_code(std::Error::broken_pipe));
    }

    TEST(Reliable, AccessorsAndRelease)
    {
        net::io_context ioc;
        std::Transport::Reliable t(ioc.get_executor());

        EXPECT_EQ(t.TransportType(), std::Transmission::Type::Tcp);
        EXPECT_EQ(t.NextLayer(), nullptr);
        EXPECT_EQ(t.LowestLayer<std::Transport::Reliable>(), &t);
        EXPECT_NO_THROW((void)t.Executor());

        // 构造后 socket 未打开：Release 返回未打开的 socket
        auto sock = t.ReleaseSocket();
        ASSERT_TRUE(sock.has_value());
        EXPECT_FALSE(sock->is_open());
        // 二次 Release：无 socket → nullopt
        EXPECT_FALSE(t.ReleaseSocket().has_value());

        std::Transport::Reliable t2(ioc.get_executor());
        EXPECT_NO_THROW(t2.Close());
        EXPECT_NO_THROW(t2.Cancel());
    }

    // ══════════════════════ Unreliable ══════════════════════

    TEST(Unreliable, DatagramRoundTrip)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::Transport::Unreliable Server(ioc.get_executor());
                     std::Transport::Unreliable Client(ioc.get_executor());

                     boost::system::error_code oec;
                     Server.NativeSocket().open(net::ip::udp::v4(), oec);
                     Server.NativeSocket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Server Open/Bind Failed: " << oec.message();
                         co_return;
                     }
                     Client.NativeSocket().open(net::ip::udp::v4(), oec);
                     Client.NativeSocket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Client Open/Bind Failed: " << oec.message();
                         co_return;
                     }

                     Client.SetRemote(Server.NativeSocket().local_endpoint());
                     EXPECT_TRUE(Client.RemoteEndpoint().has_value());

                     // 客户端 → 服务端（服务端首次接收自动记录远程）
                     std::error_code ec;
                     const auto w = co_await Client.AsyncWriteSome(sv_bytes("ping"), ec);
                     EXPECT_EQ(w, 4u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 16> buf{};
                     auto r = co_await Server.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(4))),
                               "ping");
                     EXPECT_TRUE(Server.RemoteEndpoint().has_value());

                     // 服务端回写（远程已记录）
                     const auto w2 = co_await Server.AsyncWriteSome(sv_bytes("pong"), ec);
                     EXPECT_EQ(w2, 4u);
                     r = co_await Client.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(4))),
                               "pong");

                     Server.Close();
                     Client.Close();
                 });
    }

    TEST(Unreliable, WriteWithoutRemoteFails)
    {
        net::io_context ioc;
        std::Transport::Unreliable u(ioc.get_executor());
        boost::system::error_code oec;
        u.NativeSocket().open(net::ip::udp::v4(), oec);
        u.NativeSocket().bind({net::ip::udp::v4(), 0}, oec);
        ASSERT_FALSE(oec);
        EXPECT_FALSE(u.RemoteEndpoint().has_value());

        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await u.AsyncWriteSome(sv_bytes("nope"), ec);
                EXPECT_EQ(n, 0u);
            },
            net::detached);
        ioc.run();
        ASSERT_TRUE(ec);
        EXPECT_EQ(ec, std::Fault::make_error_code(std::Fault::Code::io_error));
    }

    TEST(Unreliable, SourceFiltering)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::Transport::Unreliable Server(ioc.get_executor());
                     std::Transport::Unreliable client_a(ioc.get_executor());
                     std::Transport::Unreliable client_b(ioc.get_executor());

                     boost::system::error_code oec;
                     Server.NativeSocket().open(net::ip::udp::v4(), oec);
                     Server.NativeSocket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     client_a.NativeSocket().open(net::ip::udp::v4(), oec);
                     client_a.NativeSocket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     client_b.NativeSocket().open(net::ip::udp::v4(), oec);
                     client_b.NativeSocket().bind({net::ip::address_v4::loopback(), 0}, oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Open/Bind Failed: " << oec.message();
                         co_return;
                     }

                     const auto server_ep = Server.NativeSocket().local_endpoint();
                     client_a.SetRemote(server_ep);
                     client_b.SetRemote(server_ep);
                     // 服务端只信任 client_a 的来源
                     Server.SetRemote(client_a.NativeSocket().local_endpoint());

                     // B 的包先到 → 被丢弃；A 的包后到 → 被接收
                     std::error_code ec;
                     co_await client_b.AsyncWriteSome(sv_bytes("intruder"), ec);
                     co_await client_a.AsyncWriteSome(sv_bytes("trusted"), ec);

                     std::array<std::byte, 16> buf{};
                     const auto r = co_await Server.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 7u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(7))),
                               "trusted");

                     Server.Close();
                     client_a.Close();
                     client_b.Close();
                 });
    }

    TEST(Unreliable, AccessorsCloseCancel)
    {
        net::io_context ioc;
        std::Transport::Unreliable u(ioc.get_executor());
        EXPECT_EQ(u.TransportType(), std::Transmission::Type::udp);
        EXPECT_EQ(u.NextLayer(), nullptr);
        EXPECT_FALSE(u.RemoteEndpoint().has_value());

        const net::ip::udp::endpoint ep(net::ip::address_v4::loopback(), 9999);
        u.SetRemote(ep);
        ASSERT_TRUE(u.RemoteEndpoint().has_value());
        EXPECT_EQ(*u.RemoteEndpoint(), ep);

        EXPECT_NO_THROW((void)u.Executor());
        EXPECT_NO_THROW(u.Cancel());
        EXPECT_NO_THROW(u.Close());
    }

    // ══════════════════════ Unreliable ══════════════════════

    TEST(UdpTransmission, DatagramRoundTrip)
    {
        net::io_context ioc;
        run_coro(ioc,
                 [&]() -> net::awaitable<void>
                 {
                     std::Transport::Unreliable Client(ioc.get_executor());
                     std::Transport::Unreliable Server(ioc.get_executor());

                     boost::system::error_code oec;
                     Server.NativeSocket().open(net::ip::udp::v4(), oec);
                     if (oec || !Server.Bind(0))
                     {
                         EXPECT_TRUE(false) << "Server Open/Bind Failed";
                         co_return;
                     }
                     Client.NativeSocket().open(net::ip::udp::v4(), oec);
                     if (oec)
                     {
                         EXPECT_TRUE(false) << "Client Open Failed";
                         co_return;
                     }

                     const auto local = Server.NativeSocket().local_endpoint();
                     const auto local_addr = local.address().is_unspecified()
                                                 ? std::string("127.0.0.1")
                                                 : local.address().to_string();
                     if (!Client.Connect(local_addr + ":" + std::to_string(local.port())))
                     {
                         EXPECT_TRUE(false) << "Connect Failed";
                         co_return;
                     }

                     // 客户端 → 服务端
                     std::error_code ec;
                     const auto w = co_await Client.AsyncWriteSome(sv_bytes("udp!"), ec);
                     EXPECT_EQ(w, 4u);
                     EXPECT_FALSE(ec);
                     std::array<std::byte, 16> buf{};
                     auto r = co_await Server.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_FALSE(ec);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(4))),
                               "udp!");

                     // 服务端 → 客户端
                     const auto w2 = co_await Server.AsyncWriteSome(sv_bytes("back"), ec);
                     EXPECT_EQ(w2, 4u);
                     r = co_await Client.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 4u);
                     EXPECT_EQ(std::AsStrView(std::AsU8(std::span<std::byte>(buf).first(4))),
                               "back");

                     Server.Cancel();
                     Server.Close();
                     Client.Close();
                 });
    }

    TEST(UdpTransmission, WriteWithoutOpenFails)
    {
        net::io_context ioc;
        std::Transport::Unreliable u(ioc.get_executor()); // socket 未打开

        std::error_code ec;
        net::co_spawn(
            ioc,
            [&]() -> net::awaitable<void>
            {
                const auto n = co_await u.AsyncWriteSome(sv_bytes("x"), ec);
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
                     std::Transport::Unreliable u(ioc.get_executor());
                     boost::system::error_code oec;
                     u.NativeSocket().open(net::ip::udp::v4(), oec);
                     if (oec || !u.Bind(0))
                     {
                         EXPECT_TRUE(false) << "Open/Bind Failed";
                         co_return;
                     }
                     u.Close(); // 关闭后读 → 错误

                     std::error_code ec;
                     std::array<std::byte, 8> buf{};
                     const auto r = co_await u.AsyncReadSome(std::span<std::byte>(buf), ec);
                     EXPECT_EQ(r, 0u);
                     EXPECT_TRUE(ec);
                 });
    }

} // namespace
