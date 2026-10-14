/**
 * @file MuxSessionDeep2.cpp
 * @brief 共享会话框架（Session<C>）剩余分支深度测试
 * @details 直接驱动 Session<Smux::Codec> 引擎，手工注入帧序列覆盖
 *          Dispatch 全部事件分支：Open（含 Id==0 / 重复流 / 带负载）、
 *          Data（已知流 / 隐式开流 / Id==0）、fin / rst（含未知流）、
 *          控制帧忽略；以及 StreamHandle 的 Shutdown / Cancel /
 *          SetTimeout / SetPeerEof / OnRst / IsOpen 等剩余方法，
 *          会话关闭后 SendFin / SendRst 的空通道分支，流 ID 环绕。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Preview/Protocols/Mux/Smux/Smux.hpp>
#include <Preview/Protocols/Mux/Yamux/Yamux.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Preview::Mux;
    namespace H2Mux = Preview::Mux::H2Mux;
    namespace Smux = Preview::Mux::Smux;
    namespace Yamux = Preview::Mux::Yamux;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::Role;
    using Preview::make_error_code;
    using Preview::Mux::SessionOptions;

    /**
     * @brief 驱动协程运行
     */
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

    /**
     * @brief 构造 SYN + 负载帧（覆盖 Open 分支带负载路径）
     */
    auto MakeSynWithPayload(
        std::uint32_t Id,
        std::string_view Payload) -> std::vector<std::uint8_t>
    {
        Smux::FrameHeader Header{};
        Header.cmd = Smux::Command::Syn;
        Header.length = static_cast<std::uint16_t>(Payload.size());
        Header.StreamId = Id;
        const auto PayloadBytes = AsU8Span(Payload);
        return Smux::Build(Header, PayloadBytes);
    }

    TEST(MuxSessionDeep2, DispatchAllEvents)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Preview::Role::Server;
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // Open（带负载）→ Accept 得到流并读到负载
                     const auto w1 = co_await peer->WriteAll(MakeSynWithPayload(1, "Open-payload"));
                     EXPECT_FALSE(w1);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     auto Handle = co_await Session->AcceptStream();
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await Handle->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), "Open-payload");
                     EXPECT_EQ(Session->StreamCount(), 1u);

                     // Data 已知流
                     const auto w2 = co_await peer->WriteAll(Smux::BuildPush(1, AsU8Span(std::string_view{"data1"})));
                     EXPECT_FALSE(w2);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     const auto n1 = co_await Handle->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n1), "data1");

                     // 第二条流必须先收到 SYN，再接收 DATA
                     const auto w3 = co_await peer->WriteAll(MakeSynWithPayload(3, "explicit"));
                     EXPECT_FALSE(w3);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     auto implicit = co_await Session->AcceptStream();
                     if (!implicit)
                     {
                         EXPECT_TRUE(false) << "explicit Stream Accept Failed";
                         co_return;
                     }
                     const auto n2 = co_await implicit->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n2), "explicit");
                     EXPECT_EQ(Session->StreamCount(), 2u);

                     // Data Id==0 → 忽略
                     const auto w4 = co_await peer->WriteAll(Smux::BuildPush(0, AsU8Span(std::string_view{"x"})));
                     EXPECT_FALSE(w4);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_EQ(Session->StreamCount(), 2u);

                     // fin 已知流 → 对端半关
                     const auto w5 = co_await peer->WriteAll(Smux::BuildFin(1));
                     EXPECT_FALSE(w5);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_TRUE(Handle->IsPeerEof());

                     // fin 未知流 → 忽略
                     const auto w6 = co_await peer->WriteAll(Smux::BuildFin(99));
                     EXPECT_FALSE(w6);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);

                     // 控制帧（NOP）→ 忽略
                     Smux::FrameHeader nop_hdr{};
                     nop_hdr.cmd = Smux::Command::Nop;
                     const auto w7 = co_await peer->WriteAll(Smux::Build(nop_hdr));
                     EXPECT_FALSE(w7);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_EQ(Session->StreamCount(), 2u);

                     // smux 无独立 RST 帧：FIN 帧即半关（StreamEvent::Fin）
                     const auto w8 = co_await peer->WriteAll(Smux::BuildFin(3));
                     EXPECT_FALSE(w8);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_TRUE(implicit->IsPeerEof());
                     EXPECT_EQ(Session->StreamCount(), 2u);

                     // fin 未知流 → 无副作用
                     const auto w9 = co_await peer->WriteAll(Smux::BuildFin(98));
                     EXPECT_FALSE(w9);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_EQ(Session->StreamCount(), 2u);

                     co_await Session->Close();
                 });
    }

    TEST(MuxSessionDeep2, MuxMalformedFrameClosesSession)
    {
        Net::io_context ioc;
        auto [raw, peer_raw] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(peer_raw));
        auto Session = Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(raw)), SessionOptions{});
        const std::array<std::uint8_t, Smux::FrameHdrsize> malformed{
            0x7F, static_cast<std::uint8_t>(Smux::Command::Push), 0, 0, 1, 0, 0, 0};

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ec = co_await peer->WriteAll(malformed);
                     EXPECT_FALSE(ec);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                     co_await Session->Close();
                 });
    }

    TEST(MuxSessionDeep2, MuxPayloadLimitClosesSession)
    {
        Net::io_context ioc;
        auto [raw, peer_raw] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(peer_raw));
        auto Session = Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(raw)), SessionOptions{});
        const std::array<std::uint8_t, Yamux::FrameHdrsize> oversized{
            Yamux::ProtocolVersion,
            static_cast<std::uint8_t>(Yamux::MessageType::Data),
            0,
            0,
            0,
            0,
            0,
            0,
            0xFF,
            0xFF,
            0xFF,
            0xFF};

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ec = co_await peer->WriteAll(oversized);
                     EXPECT_FALSE(ec);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                     co_await Session->Close();
                 });
    }

    TEST(MuxSessionDeep2, YamuxRstEvent)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions YamuxOptions{};
        YamuxOptions.Role = Preview::Role::Server;
        auto Session = Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), YamuxOptions);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     (void)Session->Executor();
                     // 开流（Data + SYN + 负载）→ Open 分支带负载路径
                     const auto w1 = co_await peer->WriteAll(
                         Yamux::BuildData(Yamux::Flags::Syn, 1, AsU8Span(std::string_view{"Open-payload"})));
                     EXPECT_FALSE(w1);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     auto Handle = co_await Session->AcceptStream();
                     if (!Handle)
                     {
                         EXPECT_TRUE(false) << "AcceptStream Failed";
                         co_return;
                     }
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await Handle->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), "Open-payload");
                     EXPECT_EQ(Session->StreamCount(), 1u);

                     // FIN（Data + FIN 标志）→ fin 分支
                     const auto w2 = co_await peer->WriteAll(Yamux::BuildData(Yamux::Flags::Fin, 1, {}));
                     EXPECT_FALSE(w2);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_TRUE(Handle->IsPeerEof());
                     EXPECT_EQ(Session->StreamCount(), 1u);

                     // FIN 未知流 → 无副作用
                     const auto w3 = co_await peer->WriteAll(Yamux::BuildData(Yamux::Flags::Fin, 99, {}));
                     EXPECT_FALSE(w3);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_EQ(Session->StreamCount(), 1u);

                     // RST 已知流 → 流关闭并移除
                     const auto w4 = co_await peer->WriteAll(Yamux::BuildData(Yamux::Flags::Rst, 1, {}));
                     EXPECT_FALSE(w4);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_TRUE(Handle->IsClosed());
                     EXPECT_EQ(Session->StreamCount(), 0u);

                     // RST 未知流 → 无副作用
                     const auto w5 = co_await peer->WriteAll(Yamux::BuildData(Yamux::Flags::Rst, 98, {}));
                     EXPECT_FALSE(w5);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_EQ(Session->StreamCount(), 0u);

                     // 本端 Shutdown / Reset（SendFin / SendRst 实例路径）
                     co_await Handle->Shutdown();
                     co_await Handle->Reset();
                     co_await Session->Close();
                 });
    }

    TEST(MuxSessionDeep2, H2muxFinAndImplicitOpen)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions H2Options{};
        H2Options.Role = Preview::Role::Server;
        auto Session = Mux::Session<H2Mux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), H2Options);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     (void)Session->Executor();
                     // Data 隐式开流（无 SYN 帧）+ 负载 → 717 路径
                     const auto w1 = co_await peer->WriteAll(
                         H2Mux::BuildData(1, AsU8Span(std::string_view{"implicit"})));
                     EXPECT_FALSE(w1);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     auto Handle = co_await Session->AcceptStream();
                     if (!Handle)
                     {
                         EXPECT_TRUE(false) << "AcceptStream Failed";
                         co_return;
                     }
                     std::array<std::uint8_t, 64> buf{};
                     const auto n = co_await Handle->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data()), n), "implicit");
                     EXPECT_EQ(Session->StreamCount(), 1u);

                     // CLOSE 帧 → fin 分支
                     const auto w2 = co_await peer->WriteAll(H2Mux::BuildClose(1));
                     EXPECT_FALSE(w2);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_TRUE(Handle->IsPeerEof());

                     // CLOSE 未知流 → 无副作用
                     const auto w3 = co_await peer->WriteAll(H2Mux::BuildClose(77));
                     EXPECT_FALSE(w3);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);

                     // 本端 Shutdown / Reset（SendFin / SendRst 实例路径）
                     co_await Handle->Shutdown();
                     co_await Handle->Reset();
                     co_await Session->Close();
                 });
    }

    TEST(MuxSessionDeep2, StreamHandleMethods)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), SessionOptions{});

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     (void)Session->Executor();
                     auto Handle = co_await Session->OpenStream();
                     if (!Handle)
                     {
                         EXPECT_TRUE(false) << "OpenStream Failed";
                         co_return;
                     }
                     EXPECT_TRUE(Handle->IsOpen());
                     EXPECT_EQ(Handle->Id(), 1u);

                     // Shutdown：置 fin_sent + 发 FIN
                     co_await Handle->Shutdown();
                     EXPECT_TRUE(Handle->IsFinSent());
                     EXPECT_TRUE(Handle->IsOpen());

                     // SetPeerEof：对端 FIN 到达
                     Handle->SetPeerEof();
                     EXPECT_TRUE(Handle->IsPeerEof());

                     // OnRst：流被对端重置
                     Handle->OnRst();
                     EXPECT_TRUE(Handle->IsClosed());
                     EXPECT_FALSE(Handle->IsOpen());

                     // Cancel：唤醒挂起读返回 0
                     auto handle2 = co_await Session->OpenStream();
                     if (!handle2)
                     {
                         EXPECT_TRUE(false) << "OpenStream Failed";
                         co_return;
                     }
                     handle2->Cancel();
                     std::array<std::uint8_t, 8> buf{};
                     const auto n = co_await handle2->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(n, 0u);

                     // SetTimeout：读超时返回 0
                     handle2->SetTimeout(std::chrono::milliseconds(20));
                     const auto n2 = co_await handle2->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(n2, 0u);

                     // 挂起读超时路径（队列空 + 超时启用）
                     auto handle3 = co_await Session->OpenStream();
                     if (!handle3)
                     {
                         EXPECT_TRUE(false) << "OpenStream Failed";
                         co_return;
                     }
                     handle3->SetTimeout(std::chrono::milliseconds(20));
                     const auto n3 = co_await handle3->ReadSome(std::span<std::uint8_t>(buf));
                     EXPECT_EQ(n3, 0u);

                     // 会话关闭前 Shutdown / Reset：SendFin / SendRst 实例路径
                     co_await handle2->Shutdown();
                     co_await handle2->Reset();
                     // 会话关闭后：SendFin / SendRst 空通道分支
                     co_await Session->Close();
                     co_await handle2->Close();
                 });
    }

    TEST(MuxSessionDeep2, SessionClosedPaths)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), SessionOptions{});

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     auto Handle = co_await Session->OpenStream();
                     if (!Handle)
                     {
                         EXPECT_TRUE(false) << "OpenStream Failed";
                         co_return;
                     }
                     EXPECT_TRUE(Session->IsOpen());
                     co_await Session->Close();
                     EXPECT_FALSE(Session->IsOpen());

                     // 会话关闭后：Open / Accept / PushData 失败路径
                     const auto null_stream = co_await Session->OpenStream();
                     EXPECT_EQ(null_stream, nullptr);
                     auto accepted = co_await Session->AcceptStream();
                     EXPECT_EQ(accepted, nullptr);
                     const auto perr = co_await Handle->WriteAll(AsU8Span(std::string_view{"x"}));
                     EXPECT_TRUE(perr);
                     EXPECT_EQ(perr, make_error_code(Error::BrokenPipe));
                 });
    }

    TEST(MuxSessionDeep2, IncomingStreamsHonorMaxAndRole)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        SessionOptions Opt{};
        Opt.Role = Preview::Role::Server;
        Opt.MaxStreams = 1;
        auto Session = Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), Opt);
        auto Peer = std::make_shared<MemoryStream>(std::move(b));

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     std::error_code Ec;
                     const auto First = Smux::BuildSyn(1);
                     EXPECT_EQ(co_await Peer->AsyncWrite(AsBytes(std::span<const std::uint8_t>(First)), Ec),
                               First.size());
                     auto Accepted = co_await Session->AcceptStream();
                     EXPECT_NE(Accepted, nullptr);
                     if (!Accepted)
                     {
                         co_return;
                     }

                     // 第二条合法的对端流超过 MaxStreams，必须关闭会话而不是继续接收。
                     const auto Second = Smux::BuildSyn(3);
                     EXPECT_EQ(co_await Peer->AsyncWrite(AsBytes(std::span<const std::uint8_t>(Second)), Ec),
                               Second.size());
                     auto Rejected = co_await Session->AcceptStream();
                     EXPECT_EQ(Rejected, nullptr);
                     EXPECT_FALSE(Session->IsOpen());
                 });
    }

    TEST(MuxSessionDeep2, SessionReadTimeoutClosesIdleSession)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        (void)b;
        SessionOptions Opt{};
        Opt.timeout = std::chrono::milliseconds(10);
        auto Session = Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), Opt);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     Net::steady_timer Wait(ioc);
                     Wait.expires_after(std::chrono::milliseconds(50));
                     co_await Wait.async_wait(Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen());
                 });
    }

    TEST(MuxSessionDeep2, StreamIdWrapAround)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        SessionOptions opt{};
        opt.Role = Preview::Role::Client;
        opt.MaxStreams = 32769;
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     // 32768 个奇数流 ID（1..65535）分配成功；第 32769 个
                     // 必须继续使用 65537，不能回到 1 复用已消耗的 ID。
                     for (std::size_t i = 0; i < 32768; ++i)
                     {
                         auto Handle = co_await Session->OpenStream();
                         if (!Handle)
                         {
                             EXPECT_TRUE(false) << "OpenStream Failed at " << i;
                             co_return;
                         }
                     }
                     EXPECT_EQ(Session->StreamCount(), 32768u);
                     auto Next = co_await Session->OpenStream();
                     EXPECT_TRUE(Next != nullptr);
                     if (!Next)
                     {
                         co_await Session->Close();
                         co_return;
                     }
                     EXPECT_EQ(Next->Id(), 65537u);
                     EXPECT_EQ(Session->StreamCount(), 32769u);
                     co_await Session->Close();
        });
    }

    // ══════════════ P-H01 接收队列字节预算 ══════════════

    TEST(MuxSessionDeep2, RxStreamBudgetExceededClosesSession)
    {
        // 单流 60 字节 > 每流预算 48：帧头合法但超预算必须关闭会话，
        // 不允许远端无上限堆积接收队列。
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Preview::Role::Server;
        opt.MaxStreamRxBytes = 48;
        opt.MaxSessionRxBytes = 1024;
        auto Session = Mux::Session<H2Mux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const std::vector<std::uint8_t> Payload(60, 0x5A);
                     const auto Wire = H2Mux::BuildData(1, Payload);
                     EXPECT_FALSE(co_await peer->WriteAll(Wire));
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                      co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen()) << "单流接收预算超限应关闭会话";
                 });
    }

    TEST(MuxSessionDeep2, RxSessionBudgetExceededClosesSession)
    {
        // 跨流累计 120 字节 > 会话预算 96（每流 40 未超 48）：
        // 会话级预算必须在第三个流触发关闭。
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Preview::Role::Server;
        opt.MaxStreamRxBytes = 48;
        opt.MaxSessionRxBytes = 96;
        auto Session = Mux::Session<H2Mux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const std::vector<std::uint8_t> Payload(40, 0x33);
                     for (const std::uint32_t Id : {1u, 3u})
                     {
                         const auto Wire = H2Mux::BuildData(Id, Payload);
                         EXPECT_FALSE(co_await peer->WriteAll(Wire));
                         co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     }
                     co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_TRUE(Session->IsOpen()) << "80 字节仍在会话预算 96 内";
                     const auto Wire = H2Mux::BuildData(5, Payload);
                     EXPECT_FALSE(co_await peer->WriteAll(Wire));
                     co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     co_await Net::post(ioc.get_executor(), Net::use_awaitable);
                     EXPECT_FALSE(Session->IsOpen()) << "跨流累计超会话预算应关闭会话";
                 });
    }

    TEST(MuxSessionDeep2, RxBudgetReleasedAfterConsume)
    {
        // 每轮写入 40 字节并立即读走，4 轮累计 160 > 会话预算 96；
        // 预算必须随消费释放，否则第 3 轮就会误判超限。
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Preview::Role::Server;
        opt.MaxStreamRxBytes = 48;
        opt.MaxSessionRxBytes = 96;
        auto Session = Mux::Session<H2Mux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc,
                 [&]() -> Net::awaitable<void>
                 {
                     const std::vector<std::uint8_t> Payload(40, 0x77);
                     const auto Wire = H2Mux::BuildData(1, Payload);
                     EXPECT_FALSE(co_await peer->WriteAll(Wire));
                     auto Handle = co_await Session->AcceptStream();
                     EXPECT_TRUE(Handle != nullptr);
                     std::array<std::uint8_t, 64> Buffer{};
                     for (int Round = 0; Round < 4; ++Round)
                     {
                         if (Round > 0)
                         {
                             EXPECT_FALSE(co_await peer->WriteAll(Wire));
                         }
                         const auto N = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
                         EXPECT_EQ(N, Payload.size()) << "round=" << Round;
                     }
                     EXPECT_TRUE(Session->IsOpen()) << "消费后预算必须释放";
                 });
    }

} // namespace
