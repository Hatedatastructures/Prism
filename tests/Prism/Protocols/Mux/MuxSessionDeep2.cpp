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
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Mux/H2Mux/H2Mux.hpp>
#include <Prism/Protocols/Mux/Smux/Smux.hpp>
#include <Prism/Protocols/Mux/Stream.hpp>
#include <Prism/Protocols/Mux/Yamux/Yamux.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Mux = Prism::Mux;
    namespace H2Mux = Prism::Mux::H2Mux;
    namespace Smux = Prism::Mux::Smux::Detail;
    namespace Yamux = Prism::Mux::Yamux::Detail;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::Role;
    using Prism::make_error_code;
    using Prism::Mux::SessionOptions;

    /** @brief 交付完整 mux wire 帧，并核对实际写进度与原生结果。 */
    template <class WireBytes>
    [[nodiscard]] auto WriteMuxFrame(
        Prism::SharedTransmission Peer,
        WireBytes Wire) -> Net::awaitable<Prism::IoResult>
    {
        const auto Result = co_await Peer->WriteExact(Prism::AsBytesSpan(Wire));
        EXPECT_EQ(Result.Bytes, Wire.size());
        EXPECT_FALSE(Result.Failure.Native);
        co_return Result;
    }

    struct StreamTaskIdentityRequest final
    {
        std::shared_ptr<Mux::Session<Smux::Codec>> Session;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Registry;
        Prism::Lifecycle::TaskIdentity Parent;
    };

    auto RunStreamTaskIdentity(StreamTaskIdentityRequest Request) -> Net::awaitable<void>
    {
        const auto Stream = co_await Request.Session->OpenStream();
        if (!Stream)
        {
            ADD_FAILURE() << "OpenStream failed";
            co_await Request.Session->Close();
            co_return;
        }
        const auto Context = Stream->RetirementContext();
        EXPECT_EQ(Context.SessionId, Request.Parent.SessionId);
        EXPECT_EQ(Context.WorkerId, Request.Parent.WorkerId);
        EXPECT_EQ(Context.Generation, Request.Parent.Generation);
        EXPECT_EQ(Context.StreamId, Prism::StreamId{Stream->Id()});
        EXPECT_EQ(Context.ParentTaskId, Request.Parent.TaskId);
        Prism::Mux::StreamTransmission Transmission(Stream);
        EXPECT_TRUE(Transmission.OnClose());
        const auto DrainResult = co_await Transmission.DrainTerminations();
        EXPECT_TRUE(DrainResult);
        EXPECT_GE(Request.Registry->Stats().Started, 3U);
        co_await Request.Session->Close();
        const auto Drained = co_await Request.Registry->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_EQ(Request.Registry->Stats().Active, 0U);
    }

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

    using SmuxSession = std::shared_ptr<Mux::Session<Smux::Codec>>;
    using YamuxSession = std::shared_ptr<Mux::Session<Yamux::Codec>>;
    using H2MuxSession = std::shared_ptr<Mux::Session<H2Mux::Codec>>;

    /// 驱动 Smux 的 Open/Data/FIN/NOP/RST 事件分发路径。
    auto RunDispatchAllEvents(SmuxSession Session,
                              std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto W1 = co_await WriteMuxFrame(Peer, MakeSynWithPayload(1, "Open-payload"));
        EXPECT_FALSE(W1.Failure.Failed());
        auto Handle = co_await Session->AcceptStream();
        EXPECT_TRUE(Handle);
        if (!Handle)
        {
            co_await Session->Close();
            co_return;
        }
        std::array<std::uint8_t, 64> Buffer{};
        const auto N = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), N), "Open-payload");
        EXPECT_EQ(Session->StreamCount(), 1u);

        const auto W2 = co_await WriteMuxFrame(Peer,
            Smux::BuildPush(1, AsU8Span(std::string_view{"data1"})));
        EXPECT_FALSE(W2.Failure.Failed());
        const auto N1 = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), N1), "data1");

        const auto W3 = co_await WriteMuxFrame(Peer, MakeSynWithPayload(3, "explicit"));
        EXPECT_FALSE(W3.Failure.Failed());
        auto Second = co_await Session->AcceptStream();
        EXPECT_TRUE(Second);
        if (!Second)
        {
            co_await Session->Close();
            co_return;
        }
        const auto N2 = co_await Second->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), N2), "explicit");
        EXPECT_EQ(Session->StreamCount(), 2u);

        const auto W4 = co_await WriteMuxFrame(Peer,
            Smux::BuildPush(0, AsU8Span(std::string_view{"x"})));
        EXPECT_FALSE(W4.Failure.Failed());

        const auto W5 = co_await WriteMuxFrame(Peer, Smux::BuildFin(1));
        EXPECT_FALSE(W5.Failure.Failed());
        const auto FinRead = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(FinRead, 0u);
        EXPECT_TRUE(Handle->IsPeerEof());
        EXPECT_EQ(Session->StreamCount(), 2u);

        const auto W6 = co_await WriteMuxFrame(Peer, Smux::BuildFin(99));
        EXPECT_FALSE(W6.Failure.Failed());

        Smux::FrameHeader NopHeader{};
        NopHeader.cmd = Smux::Command::Nop;
        const auto W7 = co_await WriteMuxFrame(Peer, Smux::Build(NopHeader));
        EXPECT_FALSE(W7.Failure.Failed());
        EXPECT_EQ(Session->StreamCount(), 2u);

        const auto W8 = co_await WriteMuxFrame(Peer, Smux::BuildFin(3));
        EXPECT_FALSE(W8.Failure.Failed());
        const auto SecondFinRead = co_await Second->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(SecondFinRead, 0u);
        EXPECT_TRUE(Second->IsPeerEof());
        EXPECT_EQ(Session->StreamCount(), 2u);

        const auto W9 = co_await WriteMuxFrame(Peer, Smux::BuildFin(98));
        EXPECT_FALSE(W9.Failure.Failed());
        EXPECT_EQ(Session->StreamCount(), 2u);
        co_await Session->Close();
    }

    /// 注入非法 Smux 头，确认帧解析错误关闭会话。
    auto RunMalformedFrame(SmuxSession Session,
                           std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, Smux::FrameHdrsize> Malformed{
            0x7F, static_cast<std::uint8_t>(Smux::Command::Push), 0, 0, 1, 0, 0, 0};
        const auto ErrorCode = co_await WriteMuxFrame(Peer, Malformed);
        EXPECT_FALSE(ErrorCode.Failure.Failed());
        const auto Drained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_FALSE(Session->IsOpen());
        co_await Session->Close();
    }

    /// 注入超过 Yamux 协议长度上限的头，确认会话关闭。
    auto RunPayloadLimit(YamuxSession Session,
                         std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, Yamux::FrameHdrsize> Oversized{
            Yamux::ProtocolVersion,
            static_cast<std::uint8_t>(Yamux::MessageType::Data),
            0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF};
        const auto ErrorCode = co_await WriteMuxFrame(Peer, Oversized);
        EXPECT_FALSE(ErrorCode.Failure.Failed());
        const auto Drained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_FALSE(Session->IsOpen());
        co_await Session->Close();
    }

    /// 覆盖 Yamux 的 FIN、RST、未知流和关闭后本端发送路径。
    auto RunYamuxRstEvent(YamuxSession Session,
                          std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        (void)Session->Executor();
        const auto W1 = co_await WriteMuxFrame(Peer,
            Yamux::BuildData(Yamux::Flags::Syn, 1, AsU8Span(std::string_view{"Open-payload"})));
        EXPECT_FALSE(W1.Failure.Failed());
        auto Handle = co_await Session->AcceptStream();
        EXPECT_TRUE(Handle);
        if (!Handle)
        {
            co_await Session->Close();
            co_return;
        }
        std::array<std::uint8_t, 64> Buffer{};
        const auto N = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), N), "Open-payload");
        EXPECT_EQ(Session->StreamCount(), 1u);

        const auto W2 = co_await WriteMuxFrame(Peer, Yamux::BuildData(Yamux::Flags::Fin, 1, {}));
        EXPECT_FALSE(W2.Failure.Failed());
        const auto PeerFinBytes = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(PeerFinBytes, 0U);
        EXPECT_TRUE(Handle->IsPeerEof());
        EXPECT_EQ(Session->StreamCount(), 1u);

        const auto W3 = co_await WriteMuxFrame(Peer, Yamux::BuildData(Yamux::Flags::Fin, 99, {}));
        EXPECT_FALSE(W3.Failure.Failed());
        EXPECT_EQ(Session->StreamCount(), 1u);

        const auto W4Open = co_await WriteMuxFrame(Peer,
            Yamux::BuildData(Yamux::Flags::Syn, 3,
                             AsU8Span(std::string_view{"Reset-payload"})));
        EXPECT_FALSE(W4Open.Failure.Failed());
        auto ResetHandle = co_await Session->AcceptStream();
        EXPECT_TRUE(ResetHandle);
        if (!ResetHandle)
        {
            co_await Session->Close();
            co_return;
        }
        EXPECT_EQ(Session->StreamCount(), 2u);

        const auto W4Reset = co_await WriteMuxFrame(Peer, Yamux::BuildData(Yamux::Flags::Rst, 3, {}));
        EXPECT_FALSE(W4Reset.Failure.Failed());
        const auto ResetClosed = co_await Mux::StreamHandle<>::WaitUntilClosed(ResetHandle);
        EXPECT_TRUE(ResetClosed);
        EXPECT_FALSE(ResetHandle->IsPeerEof());
        EXPECT_TRUE(ResetHandle->IsClosed());
        EXPECT_FALSE(ResetHandle->IsOpen());
        EXPECT_EQ(ResetHandle->QueuedRxBytes(), 0u);
        const auto ResetRead = co_await ResetHandle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(ResetRead, 0u);
        EXPECT_EQ(Session->StreamCount(), 1u);

        const auto W4 = co_await WriteMuxFrame(Peer, Yamux::BuildData(Yamux::Flags::Rst, 1, {}));
        EXPECT_FALSE(W4.Failure.Failed());
        const auto HandleClosed = co_await Mux::StreamHandle<>::WaitUntilClosed(Handle);
        EXPECT_TRUE(HandleClosed);
        EXPECT_TRUE(Handle->IsClosed());
        EXPECT_FALSE(Handle->IsOpen());
        EXPECT_EQ(Session->StreamCount(), 0u);

        const auto W5 = co_await WriteMuxFrame(Peer, Yamux::BuildData(Yamux::Flags::Rst, 98, {}));
        EXPECT_FALSE(W5.Failure.Failed());
        EXPECT_EQ(Session->StreamCount(), 0u);
        co_await Handle->Shutdown();
        co_await Handle->Reset();
        co_await Session->Close();
    }

    /// 覆盖 H2Mux 隐式开流、CLOSE 半关闭和未知流路径。
    auto RunH2muxFinAndImplicitOpen(H2MuxSession Session,
                                    std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        (void)Session->Executor();
        const auto W1 = co_await WriteMuxFrame(Peer,
            H2Mux::BuildData(1, AsU8Span(std::string_view{"implicit"})));
        EXPECT_FALSE(W1.Failure.Failed());
        auto Handle = co_await Session->AcceptStream();
        EXPECT_TRUE(Handle);
        if (!Handle)
        {
            co_await Session->Close();
            co_return;
        }
        std::array<std::uint8_t, 64> Buffer{};
        const auto N = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Buffer.data()), N), "implicit");
        EXPECT_EQ(Session->StreamCount(), 1u);

        const auto W2 = co_await WriteMuxFrame(Peer, H2Mux::BuildClose(1));
        EXPECT_FALSE(W2.Failure.Failed());
        const auto PeerFinRead = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(PeerFinRead, 0u);
        EXPECT_TRUE(Handle->IsPeerEof());
        const auto W3 = co_await WriteMuxFrame(Peer, H2Mux::BuildClose(77));
        EXPECT_FALSE(W3.Failure.Failed());
        co_await Handle->Shutdown();
        co_await Handle->Reset();
        co_await Session->Close();
    }

    /// 覆盖 StreamHandle 的 FIN、RST、取消和读超时操作。
    auto RunStreamHandleMethods(SmuxSession Session) -> Net::awaitable<void>
    {
        (void)Session->Executor();
        auto Handle = co_await Session->OpenStream();
        EXPECT_TRUE(Handle);
        if (!Handle)
        {
            co_return;
        }
        EXPECT_TRUE(Handle->IsOpen());
        EXPECT_EQ(Handle->Id(), 1u);
        co_await Handle->Shutdown();
        EXPECT_TRUE(Handle->IsFinSent());
        EXPECT_TRUE(Handle->IsOpen());
        Handle->SetPeerEof();
        EXPECT_TRUE(Handle->IsPeerEof());
        Handle->OnRst();
        EXPECT_TRUE(Handle->IsClosed());
        EXPECT_FALSE(Handle->IsOpen());

        auto Handle2 = co_await Session->OpenStream();
        EXPECT_TRUE(Handle2);
        if (!Handle2)
        {
            co_return;
        }
        Handle2->Cancel();
        std::array<std::uint8_t, 8> Buffer{};
        const auto N = co_await Handle2->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(N, 0u);
        Handle2->SetTimeout(std::chrono::milliseconds(20));
        const auto N2 = co_await Handle2->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(N2, 0u);

        auto Handle3 = co_await Session->OpenStream();
        EXPECT_TRUE(Handle3);
        if (!Handle3)
        {
            co_return;
        }
        Handle3->SetTimeout(std::chrono::milliseconds(20));
        const auto N3 = co_await Handle3->ReadSome(std::span<std::uint8_t>(Buffer));
        EXPECT_EQ(N3, 0u);
        co_await Handle2->Shutdown();
        co_await Handle2->Reset();
        co_await Session->Close();
        co_await Handle2->Close();
    }

    auto RunSessionClosedPaths(SmuxSession Session) -> Net::awaitable<void>
    {
        auto Handle = co_await Session->OpenStream();
        EXPECT_TRUE(Handle);
        if (!Handle)
        {
            co_return;
        }
        EXPECT_TRUE(Session->IsOpen());
        co_await Session->Close();
        EXPECT_FALSE(Session->IsOpen());
        const auto NullStream = co_await Session->OpenStream();
        EXPECT_EQ(NullStream, nullptr);
        auto Accepted = co_await Session->AcceptStream();
        EXPECT_EQ(Accepted, nullptr);
        const auto ErrorCode = co_await Handle->WriteAll(AsU8Span(std::string_view{"x"}));
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode, make_error_code(Error::BrokenPipe));
    }

    auto RunIncomingStreams(SmuxSession Session,
                            std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const auto First = Smux::BuildSyn(1);
        const auto FirstWrite = co_await WriteMuxFrame(Peer, First);
        EXPECT_TRUE(FirstWrite.Failure.Succeeded());
        EXPECT_EQ(FirstWrite.Bytes, First.size());
        auto Accepted = co_await Session->AcceptStream();
        EXPECT_NE(Accepted, nullptr);
        if (!Accepted)
        {
            co_return;
        }
        const auto Second = Smux::BuildSyn(3);
        const auto SecondWrite = co_await WriteMuxFrame(Peer, Second);
        EXPECT_TRUE(SecondWrite.Failure.Succeeded());
        EXPECT_EQ(SecondWrite.Bytes, Second.size());
        auto Rejected = co_await Session->AcceptStream();
        EXPECT_EQ(Rejected, nullptr);
        EXPECT_FALSE(Session->IsOpen());
    }

    auto RunSessionReadTimeout(Net::io_context &Ioc, SmuxSession Session)
        -> Net::awaitable<void>
    {
        Net::steady_timer Wait(Ioc);
        Wait.expires_after(std::chrono::milliseconds(50));
        co_await Wait.async_wait(Net::use_awaitable);
        EXPECT_FALSE(Session->IsOpen());
    }

    struct WrapDiagnosticRequest final
    {
        SmuxSession Session;
        bool Enabled;
        const char *Stage;
        std::size_t Opened;
        std::uint32_t LastId;
    };

    auto EmitWrapDiagnostic(WrapDiagnosticRequest Request) -> void
    {
        if (!Request.Enabled)
        {
            return;
        }
        const auto Stats = Request.Session->Tasks()->Stats();
        std::fprintf(
            stdout,
            "mux_wrap_diag stage=%s opened=%zu last_id=%u streams=%zu active=%zu started=%zu completed=%zu "
            "cancelled=%zu failed=%zu quarantined=%zu drain_blocked=%u\n",
            Request.Stage,
            Request.Opened,
            Request.LastId,
            Request.Session->StreamCount(),
            Stats.Active,
            Stats.Started,
            Stats.Completed,
            Stats.Cancelled,
            Stats.Failed,
            Stats.Quarantined,
            Stats.DrainBlocked ? 1U : 0U);
        std::fflush(stdout);
    }

    /// 保留 32768 个奇数流以及第 32769 个 65537 ID 的环绕契约。
    auto RunStreamIdWrap(
        SmuxSession Session,
        const bool Diagnose,
        std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        std::uint32_t LastId = 0;
        std::array<std::byte, 64> DrainBuffer{};
        for (std::size_t Index = 0; Index < 32768; ++Index)
        {
            auto Handle = co_await Session->OpenStream();
            if (!Handle)
            {
                EXPECT_TRUE(false) << "OpenStream Failed at " << Index;
                co_await Session->Close();
                co_return;
            }
            LastId = Handle->Id();
            const auto Output = co_await Peer->ReadSome(std::span<std::byte>(DrainBuffer));
            if (Output.Failure.Failed() || Output.Bytes == 0)
            {
                ADD_FAILURE() << "Peer drain failed at " << Index;
                co_await Session->Close();
                co_return;
            }
            const auto Opened = Index + 1;
            if (Diagnose && Opened % 4096 == 0)
            {
                EmitWrapDiagnostic({Session, Diagnose, "open-progress", Opened, LastId});
            }
        }
        EXPECT_EQ(Session->StreamCount(), 32768u);
        EmitWrapDiagnostic({Session, Diagnose, "before-next", 32768, LastId});
        auto Next = co_await Session->OpenStream();
        EXPECT_TRUE(Next != nullptr);
        if (!Next)
        {
            EmitWrapDiagnostic({Session, Diagnose, "before-close", 32768, LastId});
            co_await Session->Close();
            EmitWrapDiagnostic({Session, Diagnose, "close-return", 32768, LastId});
            EmitWrapDiagnostic({Session, Diagnose, "scope-end", 32768, LastId});
            co_return;
        }
        LastId = Next->Id();
        const auto Output = co_await Peer->ReadSome(std::span<std::byte>(DrainBuffer));
        if (Output.Failure.Failed() || Output.Bytes == 0)
        {
            ADD_FAILURE() << "Peer drain failed after wraparound";
            co_await Session->Close();
            co_return;
        }
        EXPECT_EQ(Next->Id(), 65537u);
        EXPECT_EQ(Session->StreamCount(), 32769u);
        EmitWrapDiagnostic({Session, Diagnose, "before-close", 32769, LastId});
        co_await Session->Close();
        EmitWrapDiagnostic({Session, Diagnose, "close-return", 32769, LastId});
        EmitWrapDiagnostic({Session, Diagnose, "scope-end", 32769, LastId});
    }

    auto RunRxStreamBudget(H2MuxSession Session,
                           std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const std::vector<std::uint8_t> Payload(60, 0x5A);
        const auto Wire = H2Mux::BuildData(1, Payload);
        EXPECT_TRUE((co_await WriteMuxFrame(Peer, Wire)).Failure.Succeeded());
        const auto Drained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_FALSE(Session->IsOpen()) << "单流接收预算超限应关闭会话";
        co_await Session->Close();
    }

    auto RunRxSessionBudget(H2MuxSession Session,
                            std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const std::vector<std::uint8_t> Payload(40, 0x33);
        for (const std::uint32_t Id : {1u, 3u})
        {
            const auto Wire = H2Mux::BuildData(Id, Payload);
            EXPECT_TRUE((co_await WriteMuxFrame(Peer, Wire)).Failure.Succeeded());
        }
        const auto First = co_await Session->AcceptStream();
        EXPECT_TRUE(First != nullptr);
        if (!First)
        {
            co_await Session->Close();
            co_return;
        }
        const auto Second = co_await Session->AcceptStream();
        EXPECT_TRUE(Second != nullptr);
        if (!Second)
        {
            co_await Session->Close();
            co_return;
        }
        EXPECT_TRUE(Session->IsOpen()) << "80 字节仍在会话预算 96 内";
        const auto Wire = H2Mux::BuildData(5, Payload);
        EXPECT_TRUE((co_await WriteMuxFrame(Peer, Wire)).Failure.Succeeded());
        const auto Drained = co_await Session->Tasks()->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_FALSE(Session->IsOpen()) << "跨流累计超会话预算应关闭会话";
        co_await Session->Close();
    }

    auto RunRxBudgetRelease(H2MuxSession Session,
                            std::shared_ptr<MemoryStream> Peer) -> Net::awaitable<void>
    {
        const std::vector<std::uint8_t> Payload(40, 0x77);
        const auto Wire = H2Mux::BuildData(1, Payload);
        EXPECT_TRUE((co_await WriteMuxFrame(Peer, Wire)).Failure.Succeeded());
        auto Handle = co_await Session->AcceptStream();
        EXPECT_TRUE(Handle != nullptr);
        if (!Handle)
        {
            co_await Session->Close();
            co_return;
        }
        std::array<std::uint8_t, 64> Buffer{};
        for (int Round = 0; Round < 4; ++Round)
        {
            if (Round > 0)
            {
                EXPECT_TRUE((co_await WriteMuxFrame(Peer, Wire)).Failure.Succeeded());
            }
            const auto Count = co_await Handle->ReadSome(std::span<std::uint8_t>(Buffer));
            EXPECT_EQ(Count, Payload.size()) << "round=" << Round;
        }
        EXPECT_TRUE(Session->IsOpen()) << "消费后预算必须释放";
        co_await Session->Close();
    }

    TEST(MuxSessionDeep2, DispatchAllEvents)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Prism::Role::Server;
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc, RunDispatchAllEvents(Session, peer));
    }

    TEST(MuxSessionDeep2, MuxMalformedFrameClosesSession)
    {
        Net::io_context ioc;
        auto [raw, peer_raw] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(peer_raw));
        auto Session = Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(raw)), SessionOptions{});
        RunCoro(ioc, RunMalformedFrame(Session, peer));
    }

    TEST(MuxSessionDeep2, MuxPayloadLimitClosesSession)
    {
        Net::io_context ioc;
        auto [raw, peer_raw] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(peer_raw));
        auto Session = Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(raw)), SessionOptions{});
        RunCoro(ioc, RunPayloadLimit(Session, peer));
    }

    TEST(MuxSessionDeep2, YamuxRstEvent)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions YamuxOptions{};
        YamuxOptions.Role = Prism::Role::Server;
        auto Session = Mux::Session<Yamux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), YamuxOptions);

        RunCoro(ioc, RunYamuxRstEvent(Session, peer));
    }

    TEST(MuxSessionDeep2, H2muxFinAndImplicitOpen)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions H2Options{};
        H2Options.Role = Prism::Role::Server;
        auto Session = Mux::Session<H2Mux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), H2Options);

        RunCoro(ioc, RunH2muxFinAndImplicitOpen(Session, peer));
    }

    TEST(MuxSessionDeep2, StreamHandleMethods)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), SessionOptions{});

        RunCoro(ioc, RunStreamHandleMethods(Session));
    }

    TEST(MuxSessionDeep2, SessionClosedPaths)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), SessionOptions{});

        RunCoro(ioc, RunSessionClosedPaths(Session));
    }

    TEST(MuxSessionDeep2, IncomingStreamsHonorMaxAndRole)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        SessionOptions Opt{};
        Opt.Role = Prism::Role::Server;
        Opt.MaxStreams = 1;
        auto Session = Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(a)), Opt);
        auto Peer = std::make_shared<MemoryStream>(std::move(b));

        RunCoro(ioc, RunIncomingStreams(Session, Peer));
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

        RunCoro(ioc, RunSessionReadTimeout(ioc, Session));
    }

    TEST(MuxSessionDeep2, StreamIdWrapAround)
    {
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        SessionOptions opt{};
        opt.Role = Prism::Role::Client;
        opt.MaxStreams = 32769;
        auto Session = Mux::Session<Smux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);
        auto Peer = std::make_shared<MemoryStream>(std::move(b));
        const bool Diagnose = std::getenv("PRISM_MUX_STREAM_WRAP_DIAG") != nullptr;
        RunCoro(ioc, RunStreamIdWrap(Session, Diagnose, Peer));
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
        opt.Role = Prism::Role::Server;
        opt.MaxStreamRxBytes = 48;
        opt.MaxSessionRxBytes = 1024;
        auto Session = Mux::Session<H2Mux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc, RunRxStreamBudget(Session, peer));
    }

    TEST(MuxSessionDeep2, RxSessionBudgetExceededClosesSession)
    {
        // 跨流累计 120 字节 > 会话预算 96（每流 40 未超 48）：
        // 会话级预算必须在第三个流触发关闭。
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Prism::Role::Server;
        opt.MaxStreamRxBytes = 48;
        opt.MaxSessionRxBytes = 96;
        auto Session = Mux::Session<H2Mux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc, RunRxSessionBudget(Session, peer));
    }

    TEST(MuxSessionDeep2, RxBudgetReleasedAfterConsume)
    {
        // 每轮写入 40 字节并立即读走，4 轮累计 160 > 会话预算 96；
        // 预算必须随消费释放，否则第 3 轮就会误判超限。
        Net::io_context ioc;
        auto [a, b] = MakeMemoryPair(ioc.get_executor());
        auto peer = std::make_shared<MemoryStream>(std::move(b));
        SessionOptions opt{};
        opt.Role = Prism::Role::Server;
        opt.MaxStreamRxBytes = 48;
        opt.MaxSessionRxBytes = 96;
        auto Session = Mux::Session<H2Mux::Codec>::Create(std::make_shared<MemoryStream>(std::move(a)), opt);

        RunCoro(ioc, RunRxBudgetRelease(Session, peer));
    }

    TEST(MuxSessionDeep2, StreamFinTaskInheritsFullParentScope)
    {
        Net::io_context ioc;
        auto [Raw, PeerRaw] = MakeMemoryPair(ioc.get_executor());
        auto Registry = std::make_shared<Prism::Lifecycle::TaskRegistry>(ioc.get_executor());
        Prism::Lifecycle::TaskRequest ParentRequest;
        ParentRequest.Context = Prism::Lifecycle::TaskContext{
            Prism::SessionId{551}, {}, Prism::WorkerId{17}, Prism::GenerationId{29}, {}};
        ParentRequest.StartOnSubmit = true;
        const auto Parent = Registry->SpawnTracked(
            std::move(ParentRequest), []() -> Net::awaitable<void> { co_return; }());
        ASSERT_TRUE(Parent);
        SessionOptions Options;
        Options.Registry = Registry;
        Options.Identity = Parent->Identity();
        auto Session = Mux::Session<Smux::Codec>::Create(
            std::make_shared<MemoryStream>(std::move(Raw)), Options);
        ASSERT_NE(Session, nullptr);

        RunCoro(ioc, RunStreamTaskIdentity(
            StreamTaskIdentityRequest{Session, Registry, Parent->Identity()}));
        (void)PeerRaw;
    }

} // namespace
