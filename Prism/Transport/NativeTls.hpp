/** @file NativeTls.hpp @brief 前缀识别、TLS握手与清理共享一个绝对期限和真实字节池owner。 */
#pragma once
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Preview.hpp>
namespace Prism::Transport
{
    /**
     * @brief 原生 TLS 升级的值结果：可继续使用的载体、终态失败与是否真正下发过握手。
     * @details 输入所有权：Transport 是移交给你的共享载体（成功时的 Encrypted，或识别为非 TLS 时带前缀回放
     *          的候选），Failure 是不拥有任何资源的纯值；二者互斥——Transport 非空时 Failure 必为成功，
     *          失败时载体已被本函数按终态处理。Attempted 只区分「未进入握手」与「握手已失败」。
     *          输出与错误：结果经 awaitable 值返回，不抛异常；期限到期改写 Code 为 Timeout 并保留 Native，
     *          EOF 与底层错误由 Fault::FromNative 保留原 category/value，取消沿前门交付 Canceled，失败关闭
     *          自身的错误覆盖 Failure——四类各自独立，不折叠成单一 error_code。
     *          取消：本结构不触发取消，取消时机由 UpgradeNativeTls 与底层 Transmission 的 completion 决定。
     *          半关闭：本结果不携带半关闭事实；写方向是否已半关由 Transport 自身的 WriteShutdown 决定。
     *          最终关闭者：失败路径上本函数已对载体交付 Close 命令，握手失败还会先等待 TLS engine activity
     *          排空；除该路径外 Close 成功只表示命令已交付，真正的最终关闭者与退栈证据仍是底层叶子载体的
     *          Activity()->Drain()。
     *          executor：结果值可跨 executor 复制；Transport 内部的 State 固定在原载体 executor 上，
     *          使用它继续发起 I/O 时仍是单一执行域。
     */
    struct NativeTlsResult final
    {
        Fault::Failure Failure;
        SharedTransmission Transport;
        bool Attempted{false};
    };
    /**
     * @brief 原生 TLS 升级的入参：移交载体与字节池，借用 SSL context，共享一个绝对期限。
     * @details 输入所有权：Inbound 与 Bytes 为移交所有权——Inbound 被移交给回放候选或失败关闭路径，Bytes 在
     *          成功时经 HandshakeRequest 继续转交给 Encrypted/Writer，为空即 InvalidArgument 并走关闭分支；
     *          Context 是 shared_ptr 共享所有权，调用方必须保活 SSL_CTX 直到握手返回，engine 本身不拥有它。
     *          Timeout 是相对期限，入口处一次性换算为绝对 deadline，prefix 的每个 partial 与后续握手共用
     *          同一期限，不再重新领取一整段超时；非正期限直接判 Timeout。
     *          输出与错误：由 UpgradeNativeTls 的 awaitable<NativeTlsResult> 表达，取消、EOF、Timeout 与
     *          底层原生错误四类分别保留 Code 与 Native，失败关闭的错误另行覆盖。
     *          取消与半关闭：本结构不执行取消，也不表达写半关闭；取消沿 Inbound 的 cancellation slot 与前门
     *          交付，半关闭仍属传输层动作，本入口未定义。
     *          最终关闭者与 executor：Context 之外的实物在返回后归结果或归底层 owner，最终关闭者是 Inbound
     *          指向的叶子载体；prefix 的 deadline timer 建在 Inbound->Executor()，所有实际操作固定该原域，
     *          协程本身在调用方 executor 上恢复，要求单一执行域装配。
     */
    struct NativeTlsRequest final
    {
        SharedTransmission Inbound;
        std::shared_ptr<Net::ssl::context> Context;
        std::chrono::steady_clock::duration Timeout{Encrypted::DefaultHandshakeTimeout};
        std::shared_ptr<Memory::BytePool> Bytes;
    };
    namespace Detail
    {
        struct TlsPrefix final
        {
            std::array<std::byte, 2> Bytes{};
            std::size_t Size{0};
            Fault::Failure Failure;
            bool IsTls{false};
        };
        /** @brief prefix缓冲在本帧拥有；每个partial的计时器沿用同一绝对deadline。 */
        inline auto ReadTlsPrefix(SharedTransmission Inbound, std::chrono::steady_clock::time_point Deadline)
            -> Net::awaitable<TlsPrefix>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            TlsPrefix Prefix;
            Net::steady_timer Timer(Inbound->Executor());
            Timer.expires_at(Deadline);
            while (Prefix.Size < Prefix.Bytes.size())
            {
                const auto Buffer = std::span(Prefix.Bytes).subspan(Prefix.Size);
                auto [Order, Result, TimerError] = co_await Net::experimental::make_parallel_group(
                    Inbound->ReadSome(Buffer, Net::deferred), Timer.async_wait(Net::deferred))
                    .async_wait(Net::experimental::wait_for_one(), Net::use_awaitable);
                if (Result.Bytes > Buffer.size()) { Prefix.Failure = {Fault::Code::InvalidArgument}; co_return Prefix; }
                Prefix.Size += Result.Bytes;
                Prefix.Failure = Result.Failure;
                if (Order[0] == 1 && !TimerError) Prefix.Failure.Code = Fault::Code::Timeout;
                if (Prefix.Size != 0 && Prefix.Bytes[0] != std::byte{0x16}) co_return Prefix;
                if (Prefix.Size == 2)
                { Prefix.IsTls = Prefix.Bytes[1] == std::byte{0x03}; co_return Prefix; }
                if (Prefix.Failure.Failed()) co_return Prefix;
                if (Result.Bytes == 0) { Prefix.Failure = {Fault::Code::WouldBlock}; co_return Prefix; }
            }
            co_return Prefix;
        }
    }
    /** @brief 拥有输入到移交完成；取消值结果保留Native，失败关闭由原载体正式命令执行。 */
    [[nodiscard]] inline auto UpgradeNativeTls(NativeTlsRequest Request) -> Net::awaitable<NativeTlsResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        NativeTlsResult Result;
        if (!Request.Inbound) { Result.Failure = {Fault::Code::InvalidArgument}; co_return Result; }
        if (!Request.Context) { Result.Transport = std::move(Request.Inbound); co_return Result; }
        const auto Deadline = std::chrono::steady_clock::now() + Request.Timeout;
        if (Request.Timeout <= std::chrono::steady_clock::duration::zero() || !Request.Bytes)
        {
            Result.Failure = {Fault::Code::InvalidArgument};
            if (Request.Timeout <= std::chrono::steady_clock::duration::zero())
                Result.Failure = {Fault::Code::Timeout};
            const auto Closed = Request.Inbound->Close();
            if (!Closed) Result.Failure = Closed.error();
            co_return Result;
        }
        auto Prefix = co_await Detail::ReadTlsPrefix(Request.Inbound, Deadline);
        if (!Prefix.IsTls && Prefix.Size != 0 &&
            (Prefix.Bytes[0] != std::byte{0x16} || Prefix.Size == Prefix.Bytes.size()))
        {
            auto Replayed = PreviewTransport::Create(Request.Inbound,
                {std::span(Prefix.Bytes).first(Prefix.Size), Request.Bytes, Prefix.Failure});
            if (!Replayed)
            { Result.Failure = Replayed.error(); const auto Closed = Request.Inbound->Close();
              if (!Closed) Result.Failure = Closed.error(); co_return Result; }
            Result.Transport = std::move(*Replayed);
            co_return Result;
        }
        if (Prefix.Failure.Failed())
        {
            Result.Failure = Prefix.Failure;
            const auto Closed = Request.Inbound->Close();
            if (!Closed) Result.Failure = Closed.error();
            co_return Result;
        }
        Result.Attempted = true;
        auto Replayed = PreviewTransport::Create(Request.Inbound, {std::span(Prefix.Bytes).first(Prefix.Size), Request.Bytes, {}});
        if (!Replayed)
        { Result.Failure = Replayed.error(); const auto Closed = Request.Inbound->Close();
          if (!Closed) Result.Failure = Closed.error(); co_return Result; }
        auto Handshake = co_await Encrypted::SslHandshake(
            {std::move(*Replayed), *Request.Context, Deadline, std::move(Request.Bytes)});
        Result.Failure = Handshake.Failure;
        if (Result.Failure.Succeeded() && Handshake.Stream)
        { Result.Transport = MakeEncrypted(std::move(Handshake.Stream), std::move(Handshake.Bytes)); co_return Result; }
        if (Handshake.Recovered)
        {
            const auto Closed = Handshake.Recovered->Close();
            if (!Closed) Result.Failure = Closed.error();
        }
        if (Handshake.Stream)
        {
            if (auto* Inner = Handshake.Stream->next_layer().NextLayer())
            { const auto Closed = Inner->Close(); if (!Closed) Result.Failure = Closed.error(); }
        }
        co_return Result;
    }
}
