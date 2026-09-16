/**
 * @file Context.hpp
 * @brief 会话级日志上下文
 * @details 7 字段前缀系统：worker、Stage、proto、scheme、Target、Conn、born。
 *          前缀缓存 + 版本号机制，字段不变时零开销返回缓存指针。
 *          born 在会话创建时 set_born() 一次，后续不再读时钟。
 *
 * 用法：
 *   auto ctx = std::make_shared<Context>();
 *   ctx->born = steady_clock::now();
 *   ctx->proto = "trojan";
 *   ctx->Bump();
 *   Diagnose::Debug(ctx, "msg");  // 前缀: [W0][S3][trojan][... 18:22:48.842]
 */
#pragma once

#include <Preview/Statistics/Trace.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

namespace Preview::Diagnose
{

    /**
     * @class TraceContext
     * @brief 由 shared_ptr 持有的可复用 trace 上下文。
     * @details Snapshot() 返回值副本；日志生产者不得保存内部地址并跨越 co_await。
     */
    class TraceContext final : public std::enable_shared_from_this<TraceContext>
    {
    public:
        using Selection = Preview::Statistics::TraceSelection;

        TraceContext() noexcept = default;

        explicit TraceContext(Selection SelectionValue) noexcept : Selection_(SelectionValue) {}

        TraceContext(const TraceContext &) = delete;
        auto operator=(const TraceContext &) -> TraceContext & = delete;
        TraceContext(TraceContext &&) = delete;
        auto operator=(TraceContext &&) -> TraceContext & = delete;

        auto SetCorrelation(const Preview::RequestId Value) noexcept -> void
        {
            Correlation_ = Value;
        }

        auto SetWorker(const Preview::WorkerId Value) noexcept -> void
        {
            Worker_ = Value;
        }

        auto SetSession(const Preview::SessionId Value) noexcept -> void
        {
            Session_ = Value;
        }

        auto SetStream(const Preview::StreamId Value) noexcept -> void
        {
            Stream_ = Value;
        }

        auto SetTask(const Preview::TaskId Value) noexcept -> void
        {
            Task_ = Value;
        }

        auto SetGeneration(const Preview::GenerationId Value) noexcept -> void
        {
            Generation_ = Value;
        }

        auto SetCarrier(std::string Value) -> void
        {
            Carrier_ = std::move(Value);
        }

        auto SetProtocol(std::string Value) -> void
        {
            Protocol_ = std::move(Value);
        }

        auto SetSni(std::string Value) -> void
        {
            Sni_ = std::move(Value);
        }

        auto SetAlpn(std::string Value) -> void
        {
            Alpn_ = std::move(Value);
        }

        auto SetTlsVersion(std::string Value) -> void
        {
            TlsVersion_ = std::move(Value);
        }

        auto SetStage(std::string Value) -> void
        {
            Stage_ = std::move(Value);
        }

        auto SetStatus(std::string Value) -> void
        {
            Status_ = std::move(Value);
        }

        auto SetFaultCode(std::string Value) -> void
        {
            FaultCode_ = std::move(Value);
        }

        auto SetNativeError(std::string Value) -> void
        {
            NativeError_ = std::move(Value);
        }

        auto SetElapsedMs(const std::uint64_t Value) noexcept -> void
        {
            ElapsedMs_ = Value;
        }

        auto ClearCorrelation() noexcept -> void
        {
            Correlation_.reset();
        }

        auto ClearWorker() noexcept -> void
        {
            Worker_.reset();
        }

        auto ClearSession() noexcept -> void
        {
            Session_.reset();
        }

        auto ClearStream() noexcept -> void
        {
            Stream_.reset();
        }

        [[nodiscard]] auto Snapshot() const noexcept -> Preview::Statistics::TraceSnapshot
        {
            Preview::Statistics::TraceSnapshot Result;
            if (Selection_.IncludeCorrelation)
            {
                Result.Correlation = Correlation_;
            }
            if (Selection_.IncludeWorker)
            {
                Result.Worker = Worker_;
            }
            if (Selection_.IncludeSession)
            {
                Result.Session = Session_;
            }
            if (Selection_.IncludeStream)
            {
                Result.Stream = Stream_;
            }
            Result.Task = Task_;
            Result.Generation = Generation_;
            Result.Carrier = Carrier_;
            Result.Protocol = Protocol_;
            Result.Sni = Sni_;
            Result.Alpn = Alpn_;
            Result.TlsVersion = TlsVersion_;
            Result.Stage = Stage_;
            Result.Status = Status_;
            Result.FaultCode = FaultCode_;
            Result.NativeError = NativeError_;
            Result.ElapsedMs = ElapsedMs_;
            return Result;
        }

    private:
        Selection Selection_{};
        std::optional<Preview::RequestId> Correlation_;
        std::optional<Preview::WorkerId> Worker_;
        std::optional<Preview::SessionId> Session_;
        std::optional<Preview::StreamId> Stream_;
        std::optional<Preview::TaskId> Task_;
        std::optional<Preview::GenerationId> Generation_;
        std::string Carrier_;
        std::string Protocol_;
        std::string Sni_;
        std::string Alpn_;
        std::string TlsVersion_;
        std::string Stage_;
        std::string Status_;
        std::string FaultCode_;
        std::string NativeError_;
        std::optional<std::uint64_t> ElapsedMs_;
    };

    /// @brief 生命周期阶段
    enum class Stage : std::uint8_t
    {
        Accept = 0,
        Probe = 1,
        Identify = 2,
        Handshake = 3,
        Forward = 4,
        Close = 5,
    };

    /**
 * @struct Context
 * @brief 诊断上下文
 * @details 承载日志前缀字段。shared_ptr 管理（IOCP 回调安全）。
 *          前缀缓存 + gen 版本号：字段变化时 Bump() 标记脏，Prefix() 按需渲染。
 */
    struct Context : public std::enable_shared_from_this<Context>
    {
        Context() = default;

        // 字段
        std::chrono::steady_clock::time_point Born{};
        std::uint16_t Worker = 0;
        std::uint8_t Stage = 0;
        char Target[48] = {};
        char Proto[8] = {};
        char Scheme[8] = {};
        std::uint64_t Conn = 0;

        /**
         * @brief 标记脏——字段变化后调用
         */
        auto Bump() noexcept -> void
        {
            CacheGen++;
        }

        /**
         * @brief 返回前缀指针（缓存命中直接返回，否则重新渲染）
         * @return 日志前缀指针
         */
        [[nodiscard]] auto Prefix() const -> const char *
        {
            if (CacheGen != RenderGen)
            {
                Render();
            }
            return Cached;
        }

    private:
        auto Render() const noexcept -> void
        {
            RenderGen = CacheGen;
            auto Ms = std::chrono::duration_cast<std::chrono::milliseconds>(Born.time_since_epoch()).count();
            auto Sec = Ms / 1000;
            auto Hh = static_cast<int>((Sec % 86400) / 3600);
            auto Mm = static_cast<int>((Sec % 3600) / 60);
            auto Ss = static_cast<int>(Sec % 60);
            std::snprintf(Cached, sizeof(Cached), "[W%u][S%u][%s][%s %02d:%02d:%02d.%03d]", Worker, Stage,
                          Proto, Target, Hh, Mm, Ss, static_cast<int>(Ms % 1000));
        }

        mutable char Cached[80] = {};
        mutable std::uint8_t CacheGen = 0;
        mutable std::uint8_t RenderGen = 0;
    };

} // namespace Preview::Diagnose
