/**
 * @file Recognition.hpp
 * @brief 协议识别流水线
 * @details 首包探测 → TLS ClientHello/SNI（必要时）→ 方案包装 → 预读回注。
 *          输出 detected（协议类型）、scheme 和可继续读取的 transport。
 * @note TLS 解析与 SNI 路由为 Preview 自有实现；TLS 必须命中显式路由或显式
 *       fallback，未配置路由、路由未命中或方案未注册时默认拒绝。
 */

#pragma once

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Runtime/Recognition/ConfiguredMode.hpp>
#include <Preview/Runtime/Recognition/DeterministicMode.hpp>
#include <Preview/Runtime/Recognition/MixedTrialMode.hpp>
#include <Preview/Runtime/Recognition/Probe.hpp>
#include <Preview/Runtime/Recognition/Protocol.hpp>
#include <Preview/Runtime/Recognition/Route.hpp>
#include <Preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Runtime/Recognition/RawIngressProbe.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/Snapshot.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /**
     * @class Pipeline
     * @brief 识别流水线（Probe → TLS/SNI → scheme → 预读回注）
     * @details routes 与 executor 由启动层拥有并在会话生命周期内保持有效。
     *          scheme 执行前会回滚 Snapshot，保证包装器从 ClientHello 起点读取。
     */
    class Pipeline
    {
    public:
        /**
         * @brief 构造
         * @param Routes SNI 路由表（可选）
         * @param Executor 伪装方案执行器（可选）
         */
        explicit Pipeline(SniRouteTable *Routes = nullptr, SchemeExecutor *Executor = nullptr)
            : Routes_(Routes), Executor_(Executor)
        {
        }

        /**
         * @brief Construct a profile-based recognition pipeline.
         * @param Profile Immutable recognition profile.
         */
        explicit Pipeline(SharedProfile Profile) : Profile_(std::move(Profile)) {}

        /**
         * @brief 执行识别
         * @param transport 入站传输（预读被消费，结果含回注）
         * @return 识别结果
         */
        [[nodiscard]] auto Recognize(SharedTransmission transport) -> Net::awaitable<RecognizeResult>
        {
            if (!transport)
            {
                co_return RecognizeResult{};
            }

            if (Profile_)
            {
                ProbeBuffer Buffer(Profile_->Budget().MaxProbeBytes);
                if (Profile_->Mode() == RecognitionMode::Configured)
                {
                    ConfiguredMode Mode(Profile_);
                    co_return co_await Mode.Recognize(std::move(transport), Buffer);
                }
                if (Profile_->Mode() == RecognitionMode::DeterministicRoute)
                {
                    DeterministicMode Mode(Profile_);
                    co_return co_await Mode.Recognize(std::move(transport), Buffer);
                }
                MixedTrialMode Mode(Profile_);
                co_return co_await Mode.Recognize(std::move(transport), Buffer);
            }

            ProbeBuffer Buffer(MaxTlsClientHelloBytes);
            co_return co_await RecognizeLegacy(std::move(transport), Buffer, {});
        }

        /**
         * @brief Profile recognition overload with caller-owned control state.
         * @param transport Inbound transport.
         * @param Buffer Connection-level pre-read owner.
         * @param Control Caller-owned deadline and cancellation race.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(SharedTransmission transport, ProbeBuffer &Buffer,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            if (!Profile_)
            {
                co_return co_await RecognizeLegacy(std::move(transport), Buffer, std::move(Control));
            }
            if (!transport)
            {
                co_return RecognizeResult{};
            }
            if (Profile_->Mode() == RecognitionMode::Configured)
            {
                ConfiguredMode Mode(Profile_);
                co_return co_await Mode.Recognize(std::move(transport), Buffer, std::move(Control));
            }
            if (Profile_->Mode() == RecognitionMode::DeterministicRoute)
            {
                DeterministicMode Mode(Profile_);
                co_return co_await Mode.Recognize(std::move(transport), Buffer, std::move(Control));
            }
            MixedTrialMode Mode(Profile_);
            co_return co_await Mode.Recognize(std::move(transport), Buffer, std::move(Control));
        }

    private:
        [[nodiscard]] auto RecognizeLegacy(SharedTransmission transport, ProbeBuffer &Buffer,
                                           RecognitionControl Control)
            -> Net::awaitable<RecognizeResult>
        {
            RecognizeResult Result;
            if (!transport)
            {
                co_return Result;
            }

            co_await Net::dispatch(transport->Executor(), Net::use_awaitable);
            const auto Deadline = Control.Deadline;
            const bool HasExistingBuffer = !Buffer.Empty();
            if (!detail::ArmControl(Control, transport, Deadline))
            {
                detail::SetResultStatus(ResultStatusRequest{
                    &Result, RecognitionStatus::IoError,
                    std::make_error_code(std::errc::operation_not_supported)});
                co_return Result;
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                std::span<const std::byte> Prefix;
                if (HasExistingBuffer)
                {
                    Prefix = Buffer.Data();
                }
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport),
                                             HasExistingBuffer, Prefix);
            }

            ProbeResult ProbeRes;
            detail::ControlRaceResult<ProbeResult> ProbeRace;
            ProbeRace = co_await detail::AwaitWithControl(
                ProbeBuffered(transport, Buffer), ControlRaceRequest{Control, Deadline});
            ProbeRes = std::move(ProbeRace.Value);
            const auto ProbePrefix = Buffer.Data();
            if (ProbeRace.Controlled)
            {
                detail::SetControlStatus(Result, ProbeRace.Event);
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport),
                                             true, ProbePrefix);
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport),
                                             true, ProbePrefix);
            }

            const auto Prefix = ProbePrefix;
            Result.ProbeBytes = Prefix.size();
            if (!ProbeRes.success)
            {
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport),
                                             true, Prefix);
            }

            Result.detected = ProbeRes.Type;
            Result.success = true;
            Result.Status = RecognitionStatus::Accepted;
            if (ProbeRes.Type != ProtocolType::Tls)
            {
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport),
                                             true, Prefix);
            }

            auto ReadRace = co_await detail::AwaitWithControl(
                ReadClientHello(*transport, Buffer), ControlRaceRequest{Control, Deadline});
            const auto Captured = Buffer.Data();
            if (ReadRace.Controlled)
            {
                detail::SetControlStatus(Result, ReadRace.Event);
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport), true, Captured);
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                co_return ReplayLegacyResult(std::move(Result), Buffer, std::move(transport), true, Captured);
            }

            const auto [ReadError, Features] = std::move(ReadRace.Value);
            Result.preread.assign(Captured.begin(), Captured.end());
            Result.ProbeBytes = Captured.size();
            auto ReplayedTransport = Buffer.Replay(std::move(transport));
            if (ReadError != Error::None)
            {
                Result.transport = std::move(ReplayedTransport);
                Result.success = false;
                co_return Result;
            }
            if (!Routes_)
            {
                Result.transport = std::move(ReplayedTransport);
                // TLS 必须通过显式 route 选择 carrier 或 fallback；无路由时
                // 不能把完整 ClientHello 当作已识别协议直接透传。
                Result.success = false;
                co_return Result;
            }

            auto Snapshot = std::make_shared<Preview::Transport::Snapshot>(std::move(ReplayedTransport));
            const auto Route = Routes_->LookupValue(Features.ServerName);
            if (!Route)
            {
                (void)Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }
            Result.scheme = Route->Scheme;
            if (Route->Protocol != ProtocolType::Unknown)
            {
                Result.detected = Route->Protocol;
            }
            if (Result.scheme.empty())
            {
                (void)Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = Route->AllowFallback;
                co_return Result;
            }
            if (!Executor_ || !Executor_->Has(Result.scheme))
            {
                (void)Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                Result.success = false;
                co_return Result;
            }
            (void)Snapshot->Rewind();
            detail::ControlRaceResult<SharedTransmission> ExecuteRace;
            try
            {
                ExecuteRace = co_await detail::AwaitWithControl(
                    Executor_->Execute(Result.scheme, Snapshot), ControlRaceRequest{Control, Deadline});
            }
            catch (...)
            {
                RecoverSchemeFailure(Result, std::move(Snapshot));
                co_return Result;
            }
            if (ExecuteRace.Controlled)
            {
                detail::SetControlStatus(Result, ExecuteRace.Event);
                RecoverSchemeFailure(Result, std::move(Snapshot));
                co_return Result;
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                RecoverSchemeFailure(Result, std::move(Snapshot));
                co_return Result;
            }

            auto Wrapped = std::move(ExecuteRace.Value);
            if (!Wrapped)
            {
                RecoverSchemeFailure(Result, std::move(Snapshot));
                co_return Result;
            }
            Result.transport = std::move(Wrapped);
            co_return Result;
        }

        [[nodiscard]] static auto GetControlEvent(const RecognitionControl &Control,
                                                  RecognitionControl::Clock::time_point Deadline)
            -> std::optional<RecognitionControlEvent>
        {
            if (Control.IsCancelled())
            {
                return RecognitionControlEvent::Cancelled;
            }
            if (Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Deadline)
            {
                return RecognitionControlEvent::TimedOut;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ReplayLegacyResult(RecognizeResult Result, ProbeBuffer &Buffer,
                                                      SharedTransmission Transport, bool UseBuffer,
                                                      std::span<const std::byte> Prefix) -> RecognizeResult
        {
            Result.ProbeBytes = Prefix.size();
            Result.preread.assign(Prefix.begin(), Prefix.end());
            if (UseBuffer)
            {
                Result.transport = Buffer.Replay(std::move(Transport));
            }
            else
            {
                Result.transport = WrapPreread(std::move(Transport), Prefix);
            }
            return Result;
        }

        static auto RecoverSchemeFailure(RecognizeResult &Result,
                                         std::shared_ptr<Preview::Transport::Snapshot> Snapshot) -> void
        {
            Result.success = false;
            if (!Snapshot)
            {
                Result.transport.reset();
                return;
            }
            if (Snapshot->CanRewind())
            {
                (void)Snapshot->Rewind();
                Result.transport = std::move(Snapshot);
                return;
            }
            Snapshot->Cancel();
            Snapshot->Close();
            Result.transport.reset();
        }

        /**
         * @brief 探测结果的预读字节
         * @param res 探测结果
         * @return 预读字节 span
         */
        [[nodiscard]] static auto ProbeBytes(const ProbeResult &res) -> std::span<const std::byte>
        {
            return std::span<const std::byte>(res.PreRead.data(), res.PreReadSize);
        }

        [[nodiscard]] static auto DetectBuffered(std::span<const std::byte> Data) -> ProtocolType
        {
            const auto ProbeSize = (std::min)(Data.size(), MaxProbeSize);
            if (ProbeSize == 0)
            {
                return ProtocolType::Unknown;
            }
            const auto Bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Data.data()), ProbeSize);
            return Detect(Bytes);
        }

        [[nodiscard]] static auto ProbeBuffered(SharedTransmission Transport, ProbeBuffer &Buffer)
            -> Net::awaitable<ProbeResult>
        {
            ProbeResult Result;
            while (true)
            {
                const auto Data = Buffer.Data();
                const auto ProbeSize = (std::min)(Data.size(), MaxProbeSize);
                if (ProbeSize == 0)
                {
                    const auto Fill = co_await Buffer.ReadSome(*Transport, MaxProbeSize);
                    if (Fill.Status != RecognitionStatus::Accepted)
                    {
                        const auto Current = Buffer.Data();
                        const auto CurrentSize = (std::min)(Current.size(), MaxProbeSize);
                        Result.PreReadSize = CurrentSize;
                        std::copy_n(Current.begin(), CurrentSize, Result.PreRead.begin());
                        Result.Type = DetectBuffered(Current);
                        Result.success = false;
                        co_return Result;
                    }
                    continue;
                }
                Result.PreReadSize = ProbeSize;
                std::copy_n(Data.begin(), ProbeSize, Result.PreRead.begin());
                Result.Type = DetectBuffered(Data);
                Result.success = Result.Type != ProtocolType::Unknown;
                if (Result.success || ProbeSize == 0 || ProbeSize >= MaxProbeSize)
                {
                    co_return Result;
                }

                const auto Bytes = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Data.data()), ProbeSize);
                if (!CouldBeProtocolPrefix(Bytes))
                {
                    co_return Result;
                }

                const auto Fill = co_await Buffer.ReadSome(*Transport, MaxProbeSize - ProbeSize);
                if (Fill.Status != RecognitionStatus::Accepted)
                {
                    const auto Current = Buffer.Data();
                    const auto CurrentSize = (std::min)(Current.size(), MaxProbeSize);
                    Result.PreReadSize = CurrentSize;
                    std::copy_n(Current.begin(), CurrentSize, Result.PreRead.begin());
                    Result.Type = DetectBuffered(Current);
                    Result.success = false;
                    co_return Result;
                }
            }
        }

        /// SNI 路由表（预留，见类注释）
        SniRouteTable *Routes_{nullptr};
        /// 伪装方案执行器（由启动层拥有）
        SchemeExecutor *Executor_{nullptr};
        /// Immutable profile; an empty profile selects the legacy path.
        SharedProfile Profile_;
    };

} // namespace Preview::Recognition
