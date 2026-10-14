/**
 * @file ProbeRecognition.hpp
 * @brief 仅供实验验证的首包探测、TLS/SNI 和快照回放 owner。
 * @details 完整保留探测字节、方案执行与取消回放；生产识别只接受已编译 Profile。
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
#include <utility>
#include <Preview/Runtime/Recognition/Probe.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Runtime/Recognition/RecognitionConfig.hpp>
#include <Experiments/Preview/Route.hpp>
#include <Experiments/Preview/SchemeExecutor.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Transport/Replay.hpp>

namespace Preview::Recognition::Experiment
{
    namespace Net = boost::asio;

    class ProbeRecognition final
    {
    public:
        explicit ProbeRecognition(SniRouteTable* Routes = nullptr, SchemeExecutor* Executor = nullptr)
            : Routes_(Routes), Executor_(Executor) {}

        [[nodiscard]] auto Recognize(SharedTransmission Transport) -> Net::awaitable<RecognizeResult>
        {
            ProbeBuffer Buffer(MaxTlsClientHelloBytes);
            co_return co_await RecognizeProbe(std::move(Transport), Buffer, {});
        }

        [[nodiscard]] auto Recognize(SharedTransmission Transport, ProbeBuffer& Buffer,
                                    RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            co_return co_await RecognizeProbe(std::move(Transport), Buffer, std::move(Control));
        }

    private:
        [[nodiscard]] auto RecognizeProbe(SharedTransmission transport, ProbeBuffer &Buffer,
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
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport),
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
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport),
                                             true, ProbePrefix);
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport),
                                             true, ProbePrefix);
            }

            const auto Prefix = ProbePrefix;
            Result.ProbeBytes = Prefix.size();
            if (!ProbeRes.success)
            {
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport),
                                             true, Prefix);
            }

            Result.detected = ProbeRes.Type;
            Result.success = true;
            Result.Status = RecognitionStatus::Accepted;
            if (ProbeRes.Type != Preview::Contract::ProtocolType::Tls)
            {
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport),
                                             true, Prefix);
            }

            auto ReadRace = co_await detail::AwaitWithControl(
                ReadClientHello(*transport, Buffer), ControlRaceRequest{Control, Deadline});
            const auto Captured = Buffer.Data();
            if (ReadRace.Controlled)
            {
                detail::SetControlStatus(Result, ReadRace.Event);
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport), true, Captured);
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                co_return ReplayProbeResult(std::move(Result), Buffer, std::move(transport), true, Captured);
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

            if (!ReplayedTransport)
            {
                Result.success = false;
                co_return Result;
            }
            auto ReplayPool = std::make_shared<Preview::Memory::BytePool>(
                Preview::Memory::BytePoolOptions{.BlockCount = 1});
            auto Created = Preview::Transport::ReplayTransmission::Create(
                ReplayedTransport,
                Preview::Transport::ReplayOptions{Preview::Recognition::MaxTlsClientHelloBytes,
                    Preview::Transport::ReplayMode::Candidate, std::move(ReplayPool)});
            if (!Created)
            {
                Result.transport = std::move(ReplayedTransport);
                Result.success = false;
                co_return Result;
            }
            auto ReplayOwner = std::move(*Created);
            const auto Route = Routes_->LookupValue(Features.ServerName);
            if (!Route)
            {
                (void)ReplayOwner->Rewind();
                Result.transport = std::move(ReplayOwner);
                Result.success = false;
                co_return Result;
            }
            Result.scheme = Route->Scheme;
            if (Route->Protocol != Preview::Contract::ProtocolType::Unknown)
            {
                Result.detected = Route->Protocol;
            }
            if (Result.scheme.empty())
            {
                (void)ReplayOwner->Rewind();
                Result.transport = std::move(ReplayOwner);
                Result.success = Route->AllowFallback;
                co_return Result;
            }
            if (!Executor_ || !Executor_->Has(Result.scheme))
            {
                (void)ReplayOwner->Rewind();
                Result.transport = std::move(ReplayOwner);
                Result.success = false;
                co_return Result;
            }
            (void)ReplayOwner->Rewind();
            detail::ControlRaceResult<SharedTransmission> ExecuteRace;
            try
            {
                ExecuteRace = co_await detail::AwaitWithControl(
                    Executor_->Execute(Result.scheme, ReplayOwner), ControlRaceRequest{Control, Deadline});
            }
            catch (...)
            {
                RecoverSchemeFailure(Result, std::move(ReplayOwner));
                co_return Result;
            }
            if (ExecuteRace.Controlled)
            {
                detail::SetControlStatus(Result, ExecuteRace.Event);
                RecoverSchemeFailure(Result, std::move(ReplayOwner));
                co_return Result;
            }
            if (const auto Event = GetControlEvent(Control, Deadline))
            {
                detail::InvokeCancel(Control);
                detail::SetControlStatus(Result, *Event);
                RecoverSchemeFailure(Result, std::move(ReplayOwner));
                co_return Result;
            }

            auto Wrapped = std::move(ExecuteRace.Value);
            if (!Wrapped)
            {
                RecoverSchemeFailure(Result, std::move(ReplayOwner));
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

        [[nodiscard]] static auto ReplayProbeResult(RecognizeResult Result, ProbeBuffer &Buffer,
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
                Result.transport = WrapPreread(std::move(Transport), Prefix,
                    std::make_shared<Preview::Memory::BytePool>(
                        Preview::Memory::BytePoolOptions{.BlockCount = 1}));
            }
            return Result;
        }

        static auto RecoverSchemeFailure(RecognizeResult &Result,
                                         std::shared_ptr<Preview::Transport::ReplayTransmission> ReplayOwner) -> void
        {
            Result.success = false;
            if (!ReplayOwner)
            {
                Result.transport.reset();
                return;
            }
            if (ReplayOwner->CanRewind())
            {
                (void)ReplayOwner->Rewind();
                Result.transport = std::move(ReplayOwner);
                return;
            }
            (void)ReplayOwner->Cancel();
            (void)ReplayOwner->Close();
            Result.transport.reset();
        }

        [[nodiscard]] static auto DetectBuffered(std::span<const std::byte> Data) -> Preview::Contract::ProtocolType
        {
            const auto ProbeSize = (std::min)(Data.size(), MaxProbeSize);
            if (ProbeSize == 0)
            {
                return Preview::Contract::ProtocolType::Unknown;
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
                Result.success = Result.Type != Preview::Contract::ProtocolType::Unknown;
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


        SniRouteTable* Routes_{nullptr};
        SchemeExecutor* Executor_{nullptr};
    };
}
