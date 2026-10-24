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
#include <Prism/Runtime/Recognition/Probe.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/Detail/RecognitionConfig.hpp>
#include <Experiments/Prism/Runtime/Recognition/Route/Route.hpp>
#include <Experiments/Prism/Runtime/Recognition/Scheme/SchemeExecutor.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Transport/Replay.hpp>

namespace Prism::Recognition::Experiment
{
    namespace Net = boost::asio;

    class ProbeRecognition final
    {
    public:
        explicit ProbeRecognition(SniRouteTable* Routes = nullptr, SchemeExecutor* Executor = nullptr)
            : Routes_(Routes), Executor_(Executor) {}

        [[nodiscard]] auto Recognize(SharedTransmission Transport) -> Net::awaitable<RecognizeResult>
        {
            auto Bytes = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{MaxTlsClientHelloBytes, 1});
            ProbeBuffer Buffer(MaxTlsClientHelloBytes, std::move(Bytes));
            co_return co_await Execute(std::move(Transport), Buffer, {});
        }

        [[nodiscard]] auto Recognize(SharedTransmission Transport, ProbeBuffer& Buffer,
                                    RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>
        {
            co_return co_await Execute(std::move(Transport), Buffer, std::move(Control));
        }

    private:
        struct RecognitionState final
        {
            RecognizeResult Result{};
            ProbeResult Probe{};
            ClientHelloFeatures Features{};
            SharedTransmission Transport;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control{};
            RecognitionControl::Clock::time_point Deadline{RecognitionControl::Clock::time_point::max()};
        };

        [[nodiscard]] static auto ReplayContext(RecognitionState &State, bool UseBuffer,
                                                std::span<const std::byte> Prefix) -> RecognizeResult
        {
            return ReplayProbeResult(ReplayRequest{
                std::move(State.Result), State.Buffer, std::move(State.Transport), UseBuffer, Prefix});
        }

        [[nodiscard]] static auto ControlEvent(RecognitionControl &Control,
                                               RecognitionControl::Clock::time_point Deadline)
            -> std::optional<RecognitionControlEvent>
        {
            return GetControlEvent(Control, Deadline);
        }

        [[nodiscard]] static auto PrepareProbe(RecognitionState &State) -> std::optional<RecognizeResult>
        {
            if (!State.Transport)
            {
                return std::move(State.Result);
            }
            const bool HasExistingBuffer = !State.Buffer->Empty();
            if (!detail::ArmControl(State.Control, State.Transport, State.Deadline))
            {
                detail::SetResultStatus(ResultStatusRequest{
                    &State.Result, RecognitionStatus::IoError,
                    std::make_error_code(std::errc::operation_not_supported)});
                return std::move(State.Result);
            }
            const auto Event = ControlEvent(State.Control, State.Deadline);
            if (!Event)
            {
                return std::nullopt;
            }
            detail::InvokeCancel(State.Control);
            detail::SetControlStatus(State.Result, *Event);
            std::span<const std::byte> Prefix;
            if (HasExistingBuffer)
            {
                Prefix = State.Buffer->Data();
            }
            return ReplayContext(State, HasExistingBuffer, Prefix);
        }

        [[nodiscard]] auto Execute(SharedTransmission Transport, ProbeBuffer &Buffer,
                                    RecognitionControl Control)
            -> Net::awaitable<RecognizeResult>
        {
            RecognitionState State;
            State.Control = std::move(Control);
            State.Deadline = State.Control.Deadline;
            State.Transport = std::move(Transport);
            State.Buffer = &Buffer;
            if (!State.Transport)
            {
                co_return State.Result;
            }

            co_await Net::dispatch(State.Transport->Executor(), Net::use_awaitable);
            if (auto Early = PrepareProbe(State))
            {
                co_return std::move(*Early);
            }
            co_return co_await ProbeStage(std::move(State));
        }

        [[nodiscard]] auto ProbeStage(RecognitionState State) -> Net::awaitable<RecognizeResult>
        {
            auto Race = co_await detail::AwaitWithControl(
                ProbeBuffered(State.Transport, *State.Buffer), ControlRaceRequest{State.Control, State.Deadline});
            const auto Prefix = State.Buffer->Data();
            if (Race.Controlled)
            {
                detail::SetControlStatus(State.Result, Race.Event);
                co_return ReplayContext(State, true, Prefix);
            }
            if (const auto Event = ControlEvent(State.Control, State.Deadline))
            {
                detail::InvokeCancel(State.Control);
                detail::SetControlStatus(State.Result, *Event);
                co_return ReplayContext(State, true, Prefix);
            }
            State.Probe = std::move(Race.Value);
            State.Result.detected = State.Probe.Type;
            State.Result.success = true;
            State.Result.Status = RecognitionStatus::Accepted;
            State.Result.ProbeBytes = Prefix.size();
            if (!State.Probe.success)
            {
                State.Result.success = false;
                co_return ReplayContext(State, true, Prefix);
            }
            if (State.Probe.Type != Prism::Contract::ProtocolType::Tls)
            {
                co_return ReplayContext(State, true, Prefix);
            }
            co_return co_await ReadStage(std::move(State));
        }

        [[nodiscard]] auto ReadStage(RecognitionState State) -> Net::awaitable<RecognizeResult>
        {
            auto Race = co_await detail::AwaitWithControl(
                ReadClientHello(*State.Transport, *State.Buffer),
                ControlRaceRequest{State.Control, State.Deadline});
            const auto Captured = State.Buffer->Data();
            if (Race.Controlled)
            {
                detail::SetControlStatus(State.Result, Race.Event);
                co_return ReplayContext(State, true, Captured);
            }
            if (const auto Event = ControlEvent(State.Control, State.Deadline))
            {
                detail::InvokeCancel(State.Control);
                detail::SetControlStatus(State.Result, *Event);
                co_return ReplayContext(State, true, Captured);
            }
            const auto [ReadError, Features] = std::move(Race.Value);
            State.Features = Features;
            State.Result.preread.assign(Captured.begin(), Captured.end());
            State.Result.ProbeBytes = Captured.size();
            auto Replayed = State.Buffer->Replay(std::move(State.Transport));
            if (ReadError != Error::None)
            {
                State.Result.transport = std::move(Replayed);
                State.Result.success = false;
                co_return std::move(State.Result);
            }
            State.Transport = std::move(Replayed);
            co_return co_await RouteStage(std::move(State));
        }

        [[nodiscard]] auto RouteStage(RecognitionState State) -> Net::awaitable<RecognizeResult>
        {
            if (!Routes_)
            {
                State.Result.transport = std::move(State.Transport);
                State.Result.success = false;
                co_return std::move(State.Result);
            }
            if (!State.Transport)
            {
                State.Result.success = false;
                co_return std::move(State.Result);
            }
            auto Pool = std::make_shared<Prism::Memory::BytePool>(
                Prism::Memory::BytePoolOptions{.BlockCount = 1});
            auto Created = Prism::Transport::ReplayTransmission::Create(
                State.Transport,
                Prism::Transport::ReplayOptions{Prism::Recognition::MaxTlsClientHelloBytes,
                    Prism::Transport::ReplayMode::Candidate, std::move(Pool)});
            if (!Created)
            {
                State.Result.transport = std::move(State.Transport);
                State.Result.success = false;
                co_return std::move(State.Result);
            }
            auto Owner = std::move(*Created);
            const auto Route = Routes_->LookupValue(State.Features.ServerName);
            if (!Route)
            {
                (void)Owner->Rewind();
                State.Result.transport = std::move(Owner);
                State.Result.success = false;
                co_return std::move(State.Result);
            }
            State.Result.scheme = Route->Scheme;
            if (Route->Protocol != Prism::Contract::ProtocolType::Unknown)
            {
                State.Result.detected = Route->Protocol;
            }
            if (State.Result.scheme.empty())
            {
                (void)Owner->Rewind();
                State.Result.transport = std::move(Owner);
                State.Result.success = Route->AllowFallback;
                co_return std::move(State.Result);
            }
            if (!Executor_ || !Executor_->Has(State.Result.scheme))
            {
                (void)Owner->Rewind();
                State.Result.transport = std::move(Owner);
                State.Result.success = false;
                co_return std::move(State.Result);
            }
            (void)Owner->Rewind();
            co_return co_await ExecuteStage(std::move(State), std::move(Owner));
        }

        [[nodiscard]] auto ExecuteStage(RecognitionState State,
                                        std::shared_ptr<Prism::Transport::ReplayTransmission> Owner)
            -> Net::awaitable<RecognizeResult>
        {
            detail::ControlRaceResult<SharedTransmission> Race;
            try
            {
                Race = co_await detail::AwaitWithControl(
                    Executor_->Execute(State.Result.scheme, Owner),
                    ControlRaceRequest{State.Control, State.Deadline});
            }
            catch (...)
            {
                RecoverSchemeFailure(State.Result, std::move(Owner));
                co_return std::move(State.Result);
            }
            if (Race.Controlled)
            {
                detail::SetControlStatus(State.Result, Race.Event);
                RecoverSchemeFailure(State.Result, std::move(Owner));
                co_return std::move(State.Result);
            }
            if (const auto Event = ControlEvent(State.Control, State.Deadline))
            {
                detail::InvokeCancel(State.Control);
                detail::SetControlStatus(State.Result, *Event);
                RecoverSchemeFailure(State.Result, std::move(Owner));
                co_return std::move(State.Result);
            }
            auto Wrapped = std::move(Race.Value);
            if (!Wrapped)
            {
                RecoverSchemeFailure(State.Result, std::move(Owner));
                co_return std::move(State.Result);
            }
            State.Result.transport = std::move(Wrapped);
            co_return std::move(State.Result);
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

        struct ReplayRequest final
        {
            RecognizeResult Result;
            ProbeBuffer *Buffer;
            SharedTransmission Transport;
            bool UseBuffer{false};
            std::span<const std::byte> Prefix;
        };

        [[nodiscard]] static auto ReplayProbeResult(ReplayRequest Request) -> RecognizeResult
        {
            auto Result = std::move(Request.Result);
            const auto Prefix = Request.Prefix;
            Result.ProbeBytes = Prefix.size();
            Result.preread.assign(Prefix.begin(), Prefix.end());
            if (Request.UseBuffer)
            {
                Result.transport = Request.Buffer->Replay(std::move(Request.Transport));
            }
            else
            {
                Result.transport = WrapPreread(std::move(Request.Transport), Prefix,
                    std::make_shared<Prism::Memory::BytePool>(
                        Prism::Memory::BytePoolOptions{.BlockCount = 1}));
            }
            return Result;
        }

        static auto RecoverSchemeFailure(RecognizeResult &Result,
                                         std::shared_ptr<Prism::Transport::ReplayTransmission> ReplayOwner) -> void
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

        [[nodiscard]] static auto DetectBuffered(std::span<const std::byte> Data) -> Prism::Contract::ProtocolType
        {
            const auto ProbeSize = (std::min)(Data.size(), MaxProbeSize);
            if (ProbeSize == 0)
            {
                return Prism::Contract::ProtocolType::Unknown;
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
                Result.success = Result.Type != Prism::Contract::ProtocolType::Unknown;
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
