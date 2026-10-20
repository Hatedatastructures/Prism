/** @file LayeredCandidateFactory.cpp @brief TLS 后内层 protocol dispatch 实现。 */

#include <Prism/Composition/Recognition/LayeredCandidateFactory.hpp>
#include <Prism/Composition/Recognition/Detail/InnerProtocolDispatch.hpp>
#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Transport/Preview.hpp>

#include <algorithm>
#include <cstddef>
#include <expected>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Composition::Recognition
{
    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    namespace
    {
        class InnerProtocolFactory final : public Prism::Contract::StreamFactory
        {
        private:
            struct CandidateInspection final
            {
                std::vector<const CandidateInnerBinding*> Accepted;
                bool NeedMore{false};
                bool Structural{false};
            };

            struct WinnerDelivery final
            {
                Prism::Contract::StreamAcceptInput Input;
                Prism::Contract::InboundAdmission Admission;
                Prism::Recognition::ProbeBuffer Buffer;
                const CandidateInnerBinding* Winner;
                Prism::Fault::Failure PendingReadFailure;
            };

            [[nodiscard]] auto InspectCandidates(const Core::ProbeSnapshot& Snapshot)
                -> Net::awaitable<CandidateInspection>
            {
                CandidateInspection Inspection;
                for (const auto& Candidate : Candidates_)
                {
                    if (!Candidate || !Candidate->Spec.Inspect)
                    {
                        continue;
                    }
                    const auto State = Candidate->Spec.Inspect(Snapshot);
                    if (State == Core::MatchState::NeedMore)
                    {
                        Inspection.NeedMore = true;
                        continue;
                    }
                    if (State != Core::MatchState::Structural)
                    {
                        continue;
                    }
                    Inspection.Structural = true;
                    if (!Candidate->Spec.Prepare)
                    {
                        Inspection.Accepted.push_back(Candidate.get());
                        continue;
                    }
                    auto Prepared = co_await Candidate->Spec.Prepare(
                        Core::PrepareContext{Candidate->Spec.Id, Snapshot, {}});
                    if (Prepared.Status == Core::RecognitionStatus::Accepted && !Prepared.Polluted)
                    {
                        Inspection.Accepted.push_back(Candidate.get());
                    }
                    else if (Prepared.NeedMore && !Prepared.Polluted)
                    {
                        Inspection.NeedMore = true;
                    }
                }
                co_return std::move(Inspection);
            }

            [[nodiscard]] static auto SelectWinner(
                const std::vector<const CandidateInnerBinding*>& Accepted)
                -> std::expected<const CandidateInnerBinding*, Prism::Fault::Failure>
            {
                if (Accepted.empty())
                {
                    return nullptr;
                }
                const auto Best = std::max_element(Accepted.begin(), Accepted.end(),
                    [](const auto* Left, const auto* Right)
                    {
                        return Left->Spec.Priority < Right->Spec.Priority;
                    });
                const auto BestPriority = (*Best)->Spec.Priority;
                const auto BestCount = static_cast<std::size_t>(std::count_if(
                    Accepted.begin(), Accepted.end(), [BestPriority](const auto* Candidate)
                    {
                        return Candidate->Spec.Priority == BestPriority;
                    }));
                if (BestCount != 1U)
                {
                    return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                }
                return *Best;
            }

        public:
            explicit InnerProtocolFactory(
                std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates)
                : Candidates_(std::move(Candidates))
            {
            }

            auto Accept(Prism::Contract::StreamAcceptInput Input)
                -> Net::awaitable<Prism::Contract::AcceptOutcome> override
            {
                auto PreparedAdmission =
                    co_await Prism::Contract::InboundAdmission::Prepare(Input.Inbound);
                if (!PreparedAdmission)
                {
                    co_return std::unexpected(PreparedAdmission.error());
                }
                co_return co_await AcceptPrepared(
                    std::move(Input), std::move(*PreparedAdmission));
            }

            auto AcceptPrepared(Prism::Contract::StreamAcceptInput Input,
                Prism::Contract::InboundAdmission Admission)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                if (!Input.Inbound || !Input.Bytes || Candidates_.empty())
                {
                    co_return co_await Admission.Reject(
                        Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                }
                Prism::Recognition::ProbeBuffer Buffer(
                    Prism::Recognition::ProbeBuffer::MaxSupportedBytes, Input.Bytes);
                if (!Buffer.Bytes())
                {
                    co_return co_await Admission.Reject(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }
                auto PendingReadFailure = Prism::Fault::Failure{};
                constexpr std::size_t ReadWindow = 4096U;
                for (;;)
                {
                    const auto Snapshot = Buffer.Snapshot();
                    const auto Inspection = co_await InspectCandidates(Snapshot);
                    const auto WinnerResult = SelectWinner(Inspection.Accepted);
                    if (!WinnerResult)
                    {
                        co_return co_await Admission.Reject(WinnerResult.error());
                    }
                    if (const auto* Winner = *WinnerResult)
                    {
                        co_return co_await AdmitWinner(WinnerDelivery{
                            std::move(Input), std::move(Admission), std::move(Buffer),
                            Winner, PendingReadFailure});
                    }
                    if (PendingReadFailure.Failed())
                    {
                        co_return co_await Admission.Reject(PendingReadFailure);
                    }
                    if (!Inspection.NeedMore && !Inspection.Structural)
                    {
                        co_return co_await Admission.Reject(
                            Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                    }
                    if (Buffer.Size() >= Prism::Recognition::ProbeBuffer::MaxSupportedBytes)
                    {
                        co_return co_await Admission.Reject(
                            Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                    }
                    const auto Fill = co_await Buffer.ReadSome(*Input.Inbound, ReadWindow);
                    if (Fill.Added == 0U)
                    {
                        co_return co_await Admission.Reject(FailureFromFill(Fill));
                    }
                    if (Fill.Status != Core::RecognitionStatus::Accepted)
                    {
                        PendingReadFailure = FailureFromFill(Fill);
                    }
                }
            }

            [[nodiscard]] auto Name() const -> std::string_view override
            {
                return "tls-inner";
            }

        private:
            auto AdmitWinner(WinnerDelivery Request) -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                if (Request.PendingReadFailure.Failed())
                {
                    const auto Replay = Prism::Transport::PreviewTransport::Create(
                        Request.Input.Inbound, Prism::Transport::PrefixInput{
                            Request.Buffer.Data(), Request.Buffer.Bytes(), Request.PendingReadFailure});
                    if (!Replay)
                    {
                        co_return co_await Request.Admission.Reject(Replay.error());
                    }
                    Request.Input.Inbound = std::move(*Replay);
                }
                else
                {
                    Request.Input.Inbound = Request.Buffer.Replay(std::move(Request.Input.Inbound));
                }
                if (!Request.Input.Inbound)
                {
                    co_return co_await Request.Admission.Reject(
                        Prism::Fault::Failure{Prism::Fault::Code::IoError});
                }
                if (const auto Tracked = Request.Admission.Track(Request.Input.Inbound); !Tracked)
                {
                    co_return co_await Request.Admission.Reject(Tracked.error());
                }
                if (!Request.Winner->Accept)
                {
                    co_return co_await Request.Admission.Reject(
                        Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                }
                auto AcceptedPlane = co_await Request.Winner->Accept->Accept(
                    Prism::Contract::StreamAcceptInput{
                        std::move(Request.Input.Inbound), std::move(Request.Input.Metadata),
                        std::move(Request.Input.Bytes)});
                if (!AcceptedPlane)
                {
                    co_return co_await Request.Admission.Reject(AcceptedPlane.error());
                }
                AcceptedPlane->Protocol = Request.Winner->Spec.Protocol;
                co_return co_await Request.Admission.Admit(std::move(*AcceptedPlane));
            }

            [[nodiscard]] static auto FailureFromFill(
                const Core::ProbeFillResult& Fill) noexcept -> Prism::Fault::Failure
            {
                if (Fill.Error)
                {
                    return Prism::Fault::FromNative(Fill.Error);
                }
                if (Fill.Status == Core::RecognitionStatus::EndOfStream)
                {
                    return Prism::Fault::Failure{Prism::Fault::Code::Eof};
                }
                if (Fill.Status == Core::RecognitionStatus::TimedOut)
                {
                    return Prism::Fault::Failure{Prism::Fault::Code::Timeout};
                }
                if (Fill.Status == Core::RecognitionStatus::BudgetExceeded ||
                    Fill.Status == Core::RecognitionStatus::Polluted)
                {
                    return Prism::Fault::Failure{Prism::Fault::Code::ProtocolError};
                }
                return Prism::Fault::Failure{Prism::Fault::Code::IoError};
            }

            std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates_;
        };
    }

    auto MakeInnerProtocolDispatch(
        std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates)
        -> std::shared_ptr<Prism::Contract::StreamFactory>
    {
        return std::make_shared<InnerProtocolFactory>(std::move(Candidates));
    }

    auto LayeredCandidateFactory::Make(TlsCandidateOptions Options,
        CarrierAcceptFn Carrier, CandidateBinding Inner) -> CandidateBinding
    {
        auto Tls = TlsCandidateFactory::Make(std::move(Options), std::move(Carrier));
        CandidateBinding Result;
        Result.Spec = std::move(Tls.Spec);
        Result.Spec.Protocol = Inner.Spec.Protocol;
        Result.Spec.Kind = Core::CandidateKind::TlsCarrier;
        Result.Inner = std::make_shared<const CandidateInnerBinding>(
            CandidateInnerBinding{Inner.Spec, Inner.Accept});
        Result.Accept = std::move(Inner.Accept);
        return Result;
    }

    auto LayeredCandidateFactory::MakePrepared(TlsCandidateOptions Options,
        CarrierAcceptPreparedFn Carrier, CandidateBinding Inner) -> CandidateBinding
    {
        auto Tls = TlsCandidateFactory::MakePrepared(std::move(Options), std::move(Carrier));
        CandidateBinding Result;
        Result.Spec = std::move(Tls.Spec);
        Result.Spec.Protocol = Inner.Spec.Protocol;
        Result.Spec.Kind = Core::CandidateKind::TlsCarrier;
        Result.Inner = std::make_shared<const CandidateInnerBinding>(
            CandidateInnerBinding{Inner.Spec, Inner.Accept});
        Result.Accept = std::move(Inner.Accept);
        return Result;
    }

} // namespace Prism::Composition::Recognition
