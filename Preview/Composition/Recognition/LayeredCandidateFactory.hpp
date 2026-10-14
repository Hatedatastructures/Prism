/**
 * @file LayeredCandidateFactory.hpp
 * @brief TLS carrier 与内层协议候选的 Composition 组合器
 * @details Runtime 只看到一个候选。提交阶段先由 TLS carrier 完成外层
 *          解包/认证，Session 随后通过同一候选的接入回调调用内层协议
 *          handler；试探阶段不会触发任一 handler。
 */

#pragma once
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <memory>
#include <utility>

#include <Preview/Composition/Recognition/CandidateModel.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Runtime/Session.hpp>

#include <algorithm>
#include <cstddef>
#include <vector>

namespace Preview::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;

    /**
     * @brief 在已经解密的 carrier 数据面上选择内层协议。
     * @details 同一 SNI 可以承载多个内层协议；每个协议先用纯读的
     *          Inspect/Prepare 试探，选中后再从 ProbeBuffer 回放原始字节给
     *          原有 handler，避免失败候选消费连接状态。
     */
    class InnerProtocolFactory final : public Preview::Contract::StreamFactory
    {
    public:
        explicit InnerProtocolFactory(std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates)
            : Candidates_(std::move(Candidates)) {}

        auto Accept(Preview::Contract::StreamAcceptInput Input)
            -> Net::awaitable<Preview::Contract::AcceptOutcome> override
        {
            auto PreparedAdmission =
                co_await Preview::Contract::InboundAdmission::Prepare(Input.Inbound);
            if (!PreparedAdmission)
            {
                co_return std::unexpected(PreparedAdmission.error());
            }
            co_return co_await AcceptPrepared(
                std::move(Input), std::move(*PreparedAdmission));
        }



        auto AcceptPrepared(
            Preview::Contract::StreamAcceptInput Input,
            Preview::Contract::InboundAdmission Admission)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            if (!Input.Inbound || !Input.Bytes || Candidates_.empty())
            {
                co_return co_await Admission.Reject(
                    Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
            }

            Preview::Recognition::ProbeBuffer Buffer(
                Preview::Recognition::ProbeBuffer::MaxSupportedBytes,
                Input.Bytes);
            if (!Buffer.Bytes())
            {
                co_return co_await Admission.Reject(
                    Preview::Fault::Failure{Preview::Fault::Code::IoError});
            }
            constexpr std::size_t ReadWindow = 4096U;
            for (;;)
            {
                const auto Snapshot = Buffer.Snapshot();
                std::vector<const CandidateInnerBinding *> Accepted;
                bool NeedMore = false;
                bool Structural = false;

                for (const auto &Candidate : Candidates_)
                {
                    if (!Candidate || !Candidate->Spec.Inspect)
                    {
                        continue;
                    }
                    const auto State = Candidate->Spec.Inspect(Snapshot);
                    if (State == Core::MatchState::NeedMore)
                    {
                        NeedMore = true;
                        continue;
                    }
                    if (State != Core::MatchState::Structural)
                    {
                        continue;
                    }
                    Structural = true;
                    if (!Candidate->Spec.Prepare)
                    {
                        Accepted.push_back(Candidate.get());
                        continue;
                    }

                    auto Prepared = co_await Candidate->Spec.Prepare(
                        Core::PrepareContext{Candidate->Spec.Id, Snapshot, {}});
                    if (Prepared.Status == Core::RecognitionStatus::Accepted &&
                        !Prepared.Polluted)
                    {
                        Accepted.push_back(Candidate.get());
                    }
                    else if (Prepared.NeedMore && !Prepared.Polluted)
                    {
                        NeedMore = true;
                    }
                }

                if (Accepted.size() == 1U || Accepted.size() > 1U)
                {
                    const auto Best = std::max_element(
                        Accepted.begin(), Accepted.end(),
                        [](const auto *Left, const auto *Right)
                        { return Left->Spec.Priority < Right->Spec.Priority; });
                    const auto BestPriority = (*Best)->Spec.Priority;
                    const auto BestCount = static_cast<std::size_t>(std::count_if(
                        Accepted.begin(), Accepted.end(),
                        [BestPriority](const auto *Candidate)
                        { return Candidate->Spec.Priority == BestPriority; }));
                    if (BestCount != 1U)
                    {
                        co_return co_await Admission.Reject(
                            Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                    }
                    const auto *Winner = *Best;
                    Input.Inbound = Buffer.Replay(std::move(Input.Inbound));
                    if (!Input.Inbound)
                    {
                        co_return co_await Admission.Reject(
                            Preview::Fault::Failure{Preview::Fault::Code::IoError});
                    }
                    if (const auto Tracked = Admission.Track(Input.Inbound); !Tracked)
                    {
                        co_return co_await Admission.Reject(Tracked.error());
                    }
                    if (!Winner->Accept)
                    {
                        co_return co_await Admission.Reject(
                            Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                    }
                    auto AcceptedPlane = co_await Winner->Accept->Accept(
                        Preview::Contract::StreamAcceptInput{
                            std::move(Input.Inbound), std::move(Input.Metadata), std::move(Input.Bytes)});
                    if (!AcceptedPlane)
                    {
                        co_return co_await Admission.Reject(AcceptedPlane.error());
                    }
                    AcceptedPlane->Protocol = Winner->Spec.Protocol;
                    co_return co_await Admission.Admit(std::move(*AcceptedPlane));
                }
                if (!NeedMore && !Structural)
                {
                    co_return co_await Admission.Reject(
                        Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                }
                if (Buffer.Size() >= Preview::Recognition::ProbeBuffer::MaxSupportedBytes)
                {
                    co_return co_await Admission.Reject(
                        Preview::Fault::Failure{Preview::Fault::Code::ProtocolError});
                }
                const auto Fill = co_await Buffer.ReadSome(*Input.Inbound, ReadWindow);
                if (Fill.Added == 0U)
                {
                    co_return co_await Admission.Reject(
                        Preview::Fault::Failure{Preview::Fault::Code::IoError});
                }
            }
        }
    public:
        [[nodiscard]] auto Name() const -> std::string_view override { return "tls-inner"; }


        std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates_;
    };

    [[nodiscard]] inline auto MakeInnerProtocolDispatch(
        std::vector<std::shared_ptr<const CandidateInnerBinding>> Candidates)
        -> std::shared_ptr<Preview::Contract::StreamFactory>
    {
        return std::make_shared<InnerProtocolFactory>(std::move(Candidates));
    }

    /**
     * @class LayeredCandidateFactory
     * @brief 将 TLS carrier 候选和内层协议接入器组合为一个 Runtime 候选
     */
    class LayeredCandidateFactory
    {
    public:
        /**
         * @brief 构造分层候选
         * @param Options TLS carrier 识别和提交参数
         * @param Carrier TLS carrier 提交回调
         * @param Inner 内层协议候选；只消费其 Accept 回调和最终协议类型
         * @return 可交给 ProfileBuilder 的分层候选
         */
        [[nodiscard]] static auto Make(TlsCandidateOptions Options,
                                       CarrierAcceptFn Carrier,
                                       CandidateBinding Inner) -> CandidateBinding
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

        [[nodiscard]] static auto MakePrepared(
            TlsCandidateOptions Options,
            CarrierAcceptPreparedFn Carrier,
            CandidateBinding Inner) -> CandidateBinding
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
    };

} // namespace Preview::Composition::Recognition
