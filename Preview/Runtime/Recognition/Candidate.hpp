/**
 * @file Candidate.hpp
 * @brief Preview 识别候选的数据模型与回调上下文
 * @details 候选只拥有识别所需的值和回调，不依赖 Profile 的编译编排。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Runtime/Recognition/Protocol.hpp>
#include <Preview/Runtime/Recognition/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Recognition
{

    namespace Net = boost::asio;

    /// 候选的 wire/认证特征类别
    enum class CandidateKind : std::uint8_t
    {
        Cleartext,
        Opaque,
        EarlyResponse,
        TlsCarrier,
        QuicCarrier,

    };

    /**
     * @struct PrepareContext
     * @brief 候选认证准备输入
     * @details Snapshot、预算和候选 ID 均按值携带，允许回调跨 co_await 保持有效。
     */
    struct PrepareContext
    {
        CandidateId Candidate{InvalidCandidate};
        ProbeSnapshot Snapshot{};
        RecognitionBudget Budget{};
    };

    /** @struct PrepareResult @brief 候选认证准备结果。 */
    struct PrepareResult
    {
        CandidateId Candidate{InvalidCandidate};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        std::error_code Error{};
        bool Polluted{false};
        bool NeedMore{false};
        std::shared_ptr<const void> PreparedState{};
    };

    /**
     * @struct CommitContext
     * @brief 候选一次性提交输入
     * @details Inbound 由 shared_ptr 持有，提交回调不得借用可增长缓冲区的裸视图。
     */
    struct CommitContext
    {
        CandidateId Candidate{InvalidCandidate};
        std::shared_ptr<const void> PreparedState{};
        SharedTransmission Inbound{};
        std::shared_ptr<Preview::Memory::BytePool> Bytes{};
        bool Polluted{false};
        Preview::Diagnose::ContextState Trace{}; ///< 当前 inbound generation 的固定诊断上下文。
    };

    /**
     * @struct CarrierAcceptInput
     * @brief 载体接入输入及连接级字节池
     * @details Inbound 与 Bytes 必须来自同一 worker/session 资源链，不得在接入回调内新建池。
     */
    struct CarrierAcceptInput final
    {
        SharedTransmission Inbound{};
        std::shared_ptr<Preview::Memory::BytePool> Bytes{};
        Preview::Diagnose::ContextState Trace{}; ///< 载体 accept 协程持有的 generation 上下文。
    };

    /**
     * @struct CarrierAcceptPreparedInput
     * @brief 带认证准备状态的载体接入输入
     */
    struct CarrierAcceptPreparedInput final
    {
        SharedTransmission Inbound{};
        std::shared_ptr<const void> PreparedState{};
        std::shared_ptr<Preview::Memory::BytePool> Bytes{};
        Preview::Diagnose::ContextState Trace{}; ///< 载体 accept 协程持有的 generation 上下文。
    };

    /**
     * @struct CarrierMetadata
     * @brief TLS carrier 握手产生的可观测元数据。
     * @details ECH 接受位只来自已完成的 Native TLS 握手；接受后 SNI 为 inner 值。
     */
    struct CarrierMetadata final
    {
        std::string Carrier;
        std::string Sni;
        std::string Alpn;
        std::string TlsVersion;
        /** @brief BoringSSL 实际接受并解密 ECH inner ClientHello。 */
        bool EchAccepted{false};
        /** @brief 协商快照来自已完成的 Native SSL_CTX 服务端握手。 */
        bool NativeTlsEstablished{false};
    };

    /** @struct CarrierAcceptResult @brief Facade carrier 的 owner-held 接入结果。 */
    struct CarrierAcceptResult final
    {
        Preview::Fault::Code Code{Preview::Fault::Code::Success};
        SharedTransmission Transport{};
        CarrierMetadata Metadata{};
        boost::system::error_code NativeError{};
    };

    /** @struct CommitResult @brief 候选一次性提交结果。 */
    struct CommitResult
    {
        CandidateId Candidate{InvalidCandidate};
        RecognitionStatus Status{RecognitionStatus::NoMatch};
        std::error_code Error{};
        bool Polluted{false};
        SharedTransmission Transport{};
        Preview::Fault::Code FaultCode{Preview::Fault::Code::Success};
        boost::system::error_code NativeError{};
        CarrierMetadata Metadata{};
    };

    /// 纯结构检查回调；不得执行 I/O 或修改连接状态
    using InspectFn = std::function<MatchState(const ProbeSnapshot &)>;
    /// 认证准备回调；仅在需要认证的候选上必须提供
    using PrepareFn = std::function<Net::awaitable<PrepareResult>(PrepareContext)>;
    /// 一次性提交回调；Profile 只校验其完整性，提交时机由识别协调器负责
    using CommitFn = std::function<Net::awaitable<CommitResult>(CommitContext)>;

    /**
     * @struct CandidateSpec
     * @brief 启动阶段的候选声明
     * @details 字段只包含 Runtime 可理解的整数、边界和回调，不保存 Settings、handler
     *          或可增长缓冲区的裸引用。
     */
    struct CandidateSpec
    {
        CandidateId Id{InvalidCandidate};
        std::string Name;
        std::string Scheme;
        Preview::Contract::ProtocolType Protocol{Preview::Contract::ProtocolType::Unknown};
        CandidateKind Kind{CandidateKind::Cleartext};
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
        std::vector<std::uint8_t> FirstBytes;
        bool Fallback{false};
        bool RequiresAuthentication{false};
        std::size_t MinimumBytes{1};
        InspectFn Inspect;
        PrepareFn Prepare;
        CommitFn Commit;
    };

    /**
     * @class CandidateStore
     * @brief 已排序候选的不可变 owner
     * @details Profile 和 CandidateHandle 共享该 owner，句柄跨协程时不借用 Profile 内部地址。
     */
    class CandidateStore final
    {
    public:
        explicit CandidateStore(std::vector<CandidateSpec> Candidates)
            : Candidates_(std::move(Candidates))
        {
        }

        [[nodiscard]] auto Values() const noexcept -> const std::vector<CandidateSpec> &
        {
            return Candidates_;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Candidates_.size();
        }

        [[nodiscard]] auto Find(CandidateId Id) const noexcept -> const CandidateSpec *
        {
            for (const auto &Candidate : Candidates_)
            {
                if (Candidate.Id == Id)
                {
                    return &Candidate;
                }
            }
            return nullptr;
        }

    private:
        std::vector<CandidateSpec> Candidates_;
    };

    using SharedCandidateStore = std::shared_ptr<const CandidateStore>;

} // namespace Preview::Recognition
