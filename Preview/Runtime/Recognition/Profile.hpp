/**
 * @file Profile.hpp
 * @brief Preview 识别 Profile 编译与配置校验
 * @details Profile 只保存已编译的候选、首字节索引和 SNI 路由索引。
 *          编译完成后通过 shared_ptr<const Profile> 发布，在线路径不再修改。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/Recognition/DecisionTable.hpp>
#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Runtime/Recognition/Protocol.hpp>
#include <Preview/Runtime/Recognition/Types.hpp>

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

        /// 兼容更明确的调用方命名
        Structural = Cleartext,
        OpaqueCrypto = Opaque,
        Authenticated = Opaque,
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

    /**
     * @struct PrepareResult
     * @brief 候选认证准备结果
     */
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
        bool Polluted{false};
    };

    /**
     * @struct CarrierMetadata
     * @brief TLS carrier 握手产生的可观测元数据
     */
    struct CarrierMetadata final
    {
        std::string Carrier;
        std::string Sni;
        std::string Alpn;
        std::string TlsVersion;
    };

    /**
     * @struct CarrierAcceptResult
     * @brief Facade carrier 的 owner-held 接入结果
     */
    struct CarrierAcceptResult final
    {
        Preview::Fault::Code Code{Preview::Fault::Code::Success};
        SharedTransmission Transport{};
        CarrierMetadata Metadata{};
        boost::system::error_code NativeError{};
    };

    /**
     * @struct CommitResult
     * @brief 候选一次性提交结果
     */
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
     * @enum ProfileError
     * @brief Profile 编译失败原因
     */
    enum class ProfileError : std::uint8_t
    {
        InvalidMode,
        ConfiguredCandidateCount,
        ConfiguredCandidateNotFound,
        ConfiguredCandidateNotAllowed,
        MixedTrialRequiresCandidate,
        DuplicateCandidateId,
        DuplicateCandidateName,
        EmptyCandidateName,
        CandidateIdOutOfRange,
        CandidateLimitExceeded,
        CandidateCapacityExceeded,
        MaxRoutesExceeded,
        CandidateNameTooLong,
        SchemeNameTooLong,
        MaxProbeBytesExceeded,
        MaxCryptoTrialsExceeded,
        InvalidMinimumBytes,
        MinimumBytesExceedsBudget,
        InvalidTimeout,
        MissingInspect,
        MissingPrepare,
        MissingCommit,
        EarlyResponseOpaqueConflict,
        DanglingRoute,
        DuplicateRoute,
        InvalidRoutePattern,
        MissingResolver,
        MissingAuthenticator,
        QuicCandidateRequiresGateway,
        MissingCarrierScheme,
        DeterministicCandidateNeedsSelector,
        DeterministicSelectorConflict,
        DeterministicRouteRequiresTlsCandidate,
        TlsRouteRequiresTlsCandidate,

        /// 便于调用方使用更接近规则的名称
        ConfiguredRequiresSingleCandidate = ConfiguredCandidateCount,
        MixedTrialRequiresAtLeastOne = MixedTrialRequiresCandidate,
        CandidateCountExceeded = CandidateLimitExceeded,
        CandidateIdCapacityExceeded = CandidateCapacityExceeded,
        BudgetProbeBytesExceeded = MaxProbeBytesExceeded,
        BudgetCryptoTrialsExceeded = MaxCryptoTrialsExceeded,
    };

    /**
     * @brief Profile 错误转为诊断字符串
     * @param Error 编译错误
     * @return 稳定的错误名
     */
    [[nodiscard]] inline auto ToStringView(ProfileError Error) noexcept -> std::string_view
    {
        switch (Error)
        {
        case ProfileError::InvalidMode: return "invalid_mode";
        case ProfileError::ConfiguredCandidateCount: return "configured_candidate_count";
        case ProfileError::ConfiguredCandidateNotFound: return "configured_candidate_not_found";
        case ProfileError::ConfiguredCandidateNotAllowed: return "configured_candidate_not_allowed";
        case ProfileError::MixedTrialRequiresCandidate: return "mixed_trial_requires_candidate";
        case ProfileError::DuplicateCandidateId: return "duplicate_candidate_id";
        case ProfileError::DuplicateCandidateName: return "duplicate_candidate_name";
        case ProfileError::EmptyCandidateName: return "empty_candidate_name";
        case ProfileError::CandidateIdOutOfRange: return "candidate_id_out_of_range";
        case ProfileError::CandidateLimitExceeded: return "candidate_limit_exceeded";
        case ProfileError::CandidateCapacityExceeded: return "candidate_capacity_exceeded";
        case ProfileError::MaxRoutesExceeded: return "max_routes_exceeded";
        case ProfileError::CandidateNameTooLong: return "candidate_name_too_long";
        case ProfileError::SchemeNameTooLong: return "scheme_name_too_long";
        case ProfileError::MaxProbeBytesExceeded: return "max_probe_bytes_exceeded";
        case ProfileError::MaxCryptoTrialsExceeded: return "max_crypto_trials_exceeded";
        case ProfileError::InvalidMinimumBytes: return "invalid_minimum_bytes";
        case ProfileError::MinimumBytesExceedsBudget: return "minimum_bytes_exceeds_budget";
        case ProfileError::InvalidTimeout: return "invalid_timeout";
        case ProfileError::MissingInspect: return "missing_inspect";
        case ProfileError::MissingPrepare: return "missing_prepare";
        case ProfileError::MissingCommit: return "missing_commit";
        case ProfileError::EarlyResponseOpaqueConflict: return "early_response_opaque_conflict";
        case ProfileError::DanglingRoute: return "dangling_route";
        case ProfileError::DuplicateRoute: return "duplicate_route";
        case ProfileError::InvalidRoutePattern: return "invalid_route_pattern";
        case ProfileError::MissingResolver: return "missing_resolver";
        case ProfileError::MissingAuthenticator: return "missing_authenticator";
        case ProfileError::QuicCandidateRequiresGateway: return "quic_candidate_requires_gateway";
        case ProfileError::MissingCarrierScheme: return "missing_carrier_scheme";
        case ProfileError::DeterministicCandidateNeedsSelector:
            return "deterministic_candidate_needs_selector";
        case ProfileError::DeterministicSelectorConflict:
            return "deterministic_selector_conflict";
        case ProfileError::DeterministicRouteRequiresTlsCandidate:
            return "deterministic_route_requires_tls_candidate";
        case ProfileError::TlsRouteRequiresTlsCandidate:
            return "tls_route_requires_tls_candidate";
        }
        return "unknown_profile_error";
    }

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
        ProtocolType Protocol{ProtocolType::Unknown};
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
     * @struct RouteBinding
     * @brief SNI 模式到候选 ID 的编译期绑定
     * @details Pattern 支持精确域名和单标签 wildcard（例如 *.example.com）。
     */
    struct RouteBinding
    {
        std::string Pattern;
        CandidateId Candidate{InvalidCandidate};

        /// 与已有路由调用方的 Domain 命名兼容；编译时 Pattern 优先
        std::string Domain;

        RouteBinding() = default;

        RouteBinding(std::string PatternValue, CandidateId CandidateValue)
            : Pattern(std::move(PatternValue)), Candidate(CandidateValue)
        {
        }
    };

    /**
     * @struct ProfileSpec
     * @brief Profile 编译输入
     */
    struct ProfileSpec
    {
        RecognitionMode Mode{RecognitionMode::Configured};
        CandidateId ConfiguredCandidate{InvalidCandidate};
        CandidateId DefaultCandidate{InvalidCandidate};
        RecognitionBudget Budget{};
        std::vector<CandidateSpec> Candidates;
        std::vector<RouteBinding> Routes;
    };

    class CandidateHandle;
    class Profile;
    using SharedProfile = std::shared_ptr<const Profile>;

    /**
     * @class Profile
     * @brief 已编译且不可变的识别 Profile
     */
    class Profile : public std::enable_shared_from_this<Profile>
    {
    public:
        struct WildcardRoute
        {
            std::string Suffix;
            CandidateId Candidate{InvalidCandidate};
        };

    private:
        struct RouteIndex
        {
            std::unordered_map<std::string, CandidateId> Exact;
            std::vector<WildcardRoute> Wildcards;
            CandidateId DefaultCandidate{InvalidCandidate};
        };

        struct RouteBuildContext
        {
            RecognitionMode Mode{RecognitionMode::Configured};
            const std::vector<RouteBinding> &Routes;
            const std::vector<CandidateSpec> &Candidates;
            const RecognitionBudget &Budget;
            CandidateId DefaultCandidate{InvalidCandidate};
            RouteIndex &Index;
        };

        struct ProfileData
        {
            RecognitionMode Mode{RecognitionMode::Configured};
            CandidateId ConfiguredCandidate{InvalidCandidate};
            RecognitionBudget Budget{};
            std::vector<CandidateSpec> Candidates;
            ::Preview::Recognition::DecisionTable Decision;
            RouteIndex Routes;
        };

    public:

        Profile(const Profile &) = delete;
        auto operator=(const Profile &) -> Profile & = delete;
        Profile(Profile &&) = delete;
        auto operator=(Profile &&) -> Profile & = delete;
        ~Profile() = default;

        /**
         * @brief 编译并验证 Profile
         * @param Spec 启动阶段配置；函数取得其所有权
         * @return 成功时返回不可变 Profile
         */
        [[nodiscard]] static auto Compile(ProfileSpec Spec) -> std::expected<SharedProfile, ProfileError>
        {
            if (const auto Error = ValidateMode(Spec.Mode); Error)
            {
                return std::unexpected(*Error);
            }
            if (const auto Error = ValidateBudget(Spec.Budget); Error)
            {
                return std::unexpected(*Error);
            }
            if (const auto Error = ValidateCandidateCount(Spec); Error)
            {
                return std::unexpected(*Error);
            }
            if (const auto Error = ValidateCandidates(Spec); Error)
            {
                return std::unexpected(*Error);
            }
            if (const auto Error = ValidateModeSpecificCandidates(Spec); Error)
            {
                return std::unexpected(*Error);
            }

            auto Ordered = std::move(Spec.Candidates);
            std::stable_sort(Ordered.begin(), Ordered.end(), [](const auto &Left, const auto &Right)
                             {
                                 if (Left.Tier != Right.Tier)
                                 {
                                     return Left.Tier < Right.Tier;
                                 }
                                 return Left.Priority < Right.Priority;
                             });

            ::Preview::Recognition::DecisionTable Decision;
            if (const auto Error = BuildDecisionTable(Ordered, Decision); Error)
            {
                return std::unexpected(*Error);
            }

            RouteIndex Routes;
            const auto RouteError = BuildRoutes(RouteBuildContext{
                Spec.Mode,
                Spec.Routes,
                Ordered,
                Spec.Budget,
                Spec.DefaultCandidate,
                Routes});
            if (RouteError)
            {
                return std::unexpected(*RouteError);
            }

            ProfileData Data{Spec.Mode, Spec.ConfiguredCandidate, Spec.Budget, std::move(Ordered),
                             std::move(Decision), std::move(Routes)};
            auto Published = std::shared_ptr<Profile>(new Profile(std::move(Data)));
            return SharedProfile(std::move(Published));
        }

        /// 识别模式
        [[nodiscard]] auto Mode() const noexcept -> RecognitionMode
        {
            return Mode_;
        }

        /// Configured 模式明确选中的候选编号
        [[nodiscard]] auto ConfiguredCandidate() const noexcept -> CandidateId
        {
            return ConfiguredCandidate_;
        }

        /// 总预算
        [[nodiscard]] auto Budget() const noexcept -> RecognitionBudget
        {
            return Budget_;
        }

        /// 候选数量
        [[nodiscard]] auto CandidateCount() const noexcept -> std::size_t
        {
            return Candidates_.size();
        }

        [[nodiscard]] auto HasTlsCandidate() const noexcept -> bool
        {
            return std::any_of(
                Candidates_.begin(), Candidates_.end(),
                [](const CandidateSpec &Candidate)
                {
                    return Candidate.Kind == CandidateKind::TlsCarrier ||
                           Candidate.Protocol == ProtocolType::Tls;
                });
        }

        /// 按稳定 tier/priority 顺序获取候选 ID
        [[nodiscard]] auto CandidateIdAt(std::size_t Index) const noexcept -> CandidateId
        {
            if (Index >= Candidates_.size())
            {
                return InvalidCandidate;
            }
            return Candidates_[Index].Id;
        }

        [[nodiscard]] auto CandidateName(CandidateId Id) const -> std::string
        {
            const auto *Candidate = FindCandidateInternal(Id);
            return Candidate ? Candidate->Name : std::string{};
        }

        [[nodiscard]] auto CandidateProtocol(CandidateId Id) const noexcept -> ProtocolType
        {
            const auto *Candidate = FindCandidateInternal(Id);
            return Candidate ? Candidate->Protocol : ProtocolType::Unknown;
        }

        /// 查询首字节候选；返回固定大小位图，不暴露 Profile 内部存储
        [[nodiscard]] auto LookupCandidates(std::uint8_t FirstByte) const noexcept -> CandidateBitmap
        {
            return Decision_.Lookup(FirstByte);
        }

        /// 查询 fallback 候选；返回固定大小位图
        [[nodiscard]] auto FallbackCandidates() const noexcept -> CandidateBitmap
        {
            return Decision_.Fallback();
        }

        /// 查询仅由显式 FirstBytes 产生的首字节候选，不包含 fallback
        [[nodiscard]] auto IndexedCandidates(std::uint8_t FirstByte) const noexcept -> CandidateBitmap
        {
            auto Indexed = Decision_.Lookup(FirstByte);
            const auto Fallback = Decision_.Fallback();
            Indexed.Words[0] &= ~Fallback.Words[0];
            Indexed.Words[1] &= ~Fallback.Words[1];
            return Indexed;
        }

        /// 决策表已发布
        [[nodiscard]] auto IsDecisionSealed() const noexcept -> bool
        {
            return Decision_.IsSealed();
        }

        /// 返回持有 Profile 所有权的候选句柄；句柄可安全跨协程保存
        [[nodiscard]] auto FindCandidate(CandidateId Id) const -> CandidateHandle;

        /**
         * @brief 查询 SNI 路由
         * @param Sni 客户端 SNI
         * @return 精确或最长单标签 wildcard 的候选 ID
         */
        [[nodiscard]] auto LookupRoute(std::string_view Sni) const -> std::optional<CandidateId>
        {
            const auto Normalized = Normalize(Sni);
            if (const auto It = ExactRoutes_.find(Normalized); It != ExactRoutes_.end())
            {
                return It->second;
            }

            for (const auto &Route : WildcardRoutes_)
            {
                if (!Normalized.ends_with(Route.Suffix) || Normalized.size() <= Route.Suffix.size())
                {
                    continue;
                }
                const auto Prefix = std::string_view(Normalized).substr(
                    0, Normalized.size() - Route.Suffix.size());
                if (!Prefix.empty() && Prefix.find('.') == std::string_view::npos)
                {
                    return Route.Candidate;
                }
            }
            if (DefaultCandidate_ != InvalidCandidate)
            {
                return DefaultCandidate_;
            }
            return std::nullopt;
        }

        /// 精确路由条目数
        [[nodiscard]] auto ExactRouteCount() const noexcept -> std::size_t
        {
            return ExactRoutes_.size();
        }

        /// wildcard 路由条目数
        [[nodiscard]] auto WildcardRouteCount() const noexcept -> std::size_t
        {
            return WildcardRoutes_.size();
        }

        /// 是否配置了至少一个 SNI 路由
        [[nodiscard]] auto HasRoutes() const noexcept -> bool
        {
            return !ExactRoutes_.empty() || !WildcardRoutes_.empty() || DefaultCandidate_ != InvalidCandidate;
        }

    private:
        friend class CandidateHandle;

        [[nodiscard]] auto FindCandidateInternal(CandidateId Id) const noexcept -> const CandidateSpec *
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

        explicit Profile(ProfileData Data)
            : Mode_(Data.Mode), ConfiguredCandidate_(Data.ConfiguredCandidate), Budget_(Data.Budget),
              Candidates_(std::move(Data.Candidates)),
              Decision_(std::move(Data.Decision)), ExactRoutes_(std::move(Data.Routes.Exact)),
              WildcardRoutes_(std::move(Data.Routes.Wildcards)),
              DefaultCandidate_(Data.Routes.DefaultCandidate)
        {
        }

        [[nodiscard]] static auto ValidateMode(RecognitionMode Mode) -> std::optional<ProfileError>
        {
            switch (Mode)
            {
            case RecognitionMode::Configured:
            case RecognitionMode::DeterministicRoute:
            case RecognitionMode::MixedTrial:
                return std::nullopt;
            }
            return ProfileError::InvalidMode;
        }

        [[nodiscard]] static auto ValidateBudget(const RecognitionBudget &Budget)
            -> std::optional<ProfileError>
        {
            if (Budget.MaxProbeBytes > ProbeBuffer::MaxSupportedBytes)
            {
                return ProfileError::MaxProbeBytesExceeded;
            }
            if (Budget.MaxCryptoTrials > 16)
            {
                return ProfileError::MaxCryptoTrialsExceeded;
            }
            if (Budget.MaxCandidates > CandidateBitmap::Capacity)
            {
                return ProfileError::CandidateCapacityExceeded;
            }
            if (Budget.MaxRoutes > 4096)
            {
                return ProfileError::MaxRoutesExceeded;
            }
            if (Budget.MaxCandidateNameBytes > 1024)
            {
                return ProfileError::CandidateNameTooLong;
            }
            if (Budget.MaxSchemeBytes > 256)
            {
                return ProfileError::SchemeNameTooLong;
            }
            if (Budget.Timeout.count() < 0)
            {
                return ProfileError::InvalidTimeout;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ValidateCandidateCount(const ProfileSpec &Spec)
            -> std::optional<ProfileError>
        {
            if (Spec.Mode == RecognitionMode::Configured && Spec.Candidates.size() != 1)
            {
                return ProfileError::ConfiguredCandidateCount;
            }
            if ((Spec.Mode == RecognitionMode::MixedTrial || Spec.Mode == RecognitionMode::DeterministicRoute) &&
                Spec.Candidates.empty())
            {
                return ProfileError::MixedTrialRequiresCandidate;
            }
            if (Spec.Candidates.size() > Spec.Budget.MaxCandidates)
            {
                return ProfileError::CandidateLimitExceeded;
            }
            if (Spec.Candidates.size() > CandidateBitmap::Capacity)
            {
                return ProfileError::CandidateCapacityExceeded;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ValidateCandidates(const ProfileSpec &Spec)
            -> std::optional<ProfileError>
        {
            std::array<bool, CandidateBitmap::Capacity> SeenIds{};
            std::unordered_set<std::string> SeenNames;
            for (const auto &Candidate : Spec.Candidates)
            {
                const auto Index = static_cast<std::size_t>(Candidate.Id);
                if (Index >= CandidateBitmap::Capacity)
                {
                    return ProfileError::CandidateIdOutOfRange;
                }
                if (SeenIds[Index])
                {
                    return ProfileError::DuplicateCandidateId;
                }
                SeenIds[Index] = true;
                if (Candidate.Name.size() > Spec.Budget.MaxCandidateNameBytes)
                {
                    return ProfileError::CandidateNameTooLong;
                }
                if (!SeenNames.emplace(Candidate.Name).second)
                {
                    return ProfileError::DuplicateCandidateName;
                }
                if (Candidate.Name.empty())
                {
                    return ProfileError::EmptyCandidateName;
                }
                if (Candidate.Kind == CandidateKind::TlsCarrier && Candidate.Scheme.empty())
                {
                    return ProfileError::MissingCarrierScheme;
                }
                if (Candidate.Scheme.size() > Spec.Budget.MaxSchemeBytes)
                {
                    return ProfileError::SchemeNameTooLong;
                }
                if (Candidate.MinimumBytes == 0)
                {
                    return ProfileError::InvalidMinimumBytes;
                }
                if (Candidate.MinimumBytes > Spec.Budget.MaxProbeBytes)
                {
                    return ProfileError::MinimumBytesExceedsBudget;
                }
                if (!Candidate.Inspect)
                {
                    return ProfileError::MissingInspect;
                }
                if (!Candidate.Commit)
                {
                    return ProfileError::MissingCommit;
                }
                if (RequiresPrepare(Candidate) && !Candidate.Prepare)
                {
                    return ProfileError::MissingPrepare;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ValidateModeSpecificCandidates(const ProfileSpec &Spec)
            -> std::optional<ProfileError>
        {
            for (const auto &Candidate : Spec.Candidates)
            {
                if (Candidate.Kind == CandidateKind::QuicCarrier ||
                    Candidate.Protocol == ProtocolType::Hysteria2 || Candidate.Protocol == ProtocolType::Tuic)
                {
                    return ProfileError::QuicCandidateRequiresGateway;
                }
            }
            if (Spec.DefaultCandidate != InvalidCandidate &&
                !ContainsCandidate(Spec.Candidates, Spec.DefaultCandidate))
            {
                return ProfileError::DanglingRoute;
            }
            if (Spec.Mode == RecognitionMode::Configured)
            {
                if (Spec.Candidates.front().Id != Spec.ConfiguredCandidate)
                {
                    return ProfileError::ConfiguredCandidateNotFound;
                }
                return std::nullopt;
            }

            if (Spec.Mode == RecognitionMode::DeterministicRoute)
            {
                if (Spec.ConfiguredCandidate != InvalidCandidate)
                {
                    return ProfileError::ConfiguredCandidateNotAllowed;
                }
                if (Spec.Candidates.size() > 1)
                {
                    for (const auto &Candidate : Spec.Candidates)
                    {
                        const bool HasFirstByteSelector = !Candidate.FirstBytes.empty();
                        const bool HasTlsRoute = std::any_of(
                            Spec.Routes.begin(), Spec.Routes.end(),
                            [&Candidate](const auto &Route) { return Route.Candidate == Candidate.Id; });
                        if (!HasFirstByteSelector && !HasTlsRoute)
                        {
                            return ProfileError::DeterministicCandidateNeedsSelector;
                        }
                        if (HasTlsRoute && Candidate.Kind != CandidateKind::TlsCarrier &&
                            Candidate.Protocol != ProtocolType::Tls)
                        {
                            return ProfileError::DeterministicCandidateNeedsSelector;
                        }
                    }
                }
                if (const auto Error = ValidateDeterministicSelectors(Spec); Error)
                {
                    return Error;
                }
                return std::nullopt;
            }

            bool HasEarlyResponse = false;
            bool HasOpaque = false;
            for (const auto &Candidate : Spec.Candidates)
            {
                HasEarlyResponse = HasEarlyResponse || Candidate.Kind == CandidateKind::EarlyResponse;
                HasOpaque = HasOpaque || IsOpaque(Candidate);
            }
            if (HasEarlyResponse && HasOpaque)
            {
                return ProfileError::EarlyResponseOpaqueConflict;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto ValidateDeterministicSelectors(const ProfileSpec &Spec)
            -> std::optional<ProfileError>
        {
            std::array<CandidateId, DecisionTable::FirstByteCount> PlainOwners;
            std::array<CandidateId, DecisionTable::FirstByteCount> TlsOwners;
            PlainOwners.fill(InvalidCandidate);
            TlsOwners.fill(InvalidCandidate);
            for (const auto &Candidate : Spec.Candidates)
            {
                const bool IsTls = Candidate.Kind == CandidateKind::TlsCarrier ||
                                   Candidate.Protocol == ProtocolType::Tls;
                for (const auto FirstByte : FirstBytesFor(Candidate))
                {
                    auto *Owner = &PlainOwners[FirstByte];
                    if (IsTls)
                    {
                        Owner = &TlsOwners[FirstByte];
                    }
                    if (!IsTls && *Owner != InvalidCandidate && *Owner != Candidate.Id)
                    {
                        return ProfileError::DeterministicSelectorConflict;
                    }
                    if (!IsTls && TlsOwners[FirstByte] != InvalidCandidate &&
                        TlsOwners[FirstByte] != Candidate.Id)
                    {
                        return ProfileError::DeterministicSelectorConflict;
                    }
                    if (IsTls && PlainOwners[FirstByte] != InvalidCandidate &&
                        PlainOwners[FirstByte] != Candidate.Id)
                    {
                        return ProfileError::DeterministicSelectorConflict;
                    }
                    *Owner = Candidate.Id;
                }
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto RequiresPrepare(const CandidateSpec &Candidate) noexcept -> bool
        {
            return Candidate.RequiresAuthentication || Candidate.Kind == CandidateKind::Opaque;
        }

        [[nodiscard]] static auto IsOpaque(const CandidateSpec &Candidate) noexcept -> bool
        {
            return Candidate.Kind == CandidateKind::Opaque || Candidate.RequiresAuthentication;
        }

        [[nodiscard]] static auto BuildDecisionTable(
            const std::vector<CandidateSpec> &Candidates,
            ::Preview::Recognition::DecisionTable &Decision) -> std::optional<ProfileError>
        {
            for (const auto &Candidate : Candidates)
            {
                if (!Decision.SetMinimumBytes(Candidate.Id, Candidate.MinimumBytes))
                {
                    return ProfileError::CandidateIdOutOfRange;
                }
                const auto FirstBytes = FirstBytesFor(Candidate);
                if (Candidate.Fallback || FirstBytes.empty())
                {
                    if (!Decision.AddFallback(Candidate.Id))
                    {
                        return ProfileError::CandidateIdOutOfRange;
                    }
                }
                for (const auto FirstByte : FirstBytes)
                {
                    if (!Decision.AddFirstByte(FirstByte, Candidate.Id))
                    {
                        return ProfileError::CandidateIdOutOfRange;
                    }
                }
            }
            if (!Decision.Seal())
            {
                return ProfileError::InvalidMode;
            }
            return std::nullopt;
        }

        [[nodiscard]] static auto FirstBytesFor(const CandidateSpec &Candidate)
            -> std::vector<std::uint8_t>
        {
            if (!Candidate.FirstBytes.empty())
            {
                return Candidate.FirstBytes;
            }
            // TLS carrier 没有可配置的应用层魔数，但 record content type
            // 是稳定的 0x16；将其作为隐式索引，避免 route-only TLS 候选
            // 在任意明文首字节上进入 fallback 试探。
            if (Candidate.Kind == CandidateKind::TlsCarrier || Candidate.Protocol == ProtocolType::Tls)
            {
                return {0x16};
            }
            return {};
        }

        [[nodiscard]] static auto IsTlsCandidate(const CandidateSpec &Candidate) noexcept -> bool
        {
            return Candidate.Kind == CandidateKind::TlsCarrier || Candidate.Protocol == ProtocolType::Tls;
        }

        [[nodiscard]] static auto BuildRoutes(RouteBuildContext Context)
            -> std::optional<ProfileError>
        {
            const bool HasTlsCandidate = std::any_of(
                Context.Candidates.begin(), Context.Candidates.end(),
                [](const auto &Candidate) { return IsTlsCandidate(Candidate); });
            const bool EnforceTlsTargets =
                Context.Mode == RecognitionMode::DeterministicRoute ||
                (HasTlsCandidate && Context.Mode == RecognitionMode::MixedTrial);
            if (Context.DefaultCandidate != InvalidCandidate &&
                !ContainsCandidate(Context.Candidates, Context.DefaultCandidate))
            {
                return ProfileError::DanglingRoute;
            }
            if (EnforceTlsTargets && Context.DefaultCandidate != InvalidCandidate)
            {
                const auto It = std::find_if(Context.Candidates.begin(), Context.Candidates.end(),
                                             [&Context](const auto &Candidate)
                                             { return Candidate.Id == Context.DefaultCandidate; });
                if (It != Context.Candidates.end() && !IsTlsCandidate(*It))
                {
                    if (Context.Mode == RecognitionMode::DeterministicRoute)
                    {
                        return ProfileError::DeterministicRouteRequiresTlsCandidate;
                    }
                    return ProfileError::TlsRouteRequiresTlsCandidate;
                }
            }
            std::unordered_set<std::string> Seen;
            if (Context.Routes.size() > Context.Budget.MaxRoutes)
            {
                return ProfileError::MaxRoutesExceeded;
            }
            for (const auto &Route : Context.Routes)
            {
                std::string_view RawPattern;
                if (Route.Pattern.empty())
                {
                    RawPattern = Route.Domain;
                }
                else
                {
                    RawPattern = Route.Pattern;
                }
                const auto Pattern = Normalize(RawPattern);
                const bool IsWildcard = Pattern.starts_with("*.");
                if (RawPattern.find("..") != std::string_view::npos || !IsValidRoutePattern(Pattern))
                {
                    return ProfileError::InvalidRoutePattern;
                }
                if (!ContainsCandidate(Context.Candidates, Route.Candidate))
                {
                    return ProfileError::DanglingRoute;
                }
                if (EnforceTlsTargets)
                {
                    const auto It = std::find_if(Context.Candidates.begin(), Context.Candidates.end(),
                                                 [&Route](const auto &Candidate)
                                                 { return Candidate.Id == Route.Candidate; });
                    if (It != Context.Candidates.end() && !IsTlsCandidate(*It))
                    {
                        if (Context.Mode == RecognitionMode::DeterministicRoute)
                        {
                            return ProfileError::DeterministicRouteRequiresTlsCandidate;
                        }
                        return ProfileError::TlsRouteRequiresTlsCandidate;
                    }
                }
                if (!Seen.emplace(Pattern).second)
                {
                    return ProfileError::DuplicateRoute;
                }
                if (IsWildcard)
                {
                    Context.Index.Wildcards.push_back(WildcardRoute{Pattern.substr(1), Route.Candidate});
                }
                else
                {
                    Context.Index.Exact.emplace(Pattern, Route.Candidate);
                }
            }
            std::stable_sort(Context.Index.Wildcards.begin(), Context.Index.Wildcards.end(),
                             [](const auto &Left, const auto &Right)
                             {
                                 return Left.Suffix.size() > Right.Suffix.size();
                             });
            Context.Index.DefaultCandidate = Context.DefaultCandidate;
            return std::nullopt;
        }

        [[nodiscard]] static auto IsValidHostLabel(std::string_view Label) noexcept -> bool
        {
            if (Label.empty() || Label.front() == '-' || Label.back() == '-')
            {
                return false;
            }
            for (const auto Character : Label)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                const bool IsAlpha = (Byte >= 'a' && Byte <= 'z') || (Byte >= 'A' && Byte <= 'Z');
                const bool IsDigit = Byte >= '0' && Byte <= '9';
                if (!IsAlpha && !IsDigit && Byte != '-')
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] static auto IsValidHostname(std::string_view Host) noexcept -> bool
        {
            if (Host.empty())
            {
                return false;
            }
            std::size_t Begin = 0;
            while (Begin < Host.size())
            {
                const auto Separator = Host.find('.', Begin);
                std::size_t End = Host.size();
                if (Separator != std::string_view::npos)
                {
                    End = Separator;
                }
                if (!IsValidHostLabel(Host.substr(Begin, End - Begin)))
                {
                    return false;
                }
                if (Separator == std::string_view::npos)
                {
                    return true;
                }
                Begin = Separator + 1;
            }
            return false;
        }

        [[nodiscard]] static auto IsValidRoutePattern(std::string_view Pattern) noexcept -> bool
        {
            if (Pattern.starts_with("*."))
            {
                const auto Suffix = Pattern.substr(2);
                return Suffix.find('*') == std::string_view::npos && IsValidHostname(Suffix);
            }
            return Pattern.find('*') == std::string_view::npos && IsValidHostname(Pattern);
        }

        [[nodiscard]] static auto ContainsCandidate(const std::vector<CandidateSpec> &Candidates,
                                                     CandidateId Id) noexcept -> bool
        {
            return std::any_of(Candidates.begin(), Candidates.end(),
                               [Id](const auto &Candidate) { return Candidate.Id == Id; });
        }

        [[nodiscard]] static auto Normalize(std::string_view Value) -> std::string
        {
            std::string Result;
            Result.reserve(Value.size());
            for (const auto Character : Value)
            {
                const auto Byte = static_cast<unsigned char>(Character);
                auto NormalizedByte = Byte;
                if (Byte >= 'A' && Byte <= 'Z')
                {
                    NormalizedByte = Byte + ('a' - 'A');
                }
                Result.push_back(static_cast<char>(NormalizedByte));
            }
            while (!Result.empty() && Result.back() == '.')
            {
                Result.pop_back();
            }
            return Result;
        }

        RecognitionMode Mode_;
        CandidateId ConfiguredCandidate_{InvalidCandidate};
        RecognitionBudget Budget_;
        std::vector<CandidateSpec> Candidates_;
        ::Preview::Recognition::DecisionTable Decision_;
        std::unordered_map<std::string, CandidateId> ExactRoutes_;
        std::vector<WildcardRoute> WildcardRoutes_;
        CandidateId DefaultCandidate_{InvalidCandidate};
    };

    /**
     * @class CandidateHandle
     * @brief 持有 Profile 所有权的候选访问句柄
     * @details 句柄只保存 SharedProfile 和 CandidateId。每次访问都重新按 ID 查找，
     *          不把 CandidateSpec 的引用或指针暴露给跨协程调用方。
     */
    class CandidateHandle
    {
    public:
        CandidateHandle() = default;

        /// 句柄是否仍绑定到有效候选
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Resolve() != nullptr;
        }

        /// 候选 ID
        [[nodiscard]] auto Id() const noexcept -> CandidateId
        {
            return Id_;
        }

        /// 候选名称（按值返回）
        [[nodiscard]] auto Name() const -> std::string
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return {};
            }
            return Candidate->Name;
        }

        /// 候选外层方案名；未指定时为空
        [[nodiscard]] auto Scheme() const -> std::string
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return {};
            }
            return Candidate->Scheme;
        }

        /// 候选协议类型
        [[nodiscard]] auto Protocol() const noexcept -> ProtocolType
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return ProtocolType::Unknown;
            }
            return Candidate->Protocol;
        }

        /// 候选类别
        [[nodiscard]] auto Kind() const noexcept -> CandidateKind
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return CandidateKind::Cleartext;
            }
            return Candidate->Kind;
        }

        /// 候选优先级
        [[nodiscard]] auto Priority() const noexcept -> std::uint16_t
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return 0;
            }
            return Candidate->Priority;
        }

        /// 候选层级
        [[nodiscard]] auto Tier() const noexcept -> std::uint8_t
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return 0;
            }
            return Candidate->Tier;
        }

        /// 候选最小预读边界
        [[nodiscard]] auto MinimumBytes() const noexcept -> std::size_t
        {
            const auto *Candidate = Resolve();
            if (!Candidate)
            {
                return 0;
            }
            return Candidate->MinimumBytes;
        }

        /// 执行纯结构检查
        [[nodiscard]] auto Inspect(const ProbeSnapshot &Snapshot) const -> MatchState
        {
            const auto *Candidate = Resolve();
            if (!Candidate || !Candidate->Inspect)
            {
                return MatchState::Rejected;
            }
            return Candidate->Inspect(Snapshot);
        }

        /// 候选是否提供认证准备回调
        [[nodiscard]] auto HasPrepare() const noexcept -> bool
        {
            const auto *Candidate = Resolve();
            return Candidate && static_cast<bool>(Candidate->Prepare);
        }

        /// 候选是否提供提交回调
        [[nodiscard]] auto HasCommit() const noexcept -> bool
        {
            const auto *Candidate = Resolve();
            return Candidate && static_cast<bool>(Candidate->Commit);
        }

        /**
         * @brief 执行认证准备
         * @param Context 按值传递的候选上下文
         * @return 认证准备结果
         */
        [[nodiscard]] auto Prepare(PrepareContext Context) const -> Net::awaitable<PrepareResult>
        {
            return PrepareOwned(Owner_, Id_, std::move(Context));
        }

        /**
         * @brief 执行一次性提交
         * @param Context 按值传递的提交上下文
         * @return 提交结果
         */
        [[nodiscard]] auto Commit(CommitContext Context) const -> Net::awaitable<CommitResult>
        {
            return CommitOwned(Owner_, Id_, std::move(Context));
        }

    private:
        friend class Profile;

        CandidateHandle(SharedProfile Owner, CandidateId Id) : Owner_(std::move(Owner)), Id_(Id)
        {
        }

        [[nodiscard]] static auto PrepareOwned(SharedProfile Owner, CandidateId Id,
                                                PrepareContext Context)
            -> Net::awaitable<PrepareResult>
        {
            const CandidateSpec *Candidate = nullptr;
            if (Owner)
            {
                Candidate = Owner->FindCandidateInternal(Id);
            }
            if (!Candidate || !Candidate->Prepare)
            {
                PrepareResult Result;
                Result.Candidate = Id;
                co_return Result;
            }
            Context.Candidate = Id;
            co_return co_await Candidate->Prepare(std::move(Context));
        }

        [[nodiscard]] static auto CommitOwned(SharedProfile Owner, CandidateId Id,
                                               CommitContext Context)
            -> Net::awaitable<CommitResult>
        {
            const CandidateSpec *Candidate = nullptr;
            if (Owner)
            {
                Candidate = Owner->FindCandidateInternal(Id);
            }
            if (!Candidate || !Candidate->Commit)
            {
                CommitResult Result;
                Result.Candidate = Id;
                co_return Result;
            }
            Context.Candidate = Id;
            co_return co_await Candidate->Commit(std::move(Context));
        }

        [[nodiscard]] auto Resolve() const noexcept -> const CandidateSpec *
        {
            if (!Owner_)
            {
                return nullptr;
            }
            return Owner_->FindCandidateInternal(Id_);
        }

        SharedProfile Owner_;
        CandidateId Id_{InvalidCandidate};
    };

    inline auto Profile::FindCandidate(CandidateId Id) const -> CandidateHandle
    {
        // CandidateHandle may cross recognition awaits; retain the immutable
        // profile owner instead of relying on a transient weak lock.
        return CandidateHandle(shared_from_this(), Id);
    }

} // namespace Preview::Recognition
