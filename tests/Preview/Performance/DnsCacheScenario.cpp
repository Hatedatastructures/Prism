/**
 * @file DnsCacheScenario.cpp
 * @brief 生成可复现的 DNS cache trace，并校验候选实现的外部合同。
 */

#include "DnsCacheScenario.hpp"

#include "DnsCacheVariants.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

namespace Preview::Network::Dns::Compare
{
    auto AddressForVersion(const Scenario &Workload, std::uint32_t Version) -> boost::asio::ip::address;
    namespace Dns = Preview::Network::Dns;
    namespace Net = boost::asio;

    namespace
    {
        class SplitMix64
        {
        public:
            explicit SplitMix64(const std::uint64_t Seed)
                : State_(Seed)
            {
            }

            auto Next() -> std::uint64_t
            {
                auto Value = (State_ += 0x9E3779B97F4A7C15ull);
                Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ull;
                Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBull;
                return Value ^ (Value >> 31);
            }

        private:
            std::uint64_t State_;
        };

        auto MakeCacheOptions(const std::size_t Capacity, const Dns::StalePolicy Policy)
            -> Dns::CacheOptions
        {
            Dns::CacheOptions Result;
            Result.MaxEntries = Capacity;
            Result.TtlMin = std::chrono::seconds{0};
            Result.TtlMax = std::chrono::seconds{86400};
            Result.NegativeTtl = std::chrono::seconds{86400};
            Result.Policy = Policy;
            return Result;
        }

        auto SelectKey(const std::size_t Capacity, const Distribution AccessDistribution,
                       SplitMix64 &Random) -> std::size_t
        {
            if (AccessDistribution == Distribution::Uniform)
            {
                return static_cast<std::size_t>(Random.Next() % Capacity);
            }
            const auto HotCount = std::max(std::size_t{1}, Capacity / 16);
            if ((Random.Next() % 100) < 80)
            {
                return static_cast<std::size_t>(Random.Next() % HotCount);
            }
            return HotCount + static_cast<std::size_t>(Random.Next() % (Capacity - HotCount));
        }

        void SetRecord(Dns::PutInput &Input, const std::string &Domain,
                       const std::chrono::seconds Ttl)
        {
            Input.Domain = Domain;
            Input.QType = 1;
            Input.Ttl = Ttl;
            Input.Failed = false;
        }

        template <typename CacheType>
        void RequirePositive(CacheType &Cache, const std::string &Domain, const Dns::IpList &Expected)
        {
            const auto Result = Cache.Get(Domain, 1);
            if (!Result.has_value() || !(*Result == Expected))
            {
                throw std::runtime_error("positive cache lookup differs");
            }
        }

        template <typename CacheType>
        void RequireNegative(CacheType &Cache, const std::string &Domain)
        {
            const auto Result = Cache.Get(Domain, 1);
            if (!Result.has_value() || !Result->empty())
            {
                throw std::runtime_error("negative cache lookup differs");
            }
        }

        template <typename CacheType>
        void RequireMiss(CacheType &Cache, const std::string &Domain)
        {
            if (Cache.Get(Domain, 1).has_value())
            {
                throw std::runtime_error("cache miss differs");
            }
        }

        template <typename CacheType>
        void ValidateFastFor()
        {
            auto Positive = Dns::IpList{};
            Positive.push_back(Net::ip::make_address("192.0.2.10"));
            auto Updated = Dns::IpList{};
            Updated.push_back(Net::ip::make_address("192.0.2.20"));

            auto FloorOptions = MakeCacheOptions(4, Dns::StalePolicy::Discard);
            FloorOptions.TtlMin = std::chrono::seconds{60};
            CacheType Floor{FloorOptions};
            Dns::PutInput FloorInput;
            SetRecord(FloorInput, "floor.cache.invalid", std::chrono::seconds{0});
            FloorInput.Ips = Positive;
            Floor.Put(FloorInput);
            RequirePositive(Floor, "floor.cache.invalid", Positive);

            auto StaleOptions = MakeCacheOptions(4, Dns::StalePolicy::Serve);
            CacheType Stale{StaleOptions};
            Dns::PutInput StaleInput;
            SetRecord(StaleInput, "stale.cache.invalid", std::chrono::seconds{0});
            StaleInput.Ips = Positive;
            Stale.Put(StaleInput);
            RequirePositive(Stale, "stale.cache.invalid", Positive);
            if (Stale.Size() != 1)
            {
                throw std::runtime_error("serve-stale lookup removed an expired entry");
            }

            CacheType Cache{MakeCacheOptions(3, Dns::StalePolicy::Discard)};
            Dns::PutInput Input;
            SetRecord(Input, "flip.cache.invalid", std::chrono::seconds{60});
            Input.Ips = Positive;
            Cache.Put(Input);
            Cache.PutNegative("flip.cache.invalid", 1);
            RequireNegative(Cache, "flip.cache.invalid");
            SetRecord(Input, "flip.cache.invalid", std::chrono::seconds{60});
            Input.Ips = Updated;
            Cache.Put(Input);
            RequirePositive(Cache, "flip.cache.invalid", Updated);
            if (Cache.Size() != 1)
            {
                throw std::runtime_error("overwrite changed live entry count");
            }

            auto ZeroNegativeOptions = MakeCacheOptions(2, Dns::StalePolicy::Discard);
            ZeroNegativeOptions.NegativeTtl = std::chrono::seconds{0};
            CacheType ZeroNegative{ZeroNegativeOptions};
            ZeroNegative.PutNegative("negative-expired.cache.invalid", 1);
            RequireMiss(ZeroNegative, "negative-expired.cache.invalid");

            CacheType Expired{MakeCacheOptions(2, Dns::StalePolicy::Discard)};
            SetRecord(Input, "expired.cache.invalid", std::chrono::seconds{0});
            Input.Ips = Positive;
            Expired.Put(Input);
            RequireMiss(Expired, "expired.cache.invalid");
            if (Expired.Size() != 0)
            {
                throw std::runtime_error("discarding an expired key kept a live entry");
            }

            CacheType Eviction{MakeCacheOptions(3, Dns::StalePolicy::Discard)};
            SetRecord(Input, "a.cache.invalid", std::chrono::seconds{60});
            Input.Ips = Positive;
            Eviction.Put(Input);
            Eviction.PutNegative("b.cache.invalid", 1);
            SetRecord(Input, "c.cache.invalid", std::chrono::seconds{60});
            Input.Ips = Updated;
            Eviction.Put(Input);
            RequirePositive(Eviction, "a.cache.invalid", Positive);
            SetRecord(Input, "b.cache.invalid", std::chrono::seconds{60});
            Input.Ips = Positive;
            Eviction.Put(Input);
            SetRecord(Input, "d.cache.invalid", std::chrono::seconds{60});
            Input.Ips = Updated;
            Eviction.Put(Input);
            if (Eviction.Size() != 3)
            {
                throw std::runtime_error("cache capacity was exceeded or underfilled");
            }

            if constexpr (std::is_same_v<CacheType, ClockCache>)
            {
                RequireMiss(Eviction, "a.cache.invalid");
                RequirePositive(Eviction, "b.cache.invalid", Positive);
                RequirePositive(Eviction, "c.cache.invalid", Updated);
            }
            else
            {
                RequirePositive(Eviction, "a.cache.invalid", Positive);
                RequirePositive(Eviction, "b.cache.invalid", Positive);
                RequireMiss(Eviction, "c.cache.invalid");
            }
            RequirePositive(Eviction, "d.cache.invalid", Updated);
        }

        template <typename CacheType>
        void PrepareExpiryCheck(CacheType &Cache)
        {
            Dns::PutInput Positive;
            SetRecord(Positive, "ttl-cap.cache.invalid", std::chrono::seconds{60});
            Positive.Ips.push_back(Net::ip::make_address("192.0.2.30"));
            Cache.Put(Positive);
            Cache.PutNegative("negative-ttl.cache.invalid", 1);
            RequirePositive(Cache, "ttl-cap.cache.invalid", Positive.Ips);
            RequireNegative(Cache, "negative-ttl.cache.invalid");
        }

        template <typename CacheType>
        void RequireExpired(CacheType &Cache)
        {
            if (Cache.EvictExpired() != 2)
            {
                throw std::runtime_error("expiry sweep count differs");
            }
            RequireMiss(Cache, "ttl-cap.cache.invalid");
            RequireMiss(Cache, "negative-ttl.cache.invalid");
            if (Cache.Size() != 0)
            {
                throw std::runtime_error("expired entries remain in cache size");
            }
        }

        void ValidateExpirySemantics()
        {
            auto Options = MakeCacheOptions(4, Dns::StalePolicy::Discard);
            Options.TtlMax = std::chrono::seconds{1};
            Options.NegativeTtl = std::chrono::seconds{1};
            CurrentCache Current{Options};
            IntrusiveCache Intrusive{Options};
            ClockCache Clocked{Options};
            PrepareExpiryCheck(Current);
            PrepareExpiryCheck(Intrusive);
            PrepareExpiryCheck(Clocked);
            std::this_thread::sleep_for(std::chrono::milliseconds{1100});
            RequireExpired(Current);
            RequireExpired(Intrusive);
            RequireExpired(Clocked);
        }

        struct LogicalState
        {
            bool Present{false};
            bool Negative{false};
            bool Expired{false};
            std::uint32_t Version{0};
        };

        struct MixedTraceState
        {
            Scenario &Workload;
            SplitMix64 Random;
            std::vector<LogicalState> States;
            std::size_t DynamicBegin;
            std::size_t DynamicCount;
            std::size_t InsertCursor{0};
            std::size_t LastWriteKey{0};
            bool HasWrite{false};
            std::uint32_t Version{1};
        };

        void HashWord(Scenario &Workload, const std::uint64_t Value)
        {
            Workload.TraceHash ^= Value;
            Workload.TraceHash *= 1099511628211ull;
        }

        void HashMixedOperation(Scenario &Workload, const Operation &Value)
        {
            HashWord(Workload, static_cast<std::uint64_t>(Value.Kind));
            HashWord(Workload, Value.KeyIndex);
            HashWord(Workload, Value.Negative ? 1ull : 0ull);
            HashWord(Workload, Value.ExpectedPresent ? 1ull : 0ull);
            HashWord(Workload, Value.ExpectedNegative ? 1ull : 0ull);
            HashWord(Workload, Value.RequireHit ? 1ull : 0ull);
            HashWord(Workload, Value.RequireMiss ? 1ull : 0ull);
            HashWord(Workload, Value.ValueVersion);
            HashWord(Workload, Value.ExpectedVersion);
            HashWord(Workload, Value.TtlSeconds);
        }

        void AppendMixedOperation(Scenario &Workload, const Operation &Value)
        {
            Workload.Trace.push_back(Value);
            switch (Value.Kind)
            {
            case OperationKind::Get:
                ++Workload.Mix.Gets;
                if (Value.RequireHit)
                {
                    ++Workload.Mix.RequiredHitProbes;
                }
                if (Value.RequireMiss)
                {
                    ++Workload.Mix.RequiredMissProbes;
                }
                if (Value.KeyIndex >= Workload.Settings.Capacity * 2)
                {
                    ++Workload.Mix.DynamicGets;
                }
                break;
            case OperationKind::Insert:
                ++Workload.Mix.Inserts;
                if (Value.Negative)
                {
                    ++Workload.Mix.NegativeInserts;
                }
                break;
            case OperationKind::Overwrite:
                ++Workload.Mix.Overwrites;
                if (Value.Negative)
                {
                    ++Workload.Mix.NegativeInserts;
                }
                break;
            case OperationKind::Expire:
                ++Workload.Mix.Expirations;
                break;
            case OperationKind::EvictExpired:
                ++Workload.Mix.EvictExpired;
                break;
            }
            HashMixedOperation(Workload, Value);
        }

        auto MakeProbe(const Operation &Write, const bool RequireHit) -> Operation
        {
            Operation Probe;
            Probe.KeyIndex = Write.KeyIndex;
            Probe.ExpectedHit = RequireHit;
            Probe.RequireHit = RequireHit;
            Probe.RequireMiss = !RequireHit;
            if (RequireHit)
            {
                Probe.ExpectedPresent = true;
                Probe.ExpectedNegative = Write.Negative;
                Probe.ExpectedVersion = Write.ValueVersion;
            }
            return Probe;
        }

        void SeedCache(auto &Cache, const Scenario &Workload)
        {
            for (std::size_t Index = 0; Index < Workload.Settings.Capacity; ++Index)
            {
                const auto &Key = Workload.Keys[Index];
                if (Key.Negative)
                {
                    Cache.PutNegative(Key.Domain, 1);
                    continue;
                }
                Dns::PutInput Input;
                Input.Domain = Key.Domain;
                Input.QType = 1;
                Input.Ttl = std::chrono::seconds{86400};
                Input.Ips.push_back(Workload.ExpectedAddress);
                Cache.Put(Input);
            }
        }

        auto MakeOperationInput(const Scenario &Workload, const Operation &Value)
            -> Dns::PutInput
        {
            Dns::PutInput Input;
            Input.Domain = Workload.Keys[Value.KeyIndex].Domain;
            Input.QType = 1;
            Input.Ttl = std::chrono::seconds{Value.TtlSeconds};
            Input.Failed = Value.Negative;
            if (!Value.Negative)
            {
                Input.Ips.push_back(Workload.Settings.Workload == WorkloadKind::Mixed
                                        ? (Value.ValueVersion % 2 == 0
                                               ? Workload.ExpectedAddress
                                               : Workload.AlternateAddress)
                                        : Workload.ExpectedAddress);
            }
            return Input;
        }

        struct ReplayOutcome
        {
            CacheResult Value;
            std::size_t Size{0};
            std::size_t ExplicitEvictions{0};
        };

        template <typename CacheType>
        auto ReplayOperation(CacheType &Cache, const Scenario &Workload,
                             const Operation &Value) -> ReplayOutcome
        {
            ReplayOutcome Outcome;
            switch (Value.Kind)
            {
            case OperationKind::Get:
                Outcome.Value = Cache.Get(Workload.Keys[Value.KeyIndex].Domain, 1);
                break;
            case OperationKind::Insert:
            case OperationKind::Overwrite:
                if (Value.Negative)
                {
                    Cache.PutNegative(Workload.Keys[Value.KeyIndex].Domain, 1);
                }
                else
                {
                    Cache.Put(MakeOperationInput(Workload, Value));
                }
                break;
            case OperationKind::Expire:
                Cache.Put(MakeOperationInput(Workload, Value));
                break;
            case OperationKind::EvictExpired:
                Outcome.ExplicitEvictions = Cache.EvictExpired();
                break;
            }
            Outcome.Size = Cache.Size();
            return Outcome;
        }

        void ValidateReplayResult(const Scenario &Workload, const Operation &OperationValue,
                                  const ReplayOutcome &Outcome)
        {
            if (Outcome.Size > Workload.Settings.Capacity)
            {
                throw std::runtime_error("mixed trace exceeded cache capacity");
            }
            if (OperationValue.Kind != OperationKind::Get)
            {
                return;
            }
            if (OperationValue.RequireHit && !Outcome.Value.has_value())
            {
                throw std::runtime_error("mandatory mixed hit probe missed");
            }
            if (OperationValue.RequireMiss && Outcome.Value.has_value())
            {
                throw std::runtime_error("mandatory mixed miss probe hit");
            }
            if (!Outcome.Value.has_value())
            {
                return;
            }
            if (!OperationValue.ExpectedPresent)
            {
                throw std::runtime_error("mixed trace returned an unexpected value");
            }
            if (OperationValue.ExpectedNegative)
            {
                if (!Outcome.Value->empty())
                {
                    throw std::runtime_error("negative cache value was not empty");
                }
                return;
            }
            if (Outcome.Value->size() != 1 ||
                (*Outcome.Value)[0] != AddressForVersion(Workload, OperationValue.ExpectedVersion))
            {
                throw std::runtime_error("mixed trace returned a stale value");
            }
        }

        void CompareReplayOutcomes(const Operation &OperationValue,
                                   const ReplayOutcome &Current,
                                   const ReplayOutcome &Intrusive)
        {
            if (OperationValue.Kind == OperationKind::Get && Current.Value != Intrusive.Value)
            {
                throw std::runtime_error("A/B mixed result diverged");
            }
            if (Current.Size != Intrusive.Size)
            {
                throw std::runtime_error("A/B mixed cache size diverged");
            }
            if (Current.ExplicitEvictions != Intrusive.ExplicitEvictions)
            {
                throw std::runtime_error("A/B explicit expiry eviction diverged");
            }
        }
    } // namespace

    auto AddressForVersion(const Scenario &Workload, const std::uint32_t Version)
        -> boost::asio::ip::address
    {
        return Version % 2 == 0 ? Workload.ExpectedAddress : Workload.AlternateAddress;
    }

    auto InitializeScenario(Scenario &Workload) -> void
    {
        const auto Capacity = Workload.Settings.Capacity;
        Workload.ExpectedAddress = Net::ip::make_address("192.0.2.1");
        Workload.AlternateAddress = Net::ip::make_address("192.0.2.2");
        Workload.Keys.clear();
        Workload.Trace.clear();
        Workload.Mix = {};
        Workload.TraceHash = 14695981039346656037ull;
        Workload.Keys.reserve(Capacity * 2);
        for (std::size_t Index = 0; Index < Capacity * 2; ++Index)
        {
            CacheKey Key;
            Key.Domain = "h" + std::to_string(Index) + ".cache-compare.invalid";
            Key.Negative = (Index % 8) == 0;
            Workload.Keys.push_back(std::move(Key));
        }
    }

    auto GenerateGetOnlyTrace(Scenario &Workload) -> void
    {
        const auto Capacity = Workload.Settings.Capacity;
        Workload.Trace.reserve(Workload.Settings.Operations);
        SplitMix64 Random{Workload.Settings.Seed};
        for (std::size_t Index = 0; Index < Workload.Settings.Operations; ++Index)
        {
            const bool ExpectedHit = (Index % 100) < Workload.Settings.HitPercent;
            const auto Selected = SelectKey(Capacity, Workload.Settings.AccessDistribution, Random);
            const auto KeyIndex = ExpectedHit ? Selected : Capacity + Selected;
            Workload.Trace.push_back({static_cast<std::uint32_t>(KeyIndex), ExpectedHit});
            HashWord(Workload, static_cast<std::uint64_t>(KeyIndex));
            HashWord(Workload, ExpectedHit ? 1ull : 0ull);
            ++Workload.Mix.Gets;
        }
    }

    auto AppendDynamicKeys(Scenario &Workload) -> void
    {
        const auto Capacity = Workload.Settings.Capacity;
        const auto DynamicCount = Capacity * 8 + 64;
        Workload.Keys.reserve(Capacity * 2 + DynamicCount);
        for (std::size_t Index = 0; Index < DynamicCount; ++Index)
        {
            CacheKey Key;
            Key.Domain = "m" + std::to_string(Index) + ".cache-compare.invalid";
            Workload.Keys.push_back(std::move(Key));
        }
    }

    [[nodiscard]] auto SelectMixedKey(MixedTraceState &State) -> std::size_t
    {
        const auto &Workload = State.Workload;
        const auto Capacity = Workload.Settings.Capacity;
        if (State.HasWrite && (State.Random.Next() % 4) == 0)
        {
            return State.LastWriteKey;
        }
        if (Workload.Settings.AccessDistribution == Distribution::Hotspot &&
            (State.Random.Next() % 100) < 70)
        {
            const auto HotCount = std::max(std::size_t{1}, Capacity / 16);
            return static_cast<std::size_t>(State.Random.Next() % HotCount);
        }
        if ((State.Random.Next() % 100) < 35)
        {
            return State.DynamicBegin +
                   static_cast<std::size_t>(State.Random.Next() % State.DynamicCount);
        }
        return static_cast<std::size_t>(State.Random.Next() % Workload.Keys.size());
    }

    auto AppendMixedTraceOperation(MixedTraceState &State) -> void
    {
        auto &Workload = State.Workload;
        const auto Capacity = Workload.Settings.Capacity;
        const auto Remaining = Workload.Settings.Operations - Workload.Trace.size();
        const auto CanAppendProbe = Remaining >= 2;
        const auto Bucket = State.Random.Next() % 100;
        Operation OperationValue;
        if (Bucket < 55 || !CanAppendProbe)
        {
            OperationValue.Kind = OperationKind::Get;
            const bool PreferHit = (Workload.Trace.size() % 100) < Workload.Settings.HitPercent;
            const auto Selected = PreferHit
                                      ? SelectMixedKey(State)
                                      : Capacity + static_cast<std::size_t>(State.Random.Next() % Capacity);
            OperationValue.KeyIndex = static_cast<std::uint32_t>(Selected);
            const auto &Logical = State.States[OperationValue.KeyIndex];
            OperationValue.ExpectedPresent = Logical.Present && !Logical.Expired;
            OperationValue.ExpectedHit = OperationValue.ExpectedPresent;
            OperationValue.ExpectedNegative = OperationValue.ExpectedPresent && Logical.Negative;
            OperationValue.ExpectedVersion = Logical.Version;
            AppendMixedOperation(Workload, OperationValue);
            if (Logical.Expired)
            {
                State.States[OperationValue.KeyIndex] = {};
            }
            return;
        }
        if (Bucket < 70)
        {
            OperationValue.Kind = OperationKind::Insert;
            OperationValue.KeyIndex = static_cast<std::uint32_t>(
                State.DynamicBegin + (State.InsertCursor++ % State.DynamicCount));
            OperationValue.Negative = false;
        }
        else if (Bucket < 82)
        {
            OperationValue.Kind = OperationKind::Overwrite;
            const auto Selected = SelectMixedKey(State);
            OperationValue.KeyIndex = static_cast<std::uint32_t>(
                State.HasWrite ? State.LastWriteKey : Selected);
            OperationValue.Negative = (State.Random.Next() % 4) == 0;
        }
        else if (Bucket < 90)
        {
            OperationValue.Kind = OperationKind::Insert;
            OperationValue.KeyIndex = static_cast<std::uint32_t>(
                State.DynamicBegin + (State.InsertCursor++ % State.DynamicCount));
            OperationValue.Negative = true;
        }
        else if (Bucket < 96)
        {
            OperationValue.Kind = OperationKind::Expire;
            const auto Selected = SelectMixedKey(State);
            OperationValue.KeyIndex = static_cast<std::uint32_t>(
                State.HasWrite ? State.LastWriteKey : Selected);
            OperationValue.Negative = State.States[OperationValue.KeyIndex].Negative;
            OperationValue.TtlSeconds = 0;
        }
        else
        {
            OperationValue.Kind = OperationKind::EvictExpired;
            OperationValue.KeyIndex = 0;
            AppendMixedOperation(Workload, OperationValue);
            for (auto &Logical : State.States)
            {
                if (Logical.Expired)
                {
                    Logical = {};
                }
            }
            return;
        }

        OperationValue.ValueVersion = State.Version++;
        if (OperationValue.Kind != OperationKind::Expire)
        {
            OperationValue.TtlSeconds = 86400;
        }
        OperationValue.ExpectedPresent =
            State.States[OperationValue.KeyIndex].Present &&
            !State.States[OperationValue.KeyIndex].Expired;
        State.States[OperationValue.KeyIndex] =
            {OperationValue.Kind != OperationKind::Expire,
             OperationValue.Kind == OperationKind::Expire ? false : OperationValue.Negative,
             OperationValue.Kind == OperationKind::Expire, OperationValue.ValueVersion};
        State.LastWriteKey = OperationValue.KeyIndex;
        State.HasWrite = true;
        AppendMixedOperation(Workload, OperationValue);
        AppendMixedOperation(Workload, MakeProbe(
            OperationValue, OperationValue.Kind != OperationKind::Expire));
    }

    auto GenerateMixedTrace(Scenario &Workload) -> void
    {
        AppendDynamicKeys(Workload);
        Workload.Trace.reserve(Workload.Settings.Operations);
        MixedTraceState State{
            Workload,
            SplitMix64{Workload.Settings.Seed},
            std::vector<LogicalState>(Workload.Keys.size()),
            Workload.Settings.Capacity * 2,
            Workload.Settings.Capacity * 8 + 64};
        for (std::size_t Index = 0; Index < Workload.Settings.Capacity; ++Index)
        {
            State.States[Index] = {true, Workload.Keys[Index].Negative, false, 0};
        }
        while (Workload.Trace.size() < Workload.Settings.Operations)
        {
            AppendMixedTraceOperation(State);
        }
    }

    auto GenerateScenario(Scenario &Workload) -> void
    {
        InitializeScenario(Workload);
        if (Workload.Settings.Workload == WorkloadKind::GetOnly)
        {
            GenerateGetOnlyTrace(Workload);
            return;
        }
        GenerateMixedTrace(Workload);
    }

    void ValidateScenario(const Scenario &Workload)
    {
        if (Workload.Settings.Workload == WorkloadKind::GetOnly)
        {
            return;
        }
        if (Workload.Trace.size() != Workload.Settings.Operations ||
            Workload.Mix.RequiredHitProbes != Workload.Mix.Inserts + Workload.Mix.Overwrites ||
            Workload.Mix.RequiredMissProbes != Workload.Mix.Expirations ||
            Workload.Mix.DynamicGets > Workload.Mix.Gets)
        {
            throw std::runtime_error("mixed trace probe accounting is inconsistent");
        }
        const auto Options = MakeCacheOptions(Workload.Settings.Capacity,
                                              Dns::StalePolicy::Discard);
        CurrentCache Current{Options};
        IntrusiveCache Intrusive{Options};
        ClockCache Clocked{Options};
        SeedCache(Current, Workload);
        SeedCache(Intrusive, Workload);
        SeedCache(Clocked, Workload);
        for (const auto &OperationValue : Workload.Trace)
        {
            const auto CurrentOutcome = ReplayOperation(Current, Workload, OperationValue);
            const auto IntrusiveOutcome = ReplayOperation(Intrusive, Workload, OperationValue);
            const auto ClockOutcome = ReplayOperation(Clocked, Workload, OperationValue);
            ValidateReplayResult(Workload, OperationValue, CurrentOutcome);
            ValidateReplayResult(Workload, OperationValue, IntrusiveOutcome);
            ValidateReplayResult(Workload, OperationValue, ClockOutcome);
            CompareReplayOutcomes(OperationValue, CurrentOutcome, IntrusiveOutcome);
        }
    }

    void ValidateFastSemantics()
    {
        ValidateFastFor<CurrentCache>();
        ValidateFastFor<IntrusiveCache>();
        ValidateFastFor<ClockCache>();
    }

    void ValidateSemantics()
    {
        ValidateFastSemantics();
        ValidateExpirySemantics();
    }
} // namespace Preview::Network::Dns::Compare
