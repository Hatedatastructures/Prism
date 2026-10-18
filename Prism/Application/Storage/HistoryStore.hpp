/** @file HistoryStore.hpp @brief 与额度事务隔离的窗口历史存储，保留完整直方图并公开缺测。 */
#pragma once
#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <Prism/Statistics/Analysis/HistorySeries.hpp>
#include <chrono>
#include <limits>

namespace Prism::Application::Storage
{
    /**
     * @brief Append 接管完整窗口值；相同序列及窗口 UPSERT，不将重试重复求和。
     * @details 上游拥有各层降采样，存储只选择一个层读取，禁止把重叠分辨率相加。
     *          关闭归 StorageRuntime，调用完成回原 executor；不关闭网络资源。
     */
    class HistoryStore final
    {
    public:
        explicit HistoryStore(std::shared_ptr<StorageRuntime> Owner) : Owner_(std::move(Owner))
        { if (!Owner_) throw std::invalid_argument("storage owner required"); }
        [[nodiscard]] auto Append(std::vector<Statistics::HistoryRecord> Records)
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>>
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Records = std::move(Records)]()
                { return AppendOnStorage(*Owner, Records); });
        }
        [[nodiscard]] auto Query(Statistics::HistoryQuery Request)
            -> boost::asio::awaitable<std::expected<Statistics::HistoryResult, Fault::Failure>>
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return QueryOnStorage(*Owner, Request); });
        }
        [[nodiscard]] auto Prune(std::uint64_t Now)
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>>
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Now]() -> std::expected<void, Fault::Failure>
                { PruneOnStorage(Owner->History(), Now); return {}; });
        }
    private:
        static auto Now() -> std::uint64_t
        {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        }
        static auto UsedBytes(StorageRuntime& Owner) -> std::uint64_t
        {
            auto& Database = Owner.History();
            const auto Pages = static_cast<std::uint64_t>(Database.Scalar("PRAGMA page_count"));
            const auto PageSize = static_cast<std::uint64_t>(Database.Scalar("PRAGMA page_size"));
            std::error_code Error;
            const auto Wal = std::filesystem::file_size(Owner.Options().Directory / "history.sqlite3-wal", Error);
            return Prism::Storage::AddExact(Pages * PageSize, Error ? 0 : Wal);
        }
        static auto EncodeHistogram(const Statistics::LatencyHistogram& Value) -> std::string
        {
            std::string Result;
            for (const auto Bucket : Value.Buckets) { if (!Result.empty()) Result.push_back(','); Result += Prism::Storage::Decimal(Bucket); }
            return Result;
        }
        static auto DecodeHistogram(std::string_view Text) -> Statistics::LatencyHistogram
        {
            Statistics::LatencyHistogram Result;
            for (std::size_t Index = 0; Index < Result.Buckets.size(); ++Index)
            {
                const auto End = Text.find(',');
                const bool Last = Index + 1 == Result.Buckets.size();
                if (Last != (End == std::string_view::npos)) throw Prism::Storage::SqliteError(SQLITE_CORRUPT);
                Result.Buckets[Index] = Prism::Storage::ParseDecimal(Text.substr(0, End));
                if (!Last) Text.remove_prefix(End + 1);
            }
            return Result;
        }
        static auto ValidRecord(const Statistics::HistoryRecord& Value) -> bool
        {
            const auto Resolution = Value.ResolutionMilliseconds;
            return !Value.InstanceKey.empty() && !Value.Incarnation.empty() &&
                static_cast<unsigned>(Value.Scope) <= static_cast<unsigned>(Statistics::HistoryScope::ProtocolInstance) &&
                (Resolution == 10'000 || Resolution == 60'000 || Resolution == 900'000) &&
                Value.Timestamp <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) &&
                Value.Timestamp % Resolution == 0;
        }
        static auto InsertRecord(Prism::Storage::Database& Database, const Statistics::HistoryRecord& Value) -> void
        {
            auto Row = Database.Prepare(R"sql(INSERT INTO history_record VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(scope,resource_key,instance_key,incarnation,generation,time,resolution) DO UPDATE SET
up=excluded.up,down=excluded.down,events=excluded.events,errors=excluded.errors,active=excluded.active,
latency=excluded.latency,maximum=excluded.maximum,range_exceeded=excluded.range_exceeded,
dropped=excluded.dropped,aggregation_failures=excluded.aggregation_failures,incomplete=excluded.incomplete)sql");
            Row.Integer(1, static_cast<int>(Value.Scope)); Row.Text(2, Value.Key); Row.Text(3, Value.InstanceKey);
            Row.Text(4, Value.Incarnation); Row.Unsigned(5, Value.Generation); Row.Integer(6, static_cast<std::int64_t>(Value.Timestamp));
            Row.Integer(7, static_cast<std::int64_t>(Value.ResolutionMilliseconds)); Row.Unsigned(8, Value.UpBytes);
            Row.Unsigned(9, Value.DownBytes); Row.Unsigned(10, Value.Events); Row.Unsigned(11, Value.Errors);
            if (Value.Active) Row.Unsigned(12, *Value.Active); else Row.Null(12);
            Row.Text(13, EncodeHistogram(Value.Latency)); Row.Unsigned(14, Value.Latency.Maximum);
            Row.Unsigned(15, Value.Latency.RangeExceeded); Row.Unsigned(16, Value.Quality.Dropped);
            Row.Unsigned(17, Value.Quality.AggregationFailures); Row.Integer(18, Value.Quality.Incomplete ? 1 : 0); Row.Run();
        }
        static auto AppendOnStorage(StorageRuntime& Owner, const std::vector<Statistics::HistoryRecord>& Records)
            -> std::expected<void, Fault::Failure>
        {
            if (Records.empty()) return {};
            if (Records.size() > 100'000) return std::unexpected(Fault::Failure{Fault::Code::OversizedMsg});
            for (const auto& Record : Records)
                if (!ValidRecord(Record)) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            if (UsedBytes(Owner) >= Owner.Options().HistoryBudgetBytes)
                return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable});
            auto& Database = Owner.History();
            const auto PageSize = static_cast<std::uint64_t>(Database.Scalar("PRAGMA page_size"));
            const auto MaxPages = Owner.Options().HistoryBudgetBytes / PageSize;
            if (MaxPages == 0) return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable});
            Database.Execute("PRAGMA max_page_count=" + std::to_string(MaxPages));
            Prism::Storage::Transaction Transaction(Database);
            for (const auto& Record : Records) InsertRecord(Database, Record);
            Transaction.Commit();
            return {};
        }
        static auto ReadRecord(const Prism::Storage::Statement& Row) -> Statistics::HistoryRecord
        {
            Statistics::HistoryRecord Value;
            Value.Scope = static_cast<Statistics::HistoryScope>(Row.Signed(0)); Value.Key = Row.String(1);
            Value.InstanceKey = Row.String(2); Value.Incarnation = Row.String(3); Value.Generation = Row.Uint(4);
            Value.Timestamp = static_cast<std::uint64_t>(Row.Signed(5));
            Value.ResolutionMilliseconds = static_cast<std::uint64_t>(Row.Signed(6));
            Value.UpBytes = Row.Uint(7); Value.DownBytes = Row.Uint(8); Value.Events = Row.Uint(9); Value.Errors = Row.Uint(10);
            if (!Row.IsNull(11)) Value.Active = Row.Uint(11);
            Value.Latency = DecodeHistogram(Row.String(12)); Value.Latency.Maximum = Row.Uint(13);
            Value.Latency.RangeExceeded = Row.Uint(14); Value.Quality.Dropped = Row.Uint(15);
            Value.Quality.AggregationFailures = Row.Uint(16); Value.Quality.Incomplete = Row.Signed(17) != 0;
            return Value;
        }
        static auto QueryOnStorage(StorageRuntime& Owner, const Statistics::HistoryQuery& Request)
            -> std::expected<Statistics::HistoryResult, Fault::Failure>
        {
            if (!Statistics::ValidHistoryQuery(Request) || Request.To >
                static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            Statistics::HistoryResult Result;
            Result.SampledAt = Now(); Result.From = Request.From; Result.To = Request.To;
            const auto Age = Result.SampledAt > Request.From ? Result.SampledAt - Request.From : 0;
            const auto Source = Age <= Statistics::HistoryTenSecondRetention ? 10'000U :
                Age <= Statistics::HistoryMinuteRetention ? 60'000U : 900'000U;
            const auto Width = Request.To - Request.From;
            const auto Needed = Width / Request.MaxPoints + (Width % Request.MaxPoints != 0);
            Result.ResolutionMilliseconds = (std::max)(std::uint64_t{1}, Needed / Source + (Needed % Source != 0)) * Source;
            auto Query = Owner.History().Prepare("SELECT * FROM history_record WHERE scope=? AND resource_key=? AND resolution=? AND time>=? AND time<? ORDER BY time,instance_key,incarnation,generation");
            Query.Integer(1, static_cast<int>(Request.Scope)); Query.Text(2, Request.Key); Query.Integer(3, Source);
            Query.Integer(4, static_cast<std::int64_t>(Request.From)); Query.Integer(5, static_cast<std::int64_t>(Request.To));
            std::vector<Statistics::HistoryRecord> Raw;
            while (Query.Step()) Raw.push_back(ReadRecord(Query));
            Result.Items = Statistics::AggregateHistory(std::move(Raw), Result.ResolutionMilliseconds);
            if (Result.Items.size() > Request.MaxPoints)
            {
                Result.Gaps.push_back({Result.Items[Request.MaxPoints].Timestamp, Request.To, "point_budget"});
                Result.Items.resize(Request.MaxPoints);
            }
            Statistics::FindHistoryGaps(Result);
            const bool Capacity = UsedBytes(Owner) >= Owner.Options().HistoryBudgetBytes;
            Result.Available = true; Result.Coverage = Result.Gaps.empty() && !Capacity ? "complete" : "partial";
            if (Capacity) Result.Failure = "history_capacity";
            return Result;
        }
        static auto PruneOnStorage(Prism::Storage::Database& Database, std::uint64_t Timestamp) -> void
        {
            Prism::Storage::Transaction Transaction(Database);
            PruneResolution(Database, {10'000U, Timestamp > Statistics::HistoryTenSecondRetention ? Timestamp - Statistics::HistoryTenSecondRetention : 0});
            PruneResolution(Database, {60'000U, Timestamp > Statistics::HistoryMinuteRetention ? Timestamp - Statistics::HistoryMinuteRetention : 0});
            PruneResolution(Database, {900'000U, Timestamp > Statistics::HistoryRetention ? Timestamp - Statistics::HistoryRetention : 0});
            Transaction.Commit();
            Database.Execute("PRAGMA wal_checkpoint(TRUNCATE)");
        }
        static auto PruneResolution(Prism::Storage::Database& Database, std::pair<std::uint64_t, std::uint64_t> Value) -> void
        {
            auto Delete = Database.Prepare("DELETE FROM history_record WHERE resolution=? AND time<?");
            Delete.Integer(1, static_cast<std::int64_t>(Value.first)); Delete.Integer(2, static_cast<std::int64_t>(Value.second));
            Delete.Run();
        }
        std::shared_ptr<StorageRuntime> Owner_;
    };
}
