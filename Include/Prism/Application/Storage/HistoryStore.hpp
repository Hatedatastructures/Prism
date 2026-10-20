/** @file HistoryStore.hpp @brief 与额度事务隔离的窗口历史存储，保留完整直方图并公开缺测。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Storage/Sqlite.hpp>
#include <Prism/Statistics/Analysis/HistorySeries.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Application::Storage
{
    class StorageRuntime;

    /**
     * @brief Append 接管完整窗口值；相同序列及窗口 UPSERT，不将重试重复求和。
     * @details 上游拥有各层降采样，存储只选择一个层读取，禁止把重叠分辨率相加。
     *          关闭归 StorageRuntime，调用完成回原 executor；不关闭网络资源。
     */
    class HistoryStore final
    {
    public:
        explicit HistoryStore(std::shared_ptr<StorageRuntime> Owner);
        [[nodiscard]] auto Append(std::vector<Statistics::HistoryRecord> Records)
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>>;
        [[nodiscard]] auto Query(Statistics::HistoryQuery Request)
            -> boost::asio::awaitable<std::expected<Statistics::HistoryResult, Fault::Failure>>;
        [[nodiscard]] auto Prune(std::uint64_t Now)
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>>;
    private:
        static auto Now() -> std::uint64_t;
        static auto UsedBytes(StorageRuntime& Owner) -> std::uint64_t;
        static auto EncodeHistogram(const Statistics::LatencyHistogram& Value) -> std::string;
        static auto DecodeHistogram(std::string_view Text) -> Statistics::LatencyHistogram;
        static auto ValidRecord(const Statistics::HistoryRecord& Value) -> bool;
        static auto InsertRecord(Prism::Storage::Database& Database, const Statistics::HistoryRecord& Value) -> void;
        static auto AppendOnStorage(StorageRuntime& Owner, const std::vector<Statistics::HistoryRecord>& Records)
            -> std::expected<void, Fault::Failure>;
        static auto ReadRecord(const Prism::Storage::Statement& Row) -> Statistics::HistoryRecord;
        static auto QueryOnStorage(StorageRuntime& Owner, const Statistics::HistoryQuery& Request)
            -> std::expected<Statistics::HistoryResult, Fault::Failure>;
        static auto PruneOnStorage(Prism::Storage::Database& Database, std::uint64_t Timestamp) -> void;
        static auto PruneResolution(Prism::Storage::Database& Database,
                                    std::pair<std::uint64_t, std::uint64_t> Value) -> void;
        std::shared_ptr<StorageRuntime> Owner_;
    };
}
