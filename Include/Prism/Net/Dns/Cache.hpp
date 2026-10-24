/** @file Cache.hpp @brief DNS 结果缓存的值类型与接口。 */
#pragma once

#include <Prism/Net/Dns/Config.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/container/small_vector.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Prism::Network::Dns
{
    /** @brief 缓存容量与 TTL 约束。 */
    struct CacheOptions
    {
        std::size_t MaxEntries{10000};
        std::chrono::seconds TtlMin{0};
        std::chrono::seconds TtlMax{86400};
        std::chrono::seconds NegativeTtl{30};
        StalePolicy Policy{StalePolicy::Discard};
    };

    /** @brief 一次缓存写入的拥有型输入。 */
    struct PutInput
    {
        std::string Domain;
        std::uint16_t QType{};
        boost::container::small_vector<boost::asio::ip::address, 4> Ips;
        std::chrono::seconds Ttl{0};
        bool Failed{false};
    };

    /// 缓存条目的地址容器。
    using IpList = boost::container::small_vector<boost::asio::ip::address, 4>;

    /**
     * @brief DNS 响应内存缓存；索引与 LRU 只允许在所属控制 executor 访问。
     * @details 连续存储加槽号 LRU 队列，命中路径不构造临时堆键。
     */
    class Cache
    {
    public:
        static constexpr std::size_t NoSlot = std::numeric_limits<std::size_t>::max();

        /** @brief 缓存条目，连续存储并由唯一 LRU 槽索引。 */
        struct Entry
        {
            std::string Key;
            IpList Ips;
            std::chrono::steady_clock::time_point Expire;
            std::chrono::steady_clock::time_point Inserted;
            bool Failed{false};
            bool Dead{false};
            std::size_t Previous{NoSlot};
            std::size_t Next{NoSlot};
            bool Linked{false};
        };

        explicit Cache(CacheOptions Options);

        /** @brief 查询缓存；负缓存命中返回空地址表，未命中返回空 optional。 */
        [[nodiscard]] auto Get(const std::string &Domain, std::uint16_t QTypeValue)
            -> std::optional<IpList>;

        /** @brief 写入结果并按配置钳制 TTL。 */
        auto Put(const PutInput &Input) -> void;

        /** @brief 以固定负缓存 TTL 写入失败结果。 */
        auto PutNegative(const std::string &Domain, std::uint16_t QTypeValue) -> void;

        /** @brief 驱逐全部过期条目并返回数量。 */
        auto EvictExpired() -> std::size_t;

        /** @brief 返回存活条目数。 */
        [[nodiscard]] auto Size() const -> std::size_t;

        /** @brief 清空缓存并重置 LRU 与槽回收状态。 */
        auto Clear() -> void;

        /** @brief 生成持久化缓存键。 */
        [[nodiscard]] static auto MakeKey(const std::string &Domain, std::uint16_t QTypeValue)
            -> std::string;

    private:
        using Index = std::unordered_map<std::string, std::size_t,
            TransparentStringHash, TransparentStringEqual>;

        [[nodiscard]] auto KeyView(const std::string &Domain, std::uint16_t QTypeValue)
            -> std::string_view;
        auto Unlink(std::size_t Slot) noexcept -> void;
        auto Promote(std::size_t Slot) noexcept -> void;
        auto EvictOldest() -> void;
        auto Drop(Index::iterator EntryValue) -> Index::iterator;
        auto Store(const PutInput &Input, std::chrono::seconds Ttl) -> void;

        CacheOptions Options_;
        bool Unlimited_;
        std::vector<Entry> Slots_;
        Index Index_;
        std::size_t Oldest_{NoSlot};
        std::size_t Newest_{NoSlot};
        std::vector<std::size_t> Free_;
        std::size_t LiveCount_{0};
        std::array<char, 260> KeyBuf_{};
        std::string HeapKey_;
    };
} // namespace Prism::Network::Dns
