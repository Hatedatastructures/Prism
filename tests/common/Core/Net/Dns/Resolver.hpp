/**
 * @file Resolver.hpp
 * @brief DNS 解析器（AsyncResolve + LRU 缓存）
 * @details 封装 boost::asio::tcp::Resolver：
 *          - AsyncResolve：异步解析（域名 → 端点列表）
 *          - LRU 缓存：命中免解析；TTL 过期失效；负缓存
 * @note 参照主项目 net/dns/Resolver 语义，Preview 风格
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <List>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <common/Core/Error.hpp>

namespace Preview::Network::Dns
{

    namespace net = boost::asio;
    using Tcp = net::ip::tcp;

    /**
     * @struct CacheEntry
     * @brief DNS 缓存条目
     */
    struct CacheEntry
    {
        std::vector<net::ip::address> addresses;    ///< 解析结果
        std::chrono::steady_clock::time_point expiry; ///< 过期时间
        bool negative{false};                       ///< 负缓存（解析失败）
    };

    /**
     * @class Resolver
     * @brief DNS 解析器（LRU 缓存）
     */
    class Resolver
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param CacheSize 缓存容量（0 = 禁用）
         * @param ttl 缓存 TTL
         * @param NegativeTtl 负缓存 TTL
         */
        explicit Resolver(net::any_io_executor ex, std::size_t CacheSize = 64,
                          std::chrono::seconds ttl = std::chrono::seconds(60),
                          std::chrono::seconds NegativeTtl = std::chrono::seconds(5))
            : ex_(std::move(ex)), CacheSize_(CacheSize), ttl_(ttl), NegativeTtl_(NegativeTtl)
        {
        }

        /**
         * @brief 异步解析（带缓存）
         * @param host 主机名
         * @param ec 错误码输出
         * @return 地址列表；失败为空
         */
        [[nodiscard]] auto AsyncResolve(std::string_view host, std::error_code &ec)
            -> net::awaitable<std::vector<net::ip::address>>
        {
            // 缓存命中
            if (const auto cached = LookupCache(host); cached.has_value())
            {
                if (cached->negative)
                {
                    ec = std::make_error_code(std::errc::no_such_file_or_directory);
                    co_return std::vector<net::ip::address>{};
                }
                co_return cached->addresses;
            }

            // 未命中：实际解析
            net::ip::tcp::resolver Resolver(ex_);
            boost::system::error_code REc;
            auto results = co_await Resolver.async_resolve(host, "80",
                                                           net::redirect_error(net::use_awaitable, REc));
            if (REc)
            {
                ec = std::make_error_code(std::errc::no_such_file_or_directory);
                CacheNegative(host);
                co_return std::vector<net::ip::address>{};
            }

            std::vector<net::ip::address> addresses;
            for (const auto &res : results)
            {
                addresses.push_back(res.endpoint().address());
            }
            ec.clear();
            CachePositive(host, addresses);
            co_return addresses;
        }

        /**
         * @brief 缓存命中数（测试辅助）
         * @return 命中次数
         */
        [[nodiscard]] auto HitCount() const noexcept -> std::uint64_t
        {
            return hits_;
        }

        /**
         * @brief 缓存大小
         * @return 当前条目数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return cache_.size();
        }

        /**
         * @brief 清空缓存
         */
        void Clear()
        {
            cache_.clear();
            lru_.clear();
        }

    private:
        net::any_io_executor ex_;
        std::size_t CacheSize_{64};
        std::chrono::seconds ttl_{60};
        std::chrono::seconds NegativeTtl_{5};
        std::unordered_map<std::string, CacheEntry> cache_;
        std::list<std::string> lru_; ///< LRU 顺序（前 = 最近）
        std::uint64_t hits_{0};

        /**
         * @brief 查缓存（含过期检查）
         * @param host 主机名
         * @return 有效条目；未命中/过期返回 std::nullopt
         */
        [[nodiscard]] auto LookupCache(std::string_view host) -> std::optional<CacheEntry>
        {
            const auto it = cache_.find(std::string(host));
            if (it == cache_.end())
            {
                return std::nullopt;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now >= it->second.expiry)
            {
                cache_.erase(it);
                return std::nullopt;
            }
            // LRU 提升
            lru_.remove(std::string(host));
            lru_.push_front(std::string(host));
            ++hits_;
            return it->second;
        }

        /**
         * @brief 缓存正结果
         * @param host 主机名
         * @param addresses 地址列表
         */
        void CachePositive(std::string_view host, const std::vector<net::ip::address> &addresses)
        {
            CacheEntry e;
            e.addresses = addresses;
            e.expiry = std::chrono::steady_clock::now() + ttl_;
            InsertEntry(host, std::move(e));
        }

        /**
         * @brief 缓存负结果
         * @param host 主机名
         */
        void CacheNegative(std::string_view host)
        {
            CacheEntry e;
            e.negative = true;
            e.expiry = std::chrono::steady_clock::now() + NegativeTtl_;
            InsertEntry(host, std::move(e));
        }

        /**
         * @brief 插入条目（LRU 淘汰）
         * @param host 主机名
         * @param e 条目
         */
        void InsertEntry(std::string_view host, CacheEntry e)
        {
            const auto key = std::string(host);
            cache_[key] = std::move(e);
            lru_.push_front(key);
            while (cache_.size() > CacheSize_ && CacheSize_ > 0)
            {
                const auto &oldest = lru_.back();
                cache_.erase(oldest);
                lru_.pop_back();
            }
        }
    };

} // namespace Preview::Network::Dns
