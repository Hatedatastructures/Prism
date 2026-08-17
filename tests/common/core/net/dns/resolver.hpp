/**
 * @file resolver.hpp
 * @brief DNS 解析器（async_resolve + LRU 缓存）
 * @details 封装 boost::asio::tcp::resolver：
 *          - async_resolve：异步解析（域名 → 端点列表）
 *          - LRU 缓存：命中免解析；TTL 过期失效；负缓存
 * @note 参照主项目 net/dns/resolver 语义，preview 风格
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <list>
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

#include <common/core/error.hpp>

namespace preview::network::dns
{

    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @struct cache_entry
     * @brief DNS 缓存条目
     */
    struct cache_entry
    {
        std::vector<net::ip::address> addresses;    ///< 解析结果
        std::chrono::steady_clock::time_point expiry; ///< 过期时间
        bool negative{false};                       ///< 负缓存（解析失败）
    };

    /**
     * @class resolver
     * @brief DNS 解析器（LRU 缓存）
     */
    class resolver
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param cache_size 缓存容量（0 = 禁用）
         * @param ttl 缓存 TTL
         * @param negative_ttl 负缓存 TTL
         */
        explicit resolver(net::any_io_executor ex, std::size_t cache_size = 64,
                          std::chrono::seconds ttl = std::chrono::seconds(60),
                          std::chrono::seconds negative_ttl = std::chrono::seconds(5))
            : ex_(std::move(ex)), cache_size_(cache_size), ttl_(ttl), negative_ttl_(negative_ttl)
        {
        }

        /**
         * @brief 异步解析（带缓存）
         * @param host 主机名
         * @param ec 错误码输出
         * @return 地址列表；失败为空
         */
        [[nodiscard]] auto async_resolve(std::string_view host, std::error_code &ec)
            -> net::awaitable<std::vector<net::ip::address>>
        {
            // 缓存命中
            if (const auto cached = lookup_cache(host); cached.has_value())
            {
                if (cached->negative)
                {
                    ec = std::make_error_code(std::errc::no_such_file_or_directory);
                    co_return std::vector<net::ip::address>{};
                }
                co_return cached->addresses;
            }

            // 未命中：实际解析
            tcp::resolver resolver(ex_);
            boost::system::error_code r_ec;
            auto results = co_await resolver.async_resolve(host, "80",
                                                           net::redirect_error(net::use_awaitable, r_ec));
            if (r_ec)
            {
                ec = std::make_error_code(std::errc::no_such_file_or_directory);
                cache_negative(host);
                co_return std::vector<net::ip::address>{};
            }

            std::vector<net::ip::address> addresses;
            for (const auto &res : results)
            {
                addresses.push_back(res.endpoint().address());
            }
            ec.clear();
            cache_positive(host, addresses);
            co_return addresses;
        }

        /**
         * @brief 缓存命中数（测试辅助）
         * @return 命中次数
         */
        [[nodiscard]] auto hit_count() const noexcept -> std::uint64_t
        {
            return hits_;
        }

        /**
         * @brief 缓存大小
         * @return 当前条目数
         */
        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return cache_.size();
        }

        /**
         * @brief 清空缓存
         */
        void clear()
        {
            cache_.clear();
            lru_.clear();
        }

    private:
        net::any_io_executor ex_;
        std::size_t cache_size_{64};
        std::chrono::seconds ttl_{60};
        std::chrono::seconds negative_ttl_{5};
        std::unordered_map<std::string, cache_entry> cache_;
        std::list<std::string> lru_; ///< LRU 顺序（前 = 最近）
        std::uint64_t hits_{0};

        /**
         * @brief 查缓存（含过期检查）
         * @param host 主机名
         * @return 有效条目；未命中/过期返回 std::nullopt
         */
        [[nodiscard]] auto lookup_cache(std::string_view host) -> std::optional<cache_entry>
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
        void cache_positive(std::string_view host, const std::vector<net::ip::address> &addresses)
        {
            cache_entry e;
            e.addresses = addresses;
            e.expiry = std::chrono::steady_clock::now() + ttl_;
            insert_entry(host, std::move(e));
        }

        /**
         * @brief 缓存负结果
         * @param host 主机名
         */
        void cache_negative(std::string_view host)
        {
            cache_entry e;
            e.negative = true;
            e.expiry = std::chrono::steady_clock::now() + negative_ttl_;
            insert_entry(host, std::move(e));
        }

        /**
         * @brief 插入条目（LRU 淘汰）
         * @param host 主机名
         * @param e 条目
         */
        void insert_entry(std::string_view host, cache_entry e)
        {
            const auto key = std::string(host);
            cache_[key] = std::move(e);
            lru_.push_front(key);
            while (cache_.size() > cache_size_ && cache_size_ > 0)
            {
                const auto &oldest = lru_.back();
                cache_.erase(oldest);
                lru_.pop_back();
            }
        }
    };

} // namespace preview::network::dns
