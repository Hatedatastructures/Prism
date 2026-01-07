#pragma once

#include <memory>
#include <functional>
#include <string>
#include <string_view>
#include <memory_resource>
#include <memory/container.hpp>
#include <boost/asio.hpp>
#include "obscura.hpp"
#include "connection.hpp"
#include <rule/blacklist.hpp>

#include "rule.hpp"

namespace ngx::agent
{
    namespace net = boost::asio;

    /**
     * @brief 分发容器
     * @note 容器负责将数据分发到对应的会话中实现代理功能
     */
    class distributor
    {
        struct transparent_string_hash
        {
            using is_transparent = void;

            std::size_t operator()(const std::string_view value) const noexcept
            {
                return std::hash<std::string_view>{}(value);
            }

            std::size_t operator()(const memory::string &value) const noexcept
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        }; // struct transparent_string_hash

        struct transparent_string_equal
        {
            using is_transparent = void;

            bool operator()(const std::string_view left, const std::string_view right) const noexcept
            {
                return left == right;
            }

            bool operator()(const memory::string &left, const std::string_view right) const noexcept
            {
                return std::string_view(left) == right;
            }

            bool operator()(const std::string_view left, const memory::string &right) const noexcept
            {
                return left == std::string_view(right);
            }

            bool operator()(const memory::string &left, const memory::string &right) const noexcept
            {
                return left == right;
            }
        }; // struct transparent_string_equal

        template <typename Key, typename Value>
        using unordered_map = memory::unordered_map<Key, Value, transparent_string_hash, transparent_string_equal>;

    public:
        explicit distributor(source &pool, net::io_context &ioc, std::pmr::memory_resource *mr = std::pmr::new_delete_resource());
        void load_reverse_map(const std::string &file_path);
        [[nodiscard]] net::awaitable<exclusive_connection> route_reverse(std::string_view host);
        [[nodiscard]] net::awaitable<exclusive_connection> route_direct(tcp::endpoint ep) const;
        [[nodiscard]] net::awaitable<exclusive_connection> route_forward(std::string_view host, std::string_view port);
    private:

        source &pool_;
        tcp::resolver resolver_;
        rule::blacklist blacklist_;
        std::pmr::memory_resource *mr_;
        unordered_map<memory::string, tcp::endpoint> reverse_map_;
    }; // class distributor
}
