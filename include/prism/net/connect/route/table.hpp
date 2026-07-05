/**
 * @file route_table.hpp
 * @brief 反向路由表
 * @details 从 connect::router 拆出的路由子模块，仅管理 host → tcp::endpoint
 * 映射和正向代理端点配置。与 DNS 解析、连接池完全解耦。
 *
 * 设计目的：
 *   - 消除 router 上帝类（DNS + 路由 + 连接池 facade 三合一）
 *   - 让路由策略可独立测试与替换
 *   - 配置态（add_route/set_endpoint）与运行态分离
 *
 * @note 单线程使用（每 worker 一个），无需锁
 */
#pragma once

#include <prism/foundation/memory/container.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>


namespace psm::connect
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @struct route_stats
     * @brief 路由表命中统计
     */
    struct route_stats
    {
        std::uint64_t reverse_hits{0};   ///< 反向路由命中
        std::uint64_t reverse_misses{0}; ///< 反向路由未命中
        std::uint64_t forward_uses{0};   ///< 正向代理使用次数
    };

    /**
     * @class route_table
     * @brief 反向路由表（domain → endpoint）+ 正向代理端点配置
     * @details 仅管理 host → tcp::endpoint 映射，与 DNS 解析、连接池完全解耦。
     *          通过透明哈希支持 string_view/memory::string 混合查找。
     * @note 单线程使用
     */
    class route_table
    {
    public:
        /**
         * @brief 透明字符串哈希函数对象
         * @details 支持 std::string_view 和 memory::string，启用透明查找。
         */
        struct string_hash
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(std::string_view value) const noexcept
                -> std::size_t
            {
                return std::hash<std::string_view>{}(value);
            }

            [[nodiscard]] auto operator()(const memory::string &value) const noexcept
                -> std::size_t
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        };

        /**
         * @brief 透明字符串相等比较函数对象
         */
        struct string_equal
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(std::string_view left, std::string_view right) const noexcept
                -> bool
            {
                return left == right;
            }

            [[nodiscard]] auto operator()(const memory::string &left, std::string_view right) const noexcept
                -> bool
            {
                return std::string_view(left) == right;
            }

            [[nodiscard]] auto operator()(std::string_view left, const memory::string &right) const noexcept
                -> bool
            {
                return left == std::string_view(right);
            }

            [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept
                -> bool
            {
                return left == right;
            }
        };

        using map_type = memory::unordered_map<memory::string, tcp::endpoint, string_hash, string_equal>;

        /**
         * @brief 构造路由表
         * @param mr 内存资源指针
         */
        explicit route_table(memory::resource_pointer mr = memory::current_resource())
            : reverse_(mr)
        {
        }

        /**
         * @brief 添加反向路由规则
         * @param host 匹配的主机名
         * @param ep 目标 TCP 端点
         */
        auto add_route(std::string_view host, const tcp::endpoint &ep) -> void;

        /**
         * @brief 移除反向路由规则
         * @param host 主机名
         * @return 移除的规则数（0 或 1）
         */
        auto remove_route(std::string_view host) -> std::size_t;

        /**
         * @brief 设置正向代理端点
         * @param host 上游主机名
         * @param port 上游端口
         */
        auto set_forward_endpoint(std::string_view host, std::uint16_t port) -> void;

        /**
         * @brief 清空正向代理端点
         */
        auto clear_forward_endpoint() -> void;

        /**
         * @brief 反向路由查询
         * @param host 主机名
         * @return 命中返回端点，未命中返回 nullopt
         * @details 累加 reverse_hits 或 reverse_misses 统计。
         */
        [[nodiscard]] auto lookup(std::string_view host) -> std::optional<tcp::endpoint>;

        /**
         * @brief 获取正向代理主机
         * @return 主机名 optional 引用
         */
        [[nodiscard]] auto forward_host() const noexcept
            -> const std::optional<memory::string> &
        {
            return forward_host_;
        }

        /**
         * @brief 获取正向代理端口
         * @return 端口号，未设置时为 0
         */
        [[nodiscard]] auto forward_port() const noexcept -> std::uint16_t
        {
            return forward_port_;
        }

        /**
         * @brief 获取统计快照
         * @return reverse_hits/reverse_misses/forward_uses 计数
         */
        [[nodiscard]] auto stats() const noexcept -> route_stats;

    private:
        map_type reverse_;
        std::optional<memory::string> forward_host_;
        std::uint16_t forward_port_{0};
        mutable std::atomic<std::uint64_t> reverse_hits_{0};
        mutable std::atomic<std::uint64_t> reverse_misses_{0};
        mutable std::atomic<std::uint64_t> forward_uses_{0};
    };

} // namespace psm::connect
