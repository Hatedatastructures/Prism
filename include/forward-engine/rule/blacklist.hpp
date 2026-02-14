/**
 * @file blacklist.hpp
 * @brief 黑名单管理
 * @details 提供了基于 `IP` 地址和域名的黑名单匹配功能，支持精确 `IP` 匹配和域名后缀匹配。
 * 作为 `ForwardEngine` 规则引擎的核心组件，用于实现访问控制和安全过滤。
 *
 * 设计原理：
 * - 透明哈希：使用透明哈希和相等比较器，支持 `std::string_view` 直接查找 `std::string`，避免临时字符串构造；
 * - 后缀匹配：域名匹配支持后缀匹配，黑名单中的 `"baidu.com"` 会匹配 `"www.baidu.com"` 和 `"map.baidu.com"`；
 * - 线程安全：黑名单查询是只读操作，线程安全；修改操作需外部同步。
 *
 * 数据结构：
 * - IP 黑名单：`std::unordered_set` 存储精确 `IP` 地址（如 `"192.168.1.1"`、`"2001:db8::1"`）；
 * - 域名黑名单：`std::unordered_set` 存储域名后缀（如 `"example.com"`、`"malicious.org"`）。
 *
 * 匹配算法：
 * 1. IP 匹配：精确匹配 `IP` 地址字符串；
 * 2. 域名匹配：从完整域名逐级剥离子域名进行后缀匹配。
 *
 * 性能考虑：
 * - 使用透明哈希避免查询时的临时 `std::string` 分配，提升热路径性能；
 * - 域名后缀匹配时间复杂度 `O(n)`，其中 `n` 为域名标签数；
 * - 哈希表查找平均时间复杂度 `O(1)`，最坏情况 `O(n)`。
 *
 * 使用场景：
 * - 访问控制：阻止黑名单中的 `IP` 或域名访问；
 * - 安全过滤：屏蔽恶意或可疑的服务器；
 * - 流量管理：限制特定域名的访问流量。
 *
 * @note 黑名单数据通常在系统启动时加载，运行时可通过 `insert_*` 方法动态更新。
 * @warning 域名后缀匹配可能导致误判，如 `"example.com"` 会匹配 `"bad.example.com"`。
 * @warning 修改操作（`load`、`insert_*`、`clear`）不是线程安全的，需外部同步。
 */
#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

/**
 * @struct transparent_string_hash
 * @brief 透明字符串哈希函数
 * @details 提供透明哈希支持，允许使用 `std::string_view` 直接查找存储在 `std::unordered_set` 中的 `std::string`。
 *
 * 设计原理：
 * - 透明哈希：通过 `is_transparent` 类型别名标记为透明哈希函数；
 * - 避免分配：使用 `std::string_view` 哈希避免构造临时 `std::string` 对象；
 * - 性能优化：减少热路径中的内存分配和字符串复制。
 *
 * 重载说明：
 * - `operator()(const std::string_view sv)`：计算 `std::string_view` 的哈希值；
 * - `operator()(const std::string &s)`：计算 `std::string` 的哈希值（转换为 `std::string_view`）。
 *
 * @note 透明哈希是 `C++14` 引入的特性，要求哈希函数支持异构查找。
 * @warning 哈希函数必须保证对于相同的字符串内容，无论类型如何都返回相同的哈希值。
 */
struct transparent_string_hash
{
    using is_transparent = void;
    std::size_t operator()(const std::string_view sv) const noexcept
    {
        return std::hash<std::string_view>{}(sv);
    }
    std::size_t operator()(const std::string &s) const noexcept
    {
        return std::hash<std::string_view>{}(s);
    }
};

/**
 * @struct transparent_string_equal
 * @brief 透明字符串相等比较器
 * @details 提供透明相等比较支持，允许 `std::string_view` 与 `std::string` 直接比较，无需类型转换。
 *
 * 设计原理：
 * - 透明比较：通过 `is_transparent` 类型别名标记为透明比较器；
 * - 类型混合：支持 `std::string` 与 `std::string_view` 的任意组合比较；
 * - 性能优化：避免构造临时 `std::string` 对象，减少内存分配。
 *
 * 重载说明：
 * - `operator()(const std::string_view lhs, const std::string_view rhs)`：比较两个 `std::string_view`；
 * - `operator()(const std::string &lhs, const std::string_view rhs)`：比较 `std::string` 与 `std::string_view`；
 * - `operator()(const std::string_view lhs, const std::string &rhs)`：比较 `std::string_view` 与 `std::string`；
 * - `operator()(const std::string &lhs, const std::string &rhs)`：比较两个 `std::string`。
 *
 * @note 透明比较器是 `C++14` 引入的特性，要求比较器支持异构查找。
 * @warning 比较器必须保证对于相同的字符串内容，无论类型如何都返回相同的比较结果。
 *
 * std::equal_to
 * std::string_view
 */
struct transparent_string_equal
{
    using is_transparent = void;
    bool operator()(const std::string_view lhs, const std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
    bool operator()(const std::string &lhs, const std::string_view rhs) const noexcept
    {
        return lhs == rhs;
    }
    bool operator()(const std::string_view lhs, const std::string &rhs) const noexcept
    {
        return lhs == rhs;
    }
    bool operator()(const std::string &lhs, const std::string &rhs) const noexcept
    {
        return lhs == rhs;
    }
};

/**
 * @namespace ngx::rule
 * @brief 规则引擎模块
 * @details 定义了 `ForwardEngine` 的规则引擎组件，包括黑名单、访问控制等规则管理功能。
 *
 * 设计原理：
 * - 规则抽象：将访问控制、安全过滤等规则抽象为统一的规则接口；
 * - 高性能匹配：使用高效的数据结构和算法实现快速规则匹配；
 * - 线程安全：规则查询操作设计为线程安全，支持多线程并发访问。
 *
 * 包含组件：
 * - 黑名单：`blacklist` - 基于 `IP` 和域名的黑名单管理；
 * - 配置管理：`config` - 规则引擎配置结构；
 * - 规则链：未来可扩展规则链和组合规则。
 *
 * 使用准则：
 * - 规则匹配应在热路径中保持高效，避免复杂计算；
 * - 规则更新应支持热重载，无需重启服务；
 * - 规则引擎应提供详细的匹配日志，便于调试和审计。
 *
 * @note 规则引擎应保持无状态，规则数据通过配置加载。
 * @warning 规则匹配可能影响性能，应避免过于复杂的规则逻辑。
 *
 * ngx::rule::blacklist
 * ngx::rule::config
 */
namespace ngx::rule
{
    /**
     * @class blacklist
     * @brief 黑名单管理类
     * @details 管理 `IP` 地址和域名的黑名单，提供高效的查询接口。
     * 该类使用透明哈希和相等比较器优化查询性能，支持域名后缀匹配。
     *
     * 设计原则：
     * 1. 透明查找：使用 `transparent_string_hash` 和 `transparent_string_equal` 支持 `std::string_view` 查找；
     * 2. 后缀匹配：域名匹配支持后缀匹配，黑名单条目可匹配所有子域名；
     * 3. 线程安全：查询操作线程安全，修改操作需外部同步。
     *
     * 数据结构：
     * - `ips_`：`std::unordered_set` 存储 `IP` 地址黑名单；
     * - `domains_`：`std::unordered_set` 存储域名后缀黑名单。
     *
     * 性能特性：
     * - `IP` 匹配：精确匹配，`O(1)` 平均时间复杂度；
     * - 域名匹配：后缀匹配，`O(n)` 时间复杂度（`n` 为域名标签数）；
     * - 内存效率：使用透明哈希避免临时字符串分配。
     *
     * 使用示例：
     * ```
     * // 创建黑名单实例
     * ngx::rule::blacklist bl;
     *
     * // 批量加载黑名单数据
     * bl.load({"192.168.1.1", "10.0.0.1"}, {"malware.com", "phishing.org"});
     *
     * // 检查匹配
     * if (bl.endpoint("192.168.1.1")) {
     *     spdlog::warn("拒绝黑名单 IP 访问");
     * }
     *
     * if (bl.domain("download.malware.com")) {
     *     spdlog::warn("拒绝黑名单域名访问");
     * }
     *
     * // 动态更新
     * bl.insert_domain("new-threat.net");
     * bl.insert_endpoint("203.0.113.5");
     *
     * // 清空黑名单
     * bl.clear();
     *
     *
     * @note 黑名单数据应定期更新，以应对新的安全威胁。
     * @warning 域名后缀匹配可能产生误报，如 `"example.com"` 会匹配 `"evil.example.com"`。
     * @warning 修改操作不是线程安全的，多线程环境下需使用锁或其他同步机制。
     *
     * transparent_string_hash
     * transparent_string_equal
     * std::unordered_set
     */
    class blacklist
    {
    public:
        /**
         * @brief 默认构造函数
         */
        blacklist() = default;

        /**
         * @brief 加载黑名单数据
         * @param ips IP 黑名单列表
         * @param domains 域名黑名单列表
         * @details 通常在程序启动或热加载时调用。
         */
        void load(const std::vector<std::string> &ips, const std::vector<std::string> &domains);

        /**
         * @brief 检查端点（IP）是否在黑名单中
         * @param endpoint_value 待检查的 IP 地址字符串
         * @return true 如果在黑名单中，false 否则
         */
        bool endpoint(std::string_view endpoint_value) const;

        /**
         * @brief 检查域名是否在黑名单中
         * @param host_value 待检查的域名
         * @return true 如果域名或其后缀在黑名单中，false 否则
         * @details 支持子域名后缀匹配。例如：黑名单有 "baidu.com"，那么 "map.baidu.com" 也会被屏蔽。
         */
        bool domain(std::string_view host_value) const;

        /**
         * @brief 插入单个域名到黑名单
         * @param domain 待插入的域名
         */
        void insert_domain(std::string_view domain);

        /**
         * @brief 插入单个端点（IP）到黑名单
         * @param endpoint_value 待插入的 IP 地址
         * @note 插入操作会触发哈希表重哈希，可能影响性能。
         * @warning 插入重复的 IP 地址不会抛出异常，但会浪费空间。
         * @warning 插入操作不是线程安全的，需外部同步。
         */
        void insert_endpoint(std::string &endpoint_value);

        /**
         * @brief 清空黑名单
         */
        void clear();

    private:
        std::unordered_set<std::string, transparent_string_hash, transparent_string_equal> ips_;     // IP 黑名单集合
        std::unordered_set<std::string, transparent_string_hash, transparent_string_equal> domains_; // 域名黑名单集合
    };

}