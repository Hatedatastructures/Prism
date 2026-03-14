/**
 * @file blacklist.hpp
 * @brief 黑名单管理
 * @details 提供基于 IP 地址和域名的黑名单匹配功能，支持精确 IP
 * 匹配和域名后缀匹配。作为 ForwardEngine 规则引擎的核心组件，
 * 用于实现访问控制和安全过滤。设计原理包括透明哈希和后缀匹配。
 * 透明哈希使用透明哈希和相等比较器，支持 std::string_view 直接
 * 查找 std::string，避免临时字符串构造。后缀匹配方面，域名匹配
 * 支持后缀匹配，黑名单中的 baidu.com 会匹配 www.baidu.com 和
 * map.baidu.com。线程安全方面，黑名单查询是只读操作线程安全，
 * 修改操作需外部同步。数据结构方面，IP 黑名单使用 unordered_set
 * 存储精确 IP 地址，域名黑名单使用 unordered_set 存储域名后缀。
 * 匹配算法方面，IP 匹配采用精确匹配 IP 地址字符串，域名匹配从
 * 完整域名逐级剥离子域名进行后缀匹配。性能考虑方面，使用透明
 * 哈希避免查询时的临时 std::string 分配提升热路径性能，域名后缀
 * 匹配时间复杂度 O(n) 其中 n 为域名标签数，哈希表查找平均时间
 * 复杂度 O(1) 最坏情况 O(n)。使用场景包括访问控制、安全过滤和
 * 流量管理。
 * @note 黑名单数据通常在系统启动时加载，运行时可通过 insert_*
 * 方法动态更新。
 * @warning 域名后缀匹配可能导致误判，如 example.com 会匹配
 * bad.example.com。
 * @warning 修改操作（load、insert_*、clear）不是线程安全的，
 * 需外部同步。
 */
#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

/**
 * @struct transparent_string_hash
 * @brief 透明字符串哈希函数
 * @details 提供透明哈希支持，允许使用 std::string_view 直接查找
 * 存储在 unordered_set 中的 std::string。设计原理包括透明哈希、
 * 避免分配和性能优化。透明哈希通过 is_transparent 类型别名标记
 * 为透明哈希函数。避免分配方面，使用 std::string_view 哈希避免
 * 构造临时 std::string 对象。性能优化方面，减少热路径中的内存
 * 分配和字符串复制。重载说明包括 operator()(const string_view)
 * 计算 string_view 的哈希值，operator()(const string&) 计算
 * string 的哈希值（转换为 string_view）。
 * @note 透明哈希是 C++14 引入的特性，要求哈希函数支持异构查找。
 * @warning 哈希函数必须保证对于相同的字符串内容，无论类型如何
 * 都返回相同的哈希值。
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
 * @details 提供透明相等比较支持，允许 std::string_view 与
 * std::string 直接比较，无需类型转换。设计原理包括透明比较、
 * 类型混合和性能优化。透明比较通过 is_transparent 类型别名标记
 * 为透明比较器。类型混合方面，支持 std::string 与
 * std::string_view 的任意组合比较。性能优化方面，避免构造临时
 * std::string 对象，减少内存分配。重载说明包括四个 operator()
 * 重载，分别支持 string_view 与 string_view 比较、string 与
 * string_view 比较、string_view 与 string 比较、string 与
 * string 比较。
 * @note 透明比较器是 C++14 引入的特性，要求比较器支持异构查找。
 * @warning 比较器必须保证对于相同的字符串内容，无论类型如何都
 * 返回相同的比较结果。
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
 * @details 定义了 ForwardEngine 的规则引擎组件，包括黑名单、访问
 * 控制等规则管理功能。设计原理包括规则抽象、高性能匹配和线程
 * 安全。规则抽象将访问控制、安全过滤等规则抽象为统一的规则接口。
 * 高性能匹配使用高效的数据结构和算法实现快速规则匹配。线程安全
 * 方面，规则查询操作设计为线程安全，支持多线程并发访问。包含
 * 组件包括黑名单 blacklist 基于 IP 和域名的黑名单管理，配置管理
 * config 规则引擎配置结构，规则链为未来可扩展规则链和组合规则。
 * 使用准则方面，规则匹配应在热路径中保持高效避免复杂计算，规则
 * 更新应支持热重载无需重启服务，规则引擎应提供详细的匹配日志
 * 便于调试和审计。
 * @note 规则引擎应保持无状态，规则数据通过配置加载。
 * @warning 规则匹配可能影响性能，应避免过于复杂的规则逻辑。
 */
namespace ngx::rule
{
    /**
     * @class blacklist
     * @brief 黑名单管理类
     * @details 管理 IP 地址和域名的黑名单，提供高效的查询接口。
     * 该类使用透明哈希和相等比较器优化查询性能，支持域名后缀匹配。
     * 设计原则包括透明查找、后缀匹配和线程安全。透明查找使用
     * transparent_string_hash 和 transparent_string_equal 支持
     * std::string_view 查找。后缀匹配方面，域名匹配支持后缀匹配，
     * 黑名单条目可匹配所有子域名。线程安全方面，查询操作线程安全，
     * 修改操作需外部同步。数据结构方面，ips_ 使用 unordered_set
     * 存储 IP 地址黑名单，domains_ 使用 unordered_set 存储域名
     * 后缀黑名单。性能特性方面，IP 匹配为精确匹配 O(1) 平均时间
     * 复杂度，域名匹配为后缀匹配 O(n) 时间复杂度其中 n 为域名
     * 标签数，内存效率使用透明哈希避免临时字符串分配。
     * @note 黑名单数据应定期更新，以应对新的安全威胁。
     * @warning 域名后缀匹配可能产生误报，如 example.com 会匹配
     * evil.example.com。
     * @warning 修改操作不是线程安全的，多线程环境下需使用锁或
     * 其他同步机制。
     */
    class blacklist
    {
    public:
        /**
         * @brief 默认构造函数
         * @details 构造一个空的黑名单实例。
         */
        blacklist() = default;

        /**
         * @brief 加载黑名单数据
         * @param ips IP 黑名单列表
         * @param domains 域名黑名单列表
         * @details 批量加载 IP 地址和域名到黑名单中，通常在程序
         * 启动或热加载时调用。调用此方法会清空现有黑名单数据。
         */
        void load(const std::vector<std::string> &ips, const std::vector<std::string> &domains);

        /**
         * @brief 检查端点是否在黑名单中
         * @param endpoint_value 待检查的 IP 地址字符串
         * @return 如果在黑名单中返回 true，否则返回 false
         * @details 使用精确匹配算法检查 IP 地址是否存在于黑名单中。
         */
        bool endpoint(std::string_view endpoint_value) const;

        /**
         * @brief 检查域名是否在黑名单中
         * @param host_value 待检查的域名
         * @return 如果域名或其后缀在黑名单中返回 true，否则返回 false
         * @details 支持子域名后缀匹配。例如黑名单中有 baidu.com，
         * 那么 map.baidu.com 也会被匹配。匹配算法从完整域名逐级
         * 剥离子域名进行后缀匹配。
         */
        bool domain(std::string_view host_value) const;

        /**
         * @brief 插入单个域名到黑名单
         * @param domain 待插入的域名
         * @details 将域名添加到黑名单中，支持后续的后缀匹配查询。
         */
        void insert_domain(std::string_view domain);

        /**
         * @brief 插入单个端点到黑名单
         * @param endpoint_value 待插入的 IP 地址
         * @details 将 IP 地址添加到黑名单中，支持后续的精确匹配查询。
         * @note 插入操作会触发哈希表重哈希，可能影响性能。
         * @warning 插入重复的 IP 地址不会抛出异常，但会浪费空间。
         * @warning 插入操作不是线程安全的，需外部同步。
         */
        void insert_endpoint(std::string &endpoint_value);

        /**
         * @brief 清空黑名单
         * @details 清空所有 IP 地址和域名黑名单数据。
         * @warning 清空操作不是线程安全的，需外部同步。
         */
        void clear();

    private:
        std::unordered_set<std::string, transparent_string_hash, transparent_string_equal> ips_;     // IP 黑名单集合
        std::unordered_set<std::string, transparent_string_hash, transparent_string_equal> domains_; // 域名黑名单集合
    };

}
