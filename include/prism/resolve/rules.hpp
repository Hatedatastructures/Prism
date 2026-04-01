/**
 * @file rules.hpp
 * @brief DNS 域名规则引擎
 * @details 提供基于反转域名基数树（trie）的高效域名规则匹配系统。
 * 支持精确匹配、通配符匹配和后缀匹配三种模式，用于实现静态地址
 * 解析、广告屏蔽（否定规则）和 CNAME 重定向等 DNS 规则功能。
 *
 * 模块组成：
 * @details - rule_result：规则匹配结果，包含静态地址、CNAME 目标和拦截标记；
 * @details - domain_trie：反转域名基数树，支持通配符和后缀匹配；
 * @details - rules_engine：规则引擎，整合地址规则和 CNAME 规则的统一匹配接口。
 *
 * 设计原理：
 * @details - 反转存储：域名标签按 "com → example → www" 顺序存储，使后缀匹配
 *   等价于前缀遍历，大幅提升匹配效率；
 * @details - 通配符折叠： "*.example.com" 在 "example" 节点标记 wildcard，
 *   搜索时回溯检查即可，无需枚举子域；
 * @details - PMR 内存管理：所有容器使用 memory:: 命名空间类型，支持运行时内存资源切换。
 */
#pragma once

#include <any>
#include <memory>
#include <optional>
#include <string_view>

#include <boost/asio.hpp>

#include <prism/memory/container.hpp>
#include <prism/trace.hpp>

namespace psm::resolve
{
    namespace net = boost::asio;

    /**
     * @struct rule_result
     * @brief 域名规则匹配结果。
     * @details 封装一次规则匹配的全部产出信息。根据命中的规则类型，
     * 各字段具有不同的语义：地址规则填充 addresses，否定规则设置
     * negative 和 blocked 标记，CNAME 规则填充 cname 字段。
     * 未命中的字段保持默认值。
     */
    struct rule_result
    {
        memory::vector<net::ip::address> addresses; // 静态地址列表
        memory::string cname;                       // CNAME 目标域名
        bool negative{false};                       // 否定规则（广告屏蔽）
        bool no_cache{false};                       // 跳过缓存
        bool blocked{false};                        // 被拦截

        /**
         * @brief 构造规则匹配结果。
         * @param mr 内存资源，用于内部容器分配。
         */
        explicit rule_result(memory::resource_pointer mr = memory::current_resource())
            : addresses(mr), cname(mr)
        {
        }
    };

    /**
     * @class domain_trie
     * @brief 反转域名基数树。
     * @details 使用反转域名标签作为存储结构，将域名后缀匹配转化为
     * 树的前缀遍历问题。例如 "www.example.com" 被拆分为标签
     * ["com", "example", "www"]，沿树逐级查找。支持通配符规则
     * "*.example.com"，在 "example" 节点标记 wildcard 标志，
     * 搜索时若精确路径不存在，回溯检查沿途节点的 wildcard 标志
     * 实现通配符匹配。通配符要求至少匹配一级子域，即
     * "*.example.com" 匹配 "www.example.com" 但不匹配 "example.com"。
     * @note 所有操作使用 PMR 分配器，不直接依赖全局堆。
     */
    class domain_trie
    {
    public:
        /**
         * @struct node
         * @brief 基数树节点。
         * @details 每个节点存储一组子标签映射和可选的规则值。
         * children 按标签字符串索引子节点，value 保存命中时
         * 返回的任意类型数据，is_end 标记当前节点是否对应
         * 一条完整规则的终点，wildcard 标记当前节点是否
         * 代表通配符规则。
         */
        struct node
        {
            memory::unordered_map<memory::string, std::unique_ptr<node>> children;
            std::any value;
            bool is_end{false};
            bool wildcard{false};

            explicit node(memory::resource_pointer mr)
                : children(mr)
            {
            }
        };

        /**
         * @brief 构造反转域名基数树。
         * @param mr 内存资源，用于内部节点和标签分配。
         */
        explicit domain_trie(memory::resource_pointer mr = memory::current_resource())
            : root_(std::make_unique<node>(mr)), mr_(mr)
        {
        }

        /**
         * @brief 插入域名规则。
         * @param domain 域名字符串，支持通配符前缀 "*."。
         * @param value 规则关联的任意类型数据。
         * @details 对域名进行标签分割和反转后沿树逐级创建节点。
         * 若域名以 "*." 开头，去掉 "*" 后在倒数第二个标签节点
         * 标记 wildcard=true，表示该节点下的所有子域均匹配此规则。
         */
        void insert(std::string_view domain, const std::any &value);

        /**
         * @brief 精确 + 通配符匹配域名。
         * @param domain 待匹配的域名。
         * @return 匹配成功时返回关联值，否则返回 std::nullopt。
         * @details 首先尝试沿反转标签路径精确匹配到终点节点。
         * 若精确路径不完整，回溯检查沿途节点的 wildcard 标志，
         * 通配符要求查询域名至少比通配符域名多一级标签。
         */
        [[nodiscard]] auto search(std::string_view domain) const -> std::optional<std::any>;

        /**
         * @brief 检查域名是否命中任何规则。
         * @param domain 待检查的域名。
         * @return 命中返回 true，否则返回 false。
         */
        [[nodiscard]] auto match(std::string_view domain) const -> bool;

    private:
        /**
         * @brief 将域名分割为标签并反转顺序。
         * @param domain 原始域名，如 "www.example.com"。
         * @return 反转后的标签列表，如 ["com", "example", "www"]。
         */
        [[nodiscard]] static auto split_labels(std::string_view domain) -> memory::vector<memory::string>;

        /**
         * @brief 将字符串转换为小写。
         * @param s 输入字符串视图。
         * @return 小写字符串。
         */
        [[nodiscard]] static auto to_lower(std::string_view s) -> memory::string;

        std::unique_ptr<node> root_;  // 根节点
        memory::resource_pointer mr_; // 内存资源
    };

    /**
     * @class rules_engine
     * @brief DNS 域名规则引擎。
     * @details 整合地址规则和 CNAME 规则两棵独立的基数树，提供统一的
     * 域名匹配接口。地址规则支持静态 IP 地址映射和否定规则（广告屏蔽），
     * CNAME 规则支持域名重定向。匹配时先查找地址规则，再查找 CNAME 规则，
     * 两者结果合并后返回。
     */
    class rules_engine
    {
    public:
        /**
         * @brief 构造规则引擎。
         * @param mr 内存资源，用于内部树结构和结果分配。
         */
        explicit rules_engine(memory::resource_pointer mr = memory::current_resource())
            : address_trie_(mr), cname_trie_(mr), mr_(mr)
        {
        }

        /**
         * @brief 添加静态地址规则。
         * @param domain 匹配的域名，支持通配符。
         * @param ips 该域名映射的静态 IP 地址列表。
         */
        void add_address_rule(std::string_view domain, const memory::vector<net::ip::address> &ips);

        /**
         * @brief 添加否定规则（广告屏蔽）。
         * @param domain 需要屏蔽的域名，支持通配符。
         * @details 匹配到否定规则时，rule_result 的 negative 和
         * blocked 标记将设置为 true。
         */
        void add_negative_rule(std::string_view domain);

        /**
         * @brief 添加 CNAME 重定向规则。
         * @param domain 源域名，支持通配符。
         * @param target CNAME 目标域名。
         */
        void add_cname_rule(std::string_view domain, std::string_view target);

        /**
         * @brief 匹配域名并返回合并的规则结果。
         * @param domain 待匹配的域名。
         * @return 命中规则时返回 rule_result，未命中返回 std::nullopt。
         * @details 依次在地址树和 CNAME 树中查找域名，合并两者的结果。
         * 地址规则优先级高于 CNAME 规则。
         */
        [[nodiscard]] auto match(std::string_view domain) const -> std::optional<rule_result>;

    private:
        domain_trie address_trie_;    // 地址规则基数树
        domain_trie cname_trie_;      // CNAME 规则基数树
        memory::resource_pointer mr_; // 内存资源
    };
} // namespace psm::resolve
