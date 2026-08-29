/**
 * @file Config.hpp
 * @brief DNS 解析器配置层
 * @details 定义 DNS 解析器的全部配置类型，对齐主项目 net/dns/config.hpp 分层：
 *          - 上游服务器配置（Protocol 枚举 + Server 结构）
 *          - 查询调度策略（Mode 枚举）
 *          - 域名规则（AddressRule 地址映射 / CnameRule CNAME 重定向）
 *          - 主配置结构体 Config，聚合所有子配置
 *          地址解析规则与主项目一致：无 scheme 前缀默认 UDP；tcp:// 使用 TCP；
 *          tls:// 使用 TLS (DoT, 默认端口 853)；https:// 使用 HTTPS (DoH, 默认端口 443)。
 * @note Preview 风格：std 容器、header-only；缓存参数并入 Config 统一管理
 */

#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace Preview::Network::Dns
{

    /**
     * @struct TransparentStringHash
     * @brief 透明字符串哈希（FNV-1a）
     * @details is_transparent 启用 unordered_map 异构查找：可用 string_view
     *          直接查找而无需构造临时 string 键
     */
    struct TransparentStringHash
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(const std::string_view value) const noexcept -> std::size_t
        {
            std::size_t Hash = 14695981039346656037ull;
            for (const auto ch : value)
            {
                Hash ^= static_cast<std::uint8_t>(ch);
                Hash *= 1099511628211ull;
            }
            return Hash;
        }
    };

    /**
     * @struct TransparentStringEqual
     * @brief 透明字符串相等比较（配合 TransparentStringHash）
     */
    struct TransparentStringEqual
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(const std::string_view left,
                                      const std::string_view right) const noexcept -> bool
        {
            return left == right;
        }
    };

    /**
     * @enum StalePolicy
     * @brief 缓存过期条目处理策略
     */
    enum class StalePolicy : std::uint8_t
    {
        Discard, ///< 过期即丢弃（返回未命中并擦除条目）
        Serve,   ///< 过期仍返回旧数据（serve-stale 兜底）
    };

    /**
     * @enum Protocol
     * @brief DNS 上游服务器协议类型
     */
    enum class Protocol : std::uint8_t
    {
        /// 纯 UDP 协议，如 "1.2.3.4" 或 "udp://1.2.3.4"
        Udp,
        /// TCP 协议，如 "tcp://1.2.3.4"
        Tcp,
        /// TLS 协议 (DoT)，默认端口 853
        Tls,
        /// HTTPS 协议 (DoH)，默认端口 443
        Https,
    };

    /**
     * @struct Server
     * @brief DNS 上游服务器配置
     */
    struct Server
    {
        std::string Address;                 ///< 原始地址字符串（不含 scheme 与端口）
        Protocol Proto{Protocol::Udp};       ///< 通信协议
        std::string Hostname;                ///< TLS SNI / HTTP Host 头
        std::uint16_t Port{53};              ///< 服务端口
        std::uint32_t TimeoutMs{5000};       ///< 单次查询超时（毫秒）
        std::string HttpPath{"/dns-query"};  ///< DoH 查询路径
        bool SkipCertCheck{false};           ///< 跳过 TLS 证书验证
        bool KeepAlive{true};                ///< 连接复用（false = 每查询新建，不入池）
    };

    /**
     * @enum Mode
     * @brief 多上游查询调度策略
     */
    enum class Mode : std::uint8_t
    {
        /// 并发查询所有上游，选择 RTT 最低的成功响应
        Fastest,
        /// 并发查询所有上游，返回首个成功响应
        First,
        /// 按顺序尝试上游，前一个失败后尝试下一个
        Fallback,
    };

    /**
     * @struct AddressRule
     * @brief DNS 地址映射规则
     * @details 将特定域名映射到预定义 IP 列表；支持通配符 "*.example.com"。
     *          Negative 为 true 时该域名返回否定应答（广告拦截场景）。
     */
    struct AddressRule
    {
        std::string Domain;                        ///< 匹配域名，支持通配符 *.xxx.com
        std::vector<boost::asio::ip::address> Addresses; ///< 映射的地址列表
        bool Negative{false};                      ///< 否定应答（NXDOMAIN）
    };

    /**
     * @struct CnameRule
     * @brief DNS CNAME 重定向规则
     */
    struct CnameRule
    {
        std::string Domain; ///< 源域名
        std::string Target; ///< CNAME 目标域名
    };

    /**
     * @struct Config
     * @brief DNS 解析器主配置
     * @details 聚合上游列表、查询策略、域名规则、黑名单与缓存参数。
     *          Servers 为空时 Resolver 回退到操作系统 resolver（bootstrap 行为）。
     */
    struct Config
    {
        std::vector<Server> Servers;                   ///< 上游服务器列表
        Mode QueryMode{Mode::Fastest};                 ///< 多上游调度策略
        std::vector<AddressRule> AddressRules;         ///< 地址映射规则
        std::vector<CnameRule> CnameRules;             ///< CNAME 重定向规则
        std::vector<boost::asio::ip::address> AddressBlacklist; ///< IP 黑名单（精确地址）
        std::vector<boost::asio::ip::network_v4> BlacklistV4;   ///< IPv4 黑名单网段（CIDR）
        std::vector<boost::asio::ip::network_v6> BlacklistV6;   ///< IPv6 黑名单网段（CIDR）

        bool CacheEnabled{true};                       ///< 是否启用结果缓存
        bool DisableIpv6{false};                       ///< 禁用 IPv6（AAAA）查询
        bool NegativeOnTimeout{true};                  ///< 查询超时是否进负缓存（false = 超时可立即重试）
        std::size_t MaxCacheEntries{10000};            ///< 缓存最大条目数（0 = 禁用淘汰上限）

        std::chrono::seconds CacheTtl{120};            ///< 默认缓存 TTL（上游未给出时）
        std::chrono::seconds NegativeTtl{30};          ///< 负缓存 TTL
        StalePolicy CachePolicy{StalePolicy::Discard}; ///< 过期缓存策略（serve-stale 开关）
        std::uint32_t TtlMin{0};                       ///< 缓存 TTL 下限钳制（秒）
        std::uint32_t TtlMax{86400};                   ///< 缓存 TTL 上限钳制（秒）
        std::uint32_t TimeoutMs{4000};                 ///< 默认查询超时（毫秒）
        std::size_t MaxConnsPerServer{4};              ///< 每服务器最大闲置连接数（0 = 禁用池）
    };

    /**
     * @brief 解析上游服务器地址字符串
     * @details 按 scheme 前缀识别协议并填充默认端口：
     *          - 无前缀 / udp:// → Udp，端口 53
     *          - tcp:// → Tcp，端口 53
     *          - tls:// → Tls (DoT)，端口 853
     *          - https:// → Https (DoH)，端口 443
     *          支持 "host:port" 显式指定端口覆盖默认值。
     * @param input 原始地址字符串
     * @return 解析后的 Server 配置；无法识别的输入 Proto 保持 Udp
     */
    [[nodiscard]] inline auto ParseServer(std::string_view input) -> Server
    {
        Server s;
        s.Address = std::string(input);

        struct SchemeMapping
        {
            std::string_view Prefix;
            Protocol Proto;
            std::uint16_t DefaultPort;
        };
        static constexpr SchemeMapping Mappings[] = {
            {"udp://", Protocol::Udp, 53}, {"tcp://", Protocol::Tcp, 53},
            {"tls://", Protocol::Tls, 853}, {"https://", Protocol::Https, 443},
        };

        for (const auto &m : Mappings)
        {
            if (!input.starts_with(m.Prefix))
            {
                continue;
            }
            s.Proto = m.Proto;
            s.Port = m.DefaultPort;
            input.remove_prefix(m.Prefix.size());
            break;
        }

        // Hostname 默认与地址一致（IP 直连场景）；域名上游由调用方按需覆写 SNI
        s.Hostname = std::string(input);

        // host:port 形式拆分显式端口（仅处理最后一个冒号，兼容 IPv6 字面量需方括号，
        // Preview 测试场景以 IPv4 为主）；from_chars 零分配、不抛异常，
        // 端口须为 1-5 位纯数字且 ≤65535 才生效，否则按无端口处理
        if (const auto Colon = input.rfind(':');
            Colon != std::string_view::npos && input.find(']') == std::string_view::npos)
        {
            const auto PortStr = input.substr(Colon + 1);
            std::uint32_t PortValue = 0;
            const auto Parsed = std::from_chars(PortStr.data(), PortStr.data() + PortStr.size(), PortValue);
            if (!PortStr.empty() && PortStr.size() <= 5 &&
                Parsed.ec == std::errc{} && PortValue <= 65535)
            {
                s.Address = std::string(input.substr(0, Colon));
                s.Hostname = s.Address;
                s.Port = static_cast<std::uint16_t>(PortValue);
            }
        }
        return s;
    }

} // namespace Preview::Network::Dns
