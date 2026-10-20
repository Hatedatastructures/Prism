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
 * @note Prism 使用 std 容器；缓存参数并入 Config 统一管理。
 */

#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Network::Dns
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

        [[nodiscard]] auto operator()(const std::string_view Value) const noexcept -> std::size_t;
    };

    /**
     * @struct TransparentStringEqual
     * @brief 透明字符串相等比较（配合 TransparentStringHash）
     */
    struct TransparentStringEqual
    {
        using is_transparent = void;

        [[nodiscard]] auto operator()(const std::string_view Left,
                                      const std::string_view Right) const noexcept -> bool
        {
            return Left == Right;
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
        std::uint32_t TimeoutMs{0};          ///< 单次查询超时（0 = 使用 Config.TimeoutMs）
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
        std::size_t MaxIdleConnsPerPool{64};           ///< 每个协议连接池的闲置连接总数上限
        std::size_t MaxFlights{4096};                  ///< 并发 single-flight 上限
        std::size_t MaxWaitersPerFlight{64};           ///< 每个 flight 的等待者上限
    };

    /**
     * @brief 解析上游服务器地址字符串
     * @details 按 scheme 前缀识别协议并填充默认端口：
     *          - 无前缀 / udp:// → Udp，端口 53
     *          - tcp:// → Tcp，端口 53
     *          - tls:// → Tls (DoT)，端口 853
     *          - https:// → Https (DoH)，端口 443
     *          支持 "host:port" 和 "[ipv6]:port" 显式指定端口；
     *          HTTPS 地址还可携带 DoH 路径。
     * @param input 原始地址字符串
     * @return 解析后的 Server 配置；无法识别的输入 Proto 保持 Udp
     */
    [[nodiscard]] auto ParseServer(std::string_view Input) -> Server;

} // namespace Prism::Network::Dns
