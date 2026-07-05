/**
 * @file validator.hpp
 * @brief 配置验证器
 * @details 加载配置后进行结构验证，失败抛 exception::security。
 * 验证项覆盖：buffer.size、addressable.port、dns.servers、protocol 各子配置、
 * reverse_map 端点格式、证书文件可读性。
 */
#pragma once

#include <prism/config/config.hpp>
#include <prism/foundation/memory/container.hpp>

#include <string_view>


namespace psm::config_validator
{
    /**
     * @struct validation_result
     * @brief 验证结果
     * @details valid 为 true 表示通过；false 时 errors 列出所有失败项。
     */
    struct validation_result
    {
        bool valid{true};                         ///< 是否通过验证
        memory::vector<memory::string> errors;    ///< 错误描述列表（valid=false 时非空）

        explicit validation_result(memory::resource_pointer mr = memory::current_resource())
            : errors(mr)
        {
        }
    };

    /**
     * @brief 验证配置完整性
     * @param cfg 待验证配置
     * @return 验证结果（含错误列表）
     * @details 检查项：
     *   - buffer.size > 0
     *   - addressable.port > 0
     *   - dns.servers 非空（启用 DNS 时）
     *   - protocol.{socks5,trojan,vless,shadowsocks} 各子配置 enable_tcp/enable_udp 至少一个为 true
     *   - reverse_map 端点 host 可解析为 IP 字面量
     *   - 证书文件路径可读（cert.key/cert.cert 非空时）
     */
    [[nodiscard]] auto validate(const psm::config &cfg) -> validation_result;

    /**
     * @brief 验证并抛异常
     * @param cfg 待验证配置
     * @throws psm::exception::security 验证失败时
     * @details validate() 失败时拼接错误列表抛异常，调用方无需手动检查 valid 字段。
     */
    auto validate_or_throw(const psm::config &cfg) -> void;

} // namespace psm::config_validator
