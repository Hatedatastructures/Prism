/**
 * @file loader.hpp
 * @brief 配置加载与校验（T5-9）
 * @details JSON 配置 → 配置结构：
 *          - 必填字段缺失 → 校验失败
 *          - 类型错误 / 范围非法 → 校验失败
 *          - 未知字段忽略（向前兼容）
 * @note 自包含（settings::json）；生产用 glaze loader
 */

#pragma once

#include <cstdint>
#include <string>

#include <common/core/settings/json.hpp>

namespace psmtest::settings
{

    /**
     * @struct config_error
     * @brief 配置错误
     */
    struct config_error
    {
        std::string field{}; ///< 出错字段路径
        std::string message{}; ///< 错误描述
    };

    /**
     * @struct proxy_config
     * @brief 代理配置（T5-9 示例结构）
     */
    struct proxy_config
    {
        std::string listen_addr{"127.0.0.1"}; ///< 监听地址
        std::uint16_t listen_port{0};         ///< 监听端口
        std::string protocol{"socks5"};       ///< 入站协议
        std::uint32_t max_connections{1024};  ///< 最大连接数（0 = 无限制）
        bool auth_required{false};            ///< 是否强制认证
        std::uint64_t idle_timeout_ms{60000}; ///< 空闲超时（毫秒）
    };

    /**
     * @brief 加载并校验配置
     * @param json_text JSON 文本
     * @param out 输出配置
     * @return 空 = 成功；否则 config_error
     */
    [[nodiscard]] inline auto load_config(const std::string_view json_text, proxy_config &out)
        -> config_error
    {
        json_value root;
        const auto jerr = parse_json(json_text, root);
        if (!jerr.message.empty())
        {
            return {"<root>", jerr.message};
        }
        if (root.data.index() != 5)
        {
            return {"<root>", "expected object"};
        }

        const auto &obj = std::get<json_object>(root.data).members;

        // listen_addr（可选，字符串）
        if (const auto it = obj.find("listen_addr"); it != obj.end())
        {
            if (it->second.data.index() != 3)
            {
                return {"listen_addr", "expected string"};
            }
            out.listen_addr = std::get<std::string>(it->second.data);
            if (out.listen_addr.empty())
            {
                return {"listen_addr", "empty address"};
            }
        }

        // listen_port（必填，范围 1-65535）
        const auto port_it = obj.find("listen_port");
        if (port_it == obj.end())
        {
            return {"listen_port", "missing required field"};
        }
        if (port_it->second.data.index() != 2)
        {
            return {"listen_port", "expected number"};
        }
        const auto port = std::get<double>(port_it->second.data);
        if (port < 1 || port > 65535)
        {
            return {"listen_port", "out of range [1, 65535]"};
        }
        out.listen_port = static_cast<std::uint16_t>(port);

        // protocol（可选，字符串，枚举校验）
        if (const auto it = obj.find("protocol"); it != obj.end())
        {
            if (it->second.data.index() != 3)
            {
                return {"protocol", "expected string"};
            }
            const auto &proto = std::get<std::string>(it->second.data);
            if (proto != "socks5" && proto != "http" && proto != "trojan")
            {
                return {"protocol", "unsupported protocol"};
            }
            out.protocol = proto;
        }

        // max_connections（可选，非负整数）
        if (const auto it = obj.find("max_connections"); it != obj.end())
        {
            if (it->second.data.index() != 2)
            {
                return {"max_connections", "expected number"};
            }
            const auto mc = std::get<double>(it->second.data);
            if (mc < 0 || mc > 0xFFFFFFFFULL)
            {
                return {"max_connections", "out of range"};
            }
            out.max_connections = static_cast<std::uint32_t>(mc);
        }

        // auth_required（可选，布尔）
        if (const auto it = obj.find("auth_required"); it != obj.end())
        {
            if (it->second.data.index() != 1)
            {
                return {"auth_required", "expected bool"};
            }
            out.auth_required = std::get<bool>(it->second.data);
        }

        // idle_timeout_ms（可选，非负）
        if (const auto it = obj.find("idle_timeout_ms"); it != obj.end())
        {
            if (it->second.data.index() != 2)
            {
                return {"idle_timeout_ms", "expected number"};
            }
            const auto to = std::get<double>(it->second.data);
            if (to < 0)
            {
                return {"idle_timeout_ms", "negative"};
            }
            out.idle_timeout_ms = static_cast<std::uint64_t>(to);
        }

        return {};
    }

} // namespace psmtest::settings
