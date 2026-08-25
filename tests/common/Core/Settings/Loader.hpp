/**
 * @file loader.hpp
 * @brief 配置加载与校验（T5-9）
 * @details JSON 配置 → 配置结构：
 *          - 必填字段缺失 → 校验失败
 *          - 类型错误 / 范围非法 → 校验失败
 *          - 未知字段忽略（向前兼容）
 * @note 自包含（Settings::json）；生产用 glaze loader
 */

#pragma once

#include <cstdint>
#include <string>

#include <common/Core/Settings/Json.hpp>

namespace Preview::Settings
{

    /**
     * @struct ConfigError
     * @brief 配置错误
     */
    struct ConfigError
    {
        std::string field{}; ///< 出错字段路径
        std::string Message{}; ///< 错误描述
    };

    /**
     * @struct ProxyConfig
     * @brief 代理配置（T5-9 示例结构）
     */
    struct ProxyConfig
    {
        std::string ListenAddr{"127.0.0.1"}; ///< 监听地址
        std::uint16_t ListenPort{0};         ///< 监听端口
        std::string Protocol{"socks5"};       ///< 入站协议
        std::uint32_t MaxConnections{1024};  ///< 最大连接数（0 = 无限制）
        bool AuthRequired{false};            ///< 是否强制认证
        std::uint64_t IdleTimeoutMs{60000}; ///< 空闲超时（毫秒）
    };

    /**
     * @brief 加载并校验配置
     * @param json_text JSON 文本
     * @param out 输出配置
     * @return 空 = 成功；否则 ConfigError
     */
    [[nodiscard]] inline auto LoadConfig(std::string_view json_text, ProxyConfig &out)
        -> ConfigError
    {
        JsonValue root;
        const auto jerr = ParseJson(json_text, root);
        if (!jerr.Message.empty())
        {
            return {"<root>", jerr.Message};
        }
        if (root.Data.index() != 5)
        {
            return {"<root>", "expected object"};
        }

        const auto &obj = std::get<JsonObject>(root.Data).members;

        // ListenAddr（可选，字符串）
        if (const auto it = obj.find("ListenAddr"); it != obj.end())
        {
            if (it->second.Data.index() != 3)
            {
                return {"ListenAddr", "expected string"};
            }
            out.ListenAddr = std::get<std::string>(it->second.Data);
            if (out.ListenAddr.empty())
            {
                return {"ListenAddr", "Empty Address"};
            }
        }

        // ListenPort（必填，范围 1-65535）
        const auto PortIt = obj.find("ListenPort");
        if (PortIt == obj.end())
        {
            return {"ListenPort", "missing required field"};
        }
        if (PortIt->second.Data.index() != 2)
        {
            return {"ListenPort", "expected number"};
        }
        const auto port = std::get<double>(PortIt->second.Data);
        if (port < 1 || port > 65535)
        {
            return {"ListenPort", "out of range [1, 65535]"};
        }
        out.ListenPort = static_cast<std::uint16_t>(port);

        // Protocol（可选，字符串，枚举校验）
        if (const auto it = obj.find("Protocol"); it != obj.end())
        {
            if (it->second.Data.index() != 3)
            {
                return {"Protocol", "expected string"};
            }
            const auto &proto = std::get<std::string>(it->second.Data);
            if (proto != "socks5" && proto != "http" && proto != "trojan")
            {
                return {"Protocol", "unsupported Protocol"};
            }
            out.Protocol = proto;
        }

        // MaxConnections（可选，非负整数）
        if (const auto it = obj.find("MaxConnections"); it != obj.end())
        {
            if (it->second.Data.index() != 2)
            {
                return {"MaxConnections", "expected number"};
            }
            const auto mc = std::get<double>(it->second.Data);
            if (mc < 0 || mc > 0xFFFFFFFFULL)
            {
                return {"MaxConnections", "out of range"};
            }
            out.MaxConnections = static_cast<std::uint32_t>(mc);
        }

        // AuthRequired（可选，布尔）
        if (const auto it = obj.find("AuthRequired"); it != obj.end())
        {
            if (it->second.Data.index() != 1)
            {
                return {"AuthRequired", "expected bool"};
            }
            out.AuthRequired = std::get<bool>(it->second.Data);
        }

        // IdleTimeoutMs（可选，非负）
        if (const auto it = obj.find("IdleTimeoutMs"); it != obj.end())
        {
            if (it->second.Data.index() != 2)
            {
                return {"IdleTimeoutMs", "expected number"};
            }
            const auto to = std::get<double>(it->second.Data);
            if (to < 0)
            {
                return {"IdleTimeoutMs", "negative"};
            }
            out.IdleTimeoutMs = static_cast<std::uint64_t>(to);
        }

        return {};
    }

} // namespace Preview::Settings
