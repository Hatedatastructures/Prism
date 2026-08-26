/**
 * @file Loader.hpp
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
     * @param JsonText JSON 文本
     * @param out 输出配置
     * @return 空 = 成功；否则 ConfigError
     */
    [[nodiscard]] inline auto LoadConfig(std::string_view JsonText, ProxyConfig &out)
        -> ConfigError
    {
        JsonValue root;
        const auto Jerr = ParseJson(JsonText, root);
        if (!Jerr.Message.empty())
        {
            return {"<root>", Jerr.Message};
        }
        if (root.Data.index() != 5)
        {
            return {"<root>", "expected object"};
        }

        const auto &obj = std::get<JsonObject>(root.Data).members;

        // ListenAddr（可选，字符串）
        if (const auto It = obj.find("ListenAddr"); It != obj.end())
        {
            if (It->second.Data.index() != 3)
            {
                return {"ListenAddr", "expected string"};
            }
            out.ListenAddr = std::get<std::string>(It->second.Data);
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
        const auto Port = std::get<double>(PortIt->second.Data);
        if (Port < 1 || Port > 65535)
        {
            return {"ListenPort", "out of range [1, 65535]"};
        }
        out.ListenPort = static_cast<std::uint16_t>(Port);

        // Protocol（可选，字符串，枚举校验）
        if (const auto It = obj.find("Protocol"); It != obj.end())
        {
            if (It->second.Data.index() != 3)
            {
                return {"Protocol", "expected string"};
            }
            const auto &proto = std::get<std::string>(It->second.Data);
            if (proto != "socks5" && proto != "http" && proto != "trojan")
            {
                return {"Protocol", "unsupported Protocol"};
            }
            out.Protocol = proto;
        }

        // MaxConnections（可选，非负整数）
        if (const auto It = obj.find("MaxConnections"); It != obj.end())
        {
            if (It->second.Data.index() != 2)
            {
                return {"MaxConnections", "expected number"};
            }
            const auto Mc = std::get<double>(It->second.Data);
            if (Mc < 0 || Mc > 0xFFFFFFFFULL)
            {
                return {"MaxConnections", "out of range"};
            }
            out.MaxConnections = static_cast<std::uint32_t>(Mc);
        }

        // AuthRequired（可选，布尔）
        if (const auto It = obj.find("AuthRequired"); It != obj.end())
        {
            if (It->second.Data.index() != 1)
            {
                return {"AuthRequired", "expected bool"};
            }
            out.AuthRequired = std::get<bool>(It->second.Data);
        }

        // IdleTimeoutMs（可选，非负）
        if (const auto It = obj.find("IdleTimeoutMs"); It != obj.end())
        {
            if (It->second.Data.index() != 2)
            {
                return {"IdleTimeoutMs", "expected number"};
            }
            const auto To = std::get<double>(It->second.Data);
            if (To < 0)
            {
                return {"IdleTimeoutMs", "negative"};
            }
            out.IdleTimeoutMs = static_cast<std::uint64_t>(To);
        }

        return {};
    }

} // namespace Preview::Settings
