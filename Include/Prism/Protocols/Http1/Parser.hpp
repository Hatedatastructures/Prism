/**
 * @file Parser.hpp
 * @brief HTTP/1.1 入站代理请求解析与目标提取
 * @details 自包含 HTTP/1.1 子集：
 *          - ParseRequest：请求行 + 头字段解析（Host / Proxy-Authorization）
 *          - ResolveTarget：解析 CONNECT authority、absolute-form 和 origin-form
 *          - MakeConnectRequest：客户端构造 CONNECT 请求
 *          - ParseStatusCode：响应行状态码提取（客户端验证）
 * @note 解析边界遵循当前 Prism HTTP/1.1 carrier 契约。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Utility/Http/HeaderFields.hpp>

namespace Prism::Http11
{

    /// 最大 HTTP 头部大小（防慢速输入和解析阶段内存增长）
    inline constexpr std::size_t MaxHdrSize = HeaderFields::MaxHeaderBlockBytes;

    /**
     * @struct HttpRequest
     * @brief 解析后的 HTTP 请求（视图，不拷贝正文）
     */
    struct HttpRequest
    {
        std::string_view Method;        ///< 请求方法
        std::string_view Target;        ///< authority、absolute-form 或 origin-form 目标
        std::string_view version;       ///< 版本（HTTP/1.1；保留兼容字段名）
        std::string_view host;          ///< Host 头（保留兼容字段名）
        std::string_view authorization; ///< Proxy-Authorization 头（保留兼容字段名）
        HeaderFields::Parsed Headers;   ///< 头字段视图与逐跳/消息定界元数据
        std::size_t LineEnd{0};        ///< 请求行结束偏移（\r\n 之后）
        std::size_t HdrEnd{0};         ///< 头块结束偏移（\r\n\r\n 之后）
    };

    /// HTTP 代理请求目标的请求形态
    enum class RequestForm : std::uint8_t
    {
        Connect,
        Absolute,
        Origin,
    };

    /**
     * @struct ProxyTarget
     * @brief HTTP 入站代理解析后的拨号目标
     */
    struct ProxyTarget
    {
        std::string Host;
        std::uint16_t Port{0};
        RequestForm Form{RequestForm::Origin};
    };

    /**
     * @brief 解析 HTTP 请求
     * @param Raw 原始数据（含请求行 + 头块）
     * @param Request 解析结果
     * @return 成功或 parse_error
     */
    [[nodiscard]] auto ParseRequest(
        std::string_view Raw,
        HttpRequest &Request) -> Fault::Code;


    /**
     * @brief 解析 HTTP 入站代理请求的拨号目标
     * @param Request 已解析的请求
     * @return 目标和请求形态；格式非法时为空
     */
    [[nodiscard]] auto ResolveTarget(const HttpRequest &Request)
        -> std::optional<ProxyTarget>;


    /**
     * @brief 构造 CONNECT 请求
     * @param Host 目标主机
     * @param Port 目标端口
     * @param Authorization Basic 凭据（可选，为空则不含该头）
     * @return 完整请求字节串
     */
    [[nodiscard]] auto MakeConnectRequest(
        std::string_view Host,
        const std::uint16_t Port,
        const std::string_view Authorization = {}) -> std::string;

    /**
     * @brief 提取响应行状态码
     * @param Raw 响应头数据
     * @return 状态码（解析失败返回 0）
     */
    [[nodiscard]] auto ParseStatusCode(std::string_view Raw) -> int;


} // namespace Prism::Http11
