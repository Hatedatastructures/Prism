/**
 * @file parser.hpp
 * @brief HTTP 代理请求轻量解析器
 * @details 专为代理场景设计的 HTTP 请求头解析模块，仅提取代理转发所需的最少信息：
 * 请求方法、目标地址、Host 头字段和 Proxy-Authorization 头字段。不构建完整的
 * HTTP 消息对象，直接在原始字节上操作，避免不必要的内存分配和数据拷贝。
 * 设计目标包括零堆分配，所有结果以 string_view 指向原始缓冲区，无额外拷贝。
 * 最小化解析，仅提取代理决策所需字段，不处理 body 编码和 chunked 传输。
 * 内存高效，解析过程不分配任何内存，结果结构体仅包含 string_view 和偏移量。
 * @note 解析结果中的 string_view 依赖原始缓冲区的生命周期，缓冲区销毁后不可访问。
 * @warning 该解析器不适用于需要完整 HTTP 消息处理的场景（如 Web 服务器）。
 */
#pragma once

#include <cstddef>
#include <string_view>
#include <prism/fault/code.hpp>
#include <prism/agent/account/entry.hpp>
#include <prism/memory/container.hpp>

namespace psm
{
    namespace agent
    {
        namespace account
        {
            class directory;
        }
    }

    namespace protocol::http
    {
        /**
         * @struct proxy_request
         * @brief HTTP 代理请求解析结果
         * @details 存储从原始 HTTP 请求头中提取的代理转发所需信息。所有字符串字段
         * 以 string_view 形式指向原始缓冲区，不持有数据所有权。代理管道基于这些
         * 信息进行认证、路由和转发决策。
         * @note 字段生命周期与原始缓冲区绑定，原始缓冲区必须在使用期间保持有效。
         */
        struct proxy_request
        {
            /** @brief 请求方法，如 "CONNECT"、"GET"、"POST" */
            std::string_view method;
            /** @brief 请求目标，绝对 URI 或 host:port (CONNECT) */
            std::string_view target;
            /** @brief Host 头字段值 */
            std::string_view host;
            /** @brief Proxy-Authorization 头字段值 */
            std::string_view authorization;
            /** @brief HTTP 版本字符串，如 "HTTP/1.1" */
            std::string_view version;
            /** @brief 请求行末尾 \r\n 之后的偏移量（header 区域起始） */
            std::size_t req_line_end{0};
            /** @brief 完整头部 \r\n\r\n 之后的偏移量（body 区域起始） */
            std::size_t header_end{0};
        };

        /**
         * @brief 解析 HTTP 代理请求头
         * @param raw_data 包含完整 HTTP 请求头的原始数据（须包含 \r\n\r\n）
         * @param out 接收解析结果的代理请求结构体
         * @return 解析状态码
         * @details 从原始字节中提取请求方法、目标地址、Host 和 Proxy-Authorization
         * 头字段。解析过程不分配内存，所有 string_view 直接指向输入缓冲区。
         * 请求行格式为 "METHOD TARGET HTTP/version\r\n"，头字段以 "\r\n\r\n" 结束。
         */
        [[nodiscard]] auto parse_proxy_request(std::string_view raw_data, proxy_request &out)
            -> fault::code;

        /**
         * @brief 从绝对 URI 中提取相对路径
         * @param target 请求目标，可能是绝对 URI 或相对路径
         * @return 相对路径部分。若 target 不是绝对 URI（不以 http:// 或 https://
         * 开头），则原样返回。若绝对 URI 不含路径，返回 "/"。
         * @details 将代理场景中的绝对 URI（如 "http://example.com/path?q=1"）
         * 转换为源站所需的相对路径（如 "/path?q=1"），用于正向代理转发。
         */
        [[nodiscard]] auto extract_relative_path(std::string_view target)
            -> std::string_view;

        /**
         * @struct auth_result
         * @brief HTTP 代理认证结果
         * @details 封装 Basic 代理认证的验证结果。认证成功时持有连接租约，
         * 失败时包含待发送的错误响应。由 authenticate_proxy_request 返回。
         */
        struct auth_result
        {
            /** @brief 认证是否通过 */
            bool authenticated{false};
            /** @brief 失败时待发送的 HTTP 错误响应，认证通过时为空 */
            std::string_view error_response{};
            /** @brief 认证通过时获取的连接租约，空租约表示认证未通过 */
            agent::account::lease lease{};
        };

        /**
         * @brief 验证 HTTP 代理 Basic 认证
         * @param authorization Proxy-Authorization 头字段值
         * @param directory 账户目录引用
         * @return 认证结果，包含是否通过、错误响应和连接租约
         * @details 解码 Base64 凭据，提取密码并计算 SHA224 哈希后查询账户目录。
         * 认证流程：验证 Basic 方案前缀 → Base64 解码 → 提取密码 → SHA224 哈希 →
         * 查询账户目录获取租约。任一步骤失败均返回对应的错误响应。
         * @note 返回的 error_response 指向静态常量字符串，生命周期无限制。
         */
        [[nodiscard]] auto authenticate_proxy_request(
            std::string_view authorization,
            agent::account::directory &directory) -> auth_result;

        /**
         * @brief 构建正向代理转发请求行
         * @param req 已解析的代理请求
         * @param mr PMR 内存资源指针，用于分配返回字符串
         * @return 重写后的请求行字符串，格式为 "METHOD relative-path HTTP/version\r\n"
         * @details 将绝对 URI（如 "http://example.com/path?q=1"）转换为源站所需的
         * 相对路径（如 "/path?q=1"），拼接方法、路径和版本号构成新的请求行。
         * 仅用于普通 HTTP 请求转发，CONNECT 方法无需调用此函数。
         */
        [[nodiscard]] auto build_forward_request_line(const proxy_request &req, std::pmr::memory_resource *mr)
            -> memory::string;

    } // namespace protocol::http
} // namespace psm
