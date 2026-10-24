/**
 * @file Conn.hpp
 * @brief HTTP/1.1 入站代理握手连接
 * @details 服务端：读头 → 解析 →（可选认证）→ 400/407；CONNECT 的
 *          200/502 响应由拨号后的 handler 发送
 *          - ReadRequest：读完整请求头（65536 上限防慢速 OOM）
 *          - SendResponse：标准响应（200/400/407/502）
 *          客户端：SendConnect / ReadResponse（状态码验证）
 * @note HTTP CONNECT 握手与隧道交接由当前 Prism HTTP/1.1 carrier 实现。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Http1/Parser.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11
{

    namespace Net = boost::asio;

    /**
     * @brief 标准响应（无 body）
     */
    namespace Status
    {
        constexpr std::string_view Ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        constexpr std::string_view BadRequest = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        constexpr std::string_view ProxyAuthRequired = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                                         "Proxy-Authenticate: Basic\r\n"
                                                         "Content-Length: 0\r\n"
                                                         "\r\n";
        constexpr std::string_view BadGateway = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    } // namespace Status

    /**
     * @brief 向 HTTP 客户端发送完整响应
     * @param Transport 客户端侧传输
     * @param Body 完整响应字节
     * @return 成功或 io_error
     */
    [[nodiscard]] auto SendResponse(SharedTransmission Transport,
                                            std::string_view Body)
        -> Net::awaitable<Fault::Failure>;

    /**
     * @class ServerConn
     * @brief HTTP 入站代理服务端握手连接
     * @details 包装传输层，提供请求读取与响应发送。
     *          握手成功后释放传输层（Release）交由隧道使用。
     */
    class ServerConn
    {
    public:
        /**
         * @brief 构造
         * @param Transport 底层传输
         */
        explicit ServerConn(
            SharedTransmission Transport,
            std::shared_ptr<Prism::Memory::BytePool> Bytes);

        /**
         * @brief 读取并解析完整请求头
         * @param Request 解析结果
         * @return 请求解析状态或原样保留 Native 的读失败。
         * @details 同次结果中的字节先用于完成请求解析；若完整请求头之后已有预读字节，
         *          对应终态会随字节交给 Release/ReleaseForward，并在这些字节耗尽后返回。
         */
        [[nodiscard]] auto ReadRequest(HttpRequest &Request)
            -> Net::awaitable<Fault::Failure>;

        /**
         * @brief 发送标准响应
         * @param Body 响应字节
         * @return 成功或 io_error
         */
        [[nodiscard]] auto SendResponse(std::string_view Body)
            -> Net::awaitable<Fault::Failure>;

        /**
         * @brief 释放传输层（握手成功后交给隧道）
         * @return 底层传输
         */
        [[nodiscard]] auto Release() -> SharedTransmission;

        /**
         * @brief 释放普通 HTTP 请求的转发流
         * @return 先回放 origin-form 请求行、源站头字段和首请求正文的传输
         * @details 普通代理请求的请求头已经被握手读取；认证信息与逐跳字段
         *          在序列化时移除。Content-Length、chunked、无正文请求只消费
         *          首个消息边界；CONNECT 仍由 Release() 保持原始隧道语义。
         */
        [[nodiscard]] auto ReleaseForward() -> SharedTransmission;

    private:
        SharedTransmission Transport_; ///< 底层传输
        std::string Buffer_;            ///< 读缓冲
        std::vector<std::byte> Preread_; ///< 请求头之后已读入的请求体或隧道数据
        Fault::Failure ReadFailure_;    ///< 与握手预读字节同次返回的终态
        HttpRequest Request_{};          ///< 最近一次握手解析结果
        std::size_t Used_{0};            ///< 握手阶段已读取的原始字节数
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
    };

    /**
     * @struct ConnectParameters
     * @brief HTTP/1.1 CONNECT 请求参数
     * @details Transport 的所有权转移给异步请求；字符串字段仅在请求期间借用。
     */
    struct ConnectParameters
    {
        SharedTransmission Transport;
        std::string_view Host;
        std::uint16_t Port;
        std::string_view Authorization;
    };

    /**
     * @brief 客户端发送 CONNECT 请求
     * @param Params CONNECT 请求参数
     * @return 成功或 io_error
     */
    [[nodiscard]] auto SendConnect(ConnectParameters Params)
        -> Net::awaitable<Fault::Code>;

    /**
     * @brief 使用无认证头发送 HTTP/1.1 CONNECT 请求
     * @param Transport 底层传输（所有权移交）
     * @param Host 目标主机
     * @param Port 目标端口
     * @return 成功或 io_error
     */
    [[nodiscard]] auto SendConnect(
        SharedTransmission Transport,
        std::string_view Host,
        std::uint16_t Port) -> Net::awaitable<Fault::Code>;

    /**
     * @brief 客户端读取响应并返回状态码
     * @param Transport 底层传输
     * @param ErrorCode 错误码
     * @return 状态码（0 = 读失败）
     * @details 同次结果中的字节先用于解析响应头；头后预读的响应体字节及其终态由返回传输按序回放。
     */
    [[nodiscard]] auto ReadResponse(
        SharedTransmission &Transport,
        std::error_code &ErrorCode,
        std::shared_ptr<Prism::Memory::BytePool> Bytes) -> Net::awaitable<int>;

} // namespace Prism::Http11
