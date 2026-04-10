/**
 * @file relay.hpp
 * @brief HTTP 代理中继器
 * @details HTTP 代理协议层的核心处理类，封装请求头读取、解析、认证和响应写入。
 * 设计参照 socks5::relay 模式，将协议级逻辑从 pipeline 编排层分离。
 * relay 持有入站传输层的所有权，完成握手后通过 release() 释放传输层供隧道使用。
 * @note relay 不继承 transmission，因为它不是传输装饰器——握手完成后
 * 传输层被释放给 tunnel()，relay 本身仅作为握手阶段的状态持有者。
 */
#pragma once

#include <prism/channel/transport/transmission.hpp>
#include <prism/protocol/http/parser.hpp>
#include <boost/asio.hpp>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace psm::protocol::http
{
    namespace transport = psm::channel::transport;
    namespace net = boost::asio;

    /**
     * @class relay
     * @brief HTTP 代理中继器
     * @details 管理 HTTP 代理请求的完整握手流程：读取请求头、解析请求行和头字段、
     * 执行 Basic 认证（若已配置账户目录）。握手成功后提供响应写入和请求转发能力。
     * 生命周期：由 make_relay 创建 → handshake 完成协议协商 →
     * write_connect_success/forward 执行响应 → release 释放传输层 → 析构。
     * relay 持有的 account::lease 在 relay 析构时自动释放，确保连接计数正确。
     */
    class relay
    {
    public:
        /**
         * @brief 构造 HTTP 代理中继器
         * @param transport 入站传输层（通常经 preview 包装）
         * @param account_directory 账户目录指针，为空时跳过认证
         */
        explicit relay(transport::shared_transmission transport,
                       agent::account::directory *account_directory = nullptr);

        /**
         * @brief 执行 HTTP 代理握手
         * @return 错误码和解析后的代理请求
         * @details 读取完整 HTTP 请求头、解析请求行和头字段、
         * 若配置了账户目录则执行 Basic 认证。认证失败时自动发送 407/403 响应。
         */
        auto handshake() -> net::awaitable<std::pair<fault::code, proxy_request>>;

        /**
         * @brief 发送 200 Connection Established 响应
         * @details 用于 CONNECT 方法成功建连后通知客户端隧道已建立。
         */
        auto write_connect_success() -> net::awaitable<void>;

        /**
         * @brief 发送 502 Bad Gateway 响应
         * @details 用于上游连接失败时通知客户端。
         */
        auto write_bad_gateway() -> net::awaitable<void>;

        /**
         * @brief 转发普通 HTTP 请求到上游
         * @param req 已解析的代理请求
         * @param outbound 上游传输层
         * @param mr PMR 内存资源，用于构建转发请求行
         * @details 将绝对 URI 重写为相对路径，构建新请求行写入上游，
         *          随后写入请求行之后的剩余数据（headers + body）。
         */
        auto forward(const proxy_request &req, transport::shared_transmission outbound,
                     std::pmr::memory_resource *mr) -> net::awaitable<void>;

        /**
         * @brief 释放底层传输层
         * @return 入站传输层的共享指针
         * @details 握手完成后调用，将传输层交给 tunnel() 进行双向转发。
         */
        auto release() -> transport::shared_transmission;

    private:
        transport::shared_transmission transport_;
        agent::account::directory *account_directory_;
        agent::account::lease lease_;
        std::vector<char> buffer_;
        std::size_t used_{0};

        /**
         * @brief 循环读取直到找到 HTTP 头部结束标记
         * @return 读取成功返回 true，读取失败返回 false
         */
        auto read_until_header_end() -> net::awaitable<bool>;

        /**
         * @brief 完整写入字符串数据到传输层
         * @param data 待写入的字符串视图
         */
        auto write_bytes(std::string_view data) -> net::awaitable<void>;
    };

    /**
     * @brief 创建 HTTP 代理中继器
     * @param transport 入站传输层
     * @param account_directory 账户目录指针
     * @return relay 共享指针
     */
    inline auto make_relay(transport::shared_transmission transport,
                           agent::account::directory *account_directory = nullptr)
        -> std::shared_ptr<relay>
    {
        return std::make_shared<relay>(std::move(transport), account_directory);
    }
} // namespace psm::protocol::http
