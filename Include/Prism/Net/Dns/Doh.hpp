/**
 * @file Doh.hpp
 * @brief DoH 传输的公共配置与连接接口。
 * @details HTTP framing 与 TLS 字节流操作由 Net/Dns owner 编译单元实现。
 */
#pragma once

#include <Prism/Net/Dns/Config.hpp>
#include <Prism/Net/Dns/AttemptDeadline.hpp>
#include <Prism/Net/Dns/Transport.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace Prism::Network::Dns
{
    namespace Net = boost::asio;

    /** @brief DoH 传输构造选项；deadline 由每次操作绝对时刻传入。 */
    struct DohOptions
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Net::ssl::context> Context;
        std::string HttpPath;
        std::string HostHeader;
    };

    namespace Detail
    {
        struct DohState;
    }

    /** @brief DoH 传输；满足 DNS TransportLink 与 PoolableTransport。 */
    class DohTransport
    {
    public:
        explicit DohTransport(DohOptions Options);

        /** @brief 建连；Endpoint、ServerConfig 与绝对 Deadline 在返回 awaitable 前复制。 */
        [[nodiscard]] auto Connect(const Net::ip::tcp::endpoint &Endpoint,
            const Server &ServerConfig, Detail::AttemptDeadline Deadline)
            -> Net::awaitable<boost::system::error_code>;

        /** @brief 发送 HTTP/1.1 POST；DNS wire 借用到写完成，Deadline 按值保存。 */
        [[nodiscard]] auto Send(std::span<const std::uint8_t> Wire,
            Detail::AttemptDeadline Deadline) -> Net::awaitable<boost::system::error_code>;

        /** @brief 读取并校验 HTTP 响应，返回去掉 framing 的 DNS body。 */
        [[nodiscard]] auto Receive(Detail::AttemptDeadline Deadline)
            -> Net::awaitable<EcResult<std::vector<std::uint8_t>>>;

        [[nodiscard]] auto IsOpen() const -> bool;
        auto Close() -> void;

    private:
        std::shared_ptr<Detail::DohState> State_;
    };

    static_assert(TransportLink<DohTransport> && PoolableTransport<DohTransport>);
} // namespace Prism::Network::Dns
