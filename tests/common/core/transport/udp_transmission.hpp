/**
 * @file udp_transmission.hpp
 * @brief UDP 传输（udp::socket 包装为 transmission 接口）
 * @details 将 net::ip::udp::socket 包装为统一传输接口：
 * - async_read_some：接收一个 UDP 数据报（一次一个包，返回载荷字节）
 * - async_write_some：发送一个 UDP 数据报
 * - 叶子节点（next_layer 为 nullptr），供协议 dgram 层装饰（如
 *   SS2022 逐包 AEAD 加密层）
 * @note 与 TCP 流不同：每次读对应一个完整数据报（包边界即读边界）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>

namespace psmtest
{

    /**
     * @class udp_transmission
     * @brief UDP 传输（udp::socket → transmission）
     * @details 包装 UDP socket 为 transmission 叶子节点。读写均为
     * 数据报语义：一次读 = 一个完整包，一次写 = 一个完整包。
     */
    class udp_transmission : public psmtest::transmission,
                             public std::enable_shared_from_this<udp_transmission>
    {
    public:
        /**
         * @brief 构造函数（叶子节点，包一层 executor 构造）
         * @param ex 执行器
         */
        explicit udp_transmission(net::any_io_executor ex) : udp_(ex)
        {
        }

        /**
         * @brief 客户端：连接远程 UDP 端点
         * @param remote 服务器端点（host:port）
         * @return 是否成功
         */
        auto connect(const std::string &remote) -> bool
        {
            boost::system::error_code ec;
            const auto host = remote.substr(0, remote.find(':'));
            const auto port = static_cast<unsigned short>(std::stoi(remote.substr(remote.find(':') + 1)));
            udp_.connect(net::ip::udp::endpoint(net::ip::make_address(host), port), ec);
            return !ec;
        }

        /**
         * @brief 服务端：绑定本地端口监听
         * @param port 监听端口
         * @return 是否成功
         */
        auto bind(unsigned short port) -> bool
        {
            boost::system::error_code ec;
            udp_.bind(net::ip::udp::endpoint(net::ip::udp::v4(), port), ec);
            return !ec;
        }

        /**
         * @brief 获取执行器
         * @return 关联的执行器
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return udp_.get_executor();
        }

        /**
         * @brief 接收一个 UDP 数据报
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际接收字节数（一个完整数据报）
         * @details 记录来源端点，供未 connect 的写路径回发。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code bec;
            net::ip::udp::endpoint peer;
            const auto n = co_await udp_.async_receive_from(net::buffer(buffer.data(), buffer.size()),
                                                            peer,
                                                            boost::asio::redirect_error(boost::asio::use_awaitable,
                                                                                        bec));
            ec = bec;
            if (!bec)
            {
                last_peer_ = peer;
            }
            co_return n;
        }

        /**
         * @brief 发送一个 UDP 数据报
         * @param buffer 待发数据
         * @param ec 错误码输出参数
         * @return 实际发送字节数
         * @details 已 connect 用 async_send；未 connect 回发到最近
         * 一次接收记录的对端（async_send_to）。
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            boost::system::error_code bec;
            if (udp_.is_open() && last_peer_)
            {
                const auto n =
                    co_await udp_.async_send_to(net::buffer(buffer.data(), buffer.size()), *last_peer_,
                                                boost::asio::redirect_error(boost::asio::use_awaitable, bec));
                ec = bec;
                co_return n;
            }
            const auto n =
                co_await udp_.async_send(net::buffer(buffer.data(), buffer.size()),
                                         boost::asio::redirect_error(boost::asio::use_awaitable, bec));
            ec = bec;
            co_return n;
        }

        /**
         * @brief 关闭 socket
         */
        void close() override
        {
            boost::system::error_code ec;
            udp_.close(ec);
        }

        /**
         * @brief 取消挂起操作
         */
        void cancel() override
        {
            boost::system::error_code ec;
            udp_.cancel(ec);
        }

        /**
         * @brief 获取底层 UDP socket
         * @return 底层 UDP socket 引用
         */
        [[nodiscard]] auto socket() noexcept -> net::ip::udp::socket &
        {
            return udp_;
        }

    private:
        mutable net::ip::udp::socket udp_;                       ///< UDP socket
        std::optional<net::ip::udp::endpoint> last_peer_;        ///< 最近一次接收的来源端点
    };

    /// UDP 传输共享指针
    using shared_udp_transmission = std::shared_ptr<udp_transmission>;

} // namespace psmtest
