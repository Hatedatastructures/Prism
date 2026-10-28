/** @file State.hpp @brief Common 双family pump 的队列与 per-family 资源状态。 */
#pragma once

#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <vector>

namespace Prism::Protocols
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    /** @brief 一条已解析 UDP 发送项；vector 拥有载荷直到 socket 写入完成。 */
    struct DatagramEgress final
    {
        Udp::endpoint Target;
        std::vector<std::uint8_t> Payload;
    };

    /** @brief 一条已通过目标 peer 校验的 UDP 回复。 */
    struct DatagramReply final
    {
        Udp::endpoint Source;
        std::vector<std::uint8_t> Payload;
    };

    /** @brief 一种地址族独占 socket、发送队列、peer 集与静默退休 timer。 */
    struct DatagramFamilyLane final
    {
        using EgressQueue = Net::experimental::concurrent_channel<
            void(boost::system::error_code, DatagramEgress)>;
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        DatagramFamilyLane(Net::any_io_executor Executor, bool IsV6)
            : Socket(Executor), Outgoing(Executor, 64), Ready(Executor, 1),
              Idle(Executor), IsV6(IsV6)
        { Idle.expires_at(Net::steady_timer::time_point::max()); }

        Udp::socket Socket;
        EgressQueue Outgoing;
        Signal Ready;
        Net::steady_timer Idle;
        std::vector<Udp::endpoint> Peers;
        bool IsV6{false};
        bool SenderFinished{false};
    };
} // namespace Prism::Protocols
