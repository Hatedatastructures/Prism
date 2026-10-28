/**
 * @file State.hpp
 * @brief 拥有 QUIC stream ACK/FIN 状态与 datagram inbox 通知状态。
 * @details NativeConnection 保留 socket/CID/ngtcp2 owner；此处状态随单条 stream 或 datagram owner 退役。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Quic/Native/Datagram/Inbox.hpp>

namespace Prism::Quic::Detail
{
    class NativeConnection;
    class NativeStreamActivity;

    /** @brief 保留到 ACK 或 stream close 的传输字节。 */
    struct SentStreamData final
    {
        std::vector<std::byte> Bytes;
        std::uint64_t BeginOffset{0};
        std::uint64_t EndOffset{0};
        std::uint64_t AcknowledgedBytes{0};
        bool SubmissionComplete{false};
    };

    struct StreamWriteResult final
    {
        std::size_t Bytes{0};
        std::error_code Error{};
    };

    /** @brief 单条 QUIC stream 的接收、确认、半关闭与 reset 状态。 */
    struct StreamState final
    {
        StreamState(boost::asio::any_io_executor ExecutorValue, const std::int64_t StreamIdValue)
            : Executor(std::move(ExecutorValue)), Id(StreamIdValue), Notify(Executor, 1),
              FinAcknowledgedNotify(Executor, 1)
        {
        }

        boost::asio::any_io_executor Executor;
        std::int64_t Id;
        bool PeerInitiated{false};
        bool Unidirectional{false};
        bool StreamCreditReturned{false};
        boost::asio::experimental::channel<void(boost::system::error_code)> Notify;
        boost::asio::experimental::channel<void(boost::system::error_code)> FinAcknowledgedNotify;
        std::deque<std::vector<std::byte>> Received;
        std::deque<std::shared_ptr<SentStreamData>> SentBuffers;
        std::weak_ptr<NativeConnection> Owner;
        std::weak_ptr<NativeStreamActivity> Activity;
        std::atomic<bool> NativeTerminal{false};
        bool PeerFin{false};
        bool Closed{false};
        bool LocalWriteClosed{false};
        bool FinSubmitted{false};
        bool FinOffsetKnown{false};
        bool FinSenderDrained{false};
        bool FinAcknowledged{false};
        std::uint64_t SentOffset{0};
        std::uint64_t FinOffset{0};
        bool PeerReset{false};
        bool PeerStopSending{false};
        std::uint64_t PeerApplicationErrorCode{0};
        std::uint64_t PeerFinalSize{0};
        std::error_code PeerReadFailure{};
        std::error_code PeerWriteFailure{};
        Prism::Fault::Failure StreamCloseFailure{};
        Prism::Fault::Failure LocalWriteFailure{};
        bool Canceled{false};
    };

    /** @brief 单个 datagram provider 的 executor 通知与有界 inbox。 */
    struct DatagramState final
    {
        explicit DatagramState(
            boost::asio::any_io_executor ExecutorValue, DatagramInbox::Limits LimitsValue)
            : Executor(std::move(ExecutorValue)), Notify(Executor, 1), Inbox(LimitsValue)
        {
        }

        boost::asio::any_io_executor Executor;
        boost::asio::experimental::channel<void(boost::system::error_code)> Notify;
        DatagramInbox Inbox;
        bool Closed{false};
        bool Canceled{false};
    };
}
