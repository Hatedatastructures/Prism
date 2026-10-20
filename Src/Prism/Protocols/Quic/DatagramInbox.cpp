/**
 * @file DatagramInbox.cpp
 * @brief 原生 QUIC 的有界数据报接收队列实现。
 */

#include <Prism/Protocols/Quic/Detail/DatagramInbox.hpp>

#include <limits>
#include <utility>

namespace Prism::Quic::Detail
{
    DatagramInbox::DatagramInbox()
        : DatagramInbox(Limits{})
    {
    }

    DatagramInbox::DatagramInbox(Limits LimitsValue)
        : Limits_(LimitsValue)
    {
    }

    [[nodiscard]] auto DatagramInbox::Enqueue(
        const std::span<const std::byte> Data) noexcept -> bool
    {
        if (Datagrams_.size() >= Limits_.MaxDatagrams || Data.size() > Limits_.MaxBytes ||
            PendingBytes_ > Limits_.MaxBytes - Data.size())
        {
            CountDrop();
            return false;
        }
        try
        {
            std::vector<std::byte> Datagram;
            if (!Data.empty())
            {
                Datagram.assign(Data.begin(), Data.end());
            }
            Datagrams_.push_back(std::move(Datagram));
        }
        catch (...)
        {
            CountDrop();
            return false;
        }
        PendingBytes_ += Data.size();
        return true;
    }

    [[nodiscard]] auto DatagramInbox::Dequeue()
        -> std::optional<std::vector<std::byte>>
    {
        if (Datagrams_.empty())
        {
            return std::nullopt;
        }
        auto Datagram = std::move(Datagrams_.front());
        Datagrams_.pop_front();
        PendingBytes_ -= Datagram.size();
        return Datagram;
    }

    auto DatagramInbox::CountDrop() noexcept -> void
    {
        if (DroppedCount_ != (std::numeric_limits<std::uint64_t>::max)())
        {
            ++DroppedCount_;
        }
    }
} // namespace Prism::Quic::Detail
