/**
 * @file ConnectionState.cpp
 * @brief HTTP/2 连接帧队列收集实现
 */

#include <Prism/Protocols/Http2/Detail/ConnectionState.hpp>

namespace Prism::Http2::Detail
{
    auto ConnectionState::QueueFrame(const FrameParameters &Parameters) -> void
    {
        TxQueue_.push_back(BuildFrame(Parameters));
    }

    auto ConnectionState::Collect(std::vector<std::byte> &Output) -> bool
    {
        if (!IsServer_ && !PrefaceSent_ && !TxQueue_.empty())
        {
            constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
            std::vector<std::byte> Wire;
            Wire.reserve(Preface.size());
            for (const auto Character : Preface)
            {
                Wire.push_back(static_cast<std::byte>(Character));
            }
            TxQueue_.push_front(std::move(Wire));
            PrefaceSent_ = true;
        }
        const auto Had = !TxQueue_.empty();
        while (!TxQueue_.empty())
        {
            auto &Frame = TxQueue_.front();
            Output.insert(Output.end(), Frame.begin(), Frame.end());
            TxQueue_.pop_front();
        }
        return Had;
    }
} // namespace Prism::Http2::Detail
