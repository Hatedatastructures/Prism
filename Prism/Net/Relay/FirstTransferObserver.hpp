/** @file FirstTransferObserver.hpp @brief 中继首次成功转发通知的中立契约。 */
#pragma once

#include <cstddef>

namespace Prism::Network::Relay
{
    /** @brief 每个方向首次成功写出数据时最多通知一次。 */
    class FirstTransferObserver
    {
    public:
        virtual ~FirstTransferObserver() = default;
        virtual auto OnFirstTransfer(std::size_t Direction) noexcept -> void = 0;
    };
}
