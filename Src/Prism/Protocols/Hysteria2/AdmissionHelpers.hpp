/**
 * @file AdmissionHelpers.hpp
 * @brief Hysteria2 admission provider 关闭辅助函数声明。
 */
#pragma once

#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <expected>

namespace Prism::Hysteria2
{
    /** @brief 关闭尚未交给 stream child 的 provider。 */
    [[nodiscard]] auto CloseStream(const Prism::Quic::SharedStreamProvider &Provider) noexcept
        -> std::expected<void, Prism::Fault::Failure>;

    /** @brief 取消并关闭尚未交给 datagram child 的 provider。 */
    [[nodiscard]] auto CloseDatagram(const Prism::Quic::SharedDatagramProvider &Provider) noexcept
        -> std::expected<void, Prism::Fault::Failure>;
}
