/** @file UdpTunnelFrames.hpp @brief VLESS 普通 UDP 的长度帧流读写 owner。 */
#pragma once

#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Vless
{
    namespace Net = boost::asio;

    /** @brief 只读写普通 VLESS UDP `[uint16BE length][payload]` 的流帧 owner。 */
    class UdpTunnelFrames final
    {
    public:
        UdpTunnelFrames(std::shared_ptr<Conn<>> Stream, std::chrono::milliseconds Timeout);

        /** @brief 读取且校验完整帧；返回值拥有帧字节，空载荷合法。 */
        [[nodiscard]] auto Read() -> Net::awaitable<std::expected<std::vector<std::uint8_t>, UdpFailure>>;

        /** @brief 完整写出单条长度帧；保留传输 Failure 的 native cause。 */
        [[nodiscard]] auto Write(std::span<const std::uint8_t> Frame)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

    private:
        /** @brief 读取完整字段；结束时先保留进度，终态留给后续字段。 */
        [[nodiscard]] auto ReadExact(std::span<std::byte> Buffer)
            -> Net::awaitable<UdpResult>;

        /** @brief 显式选择 Transmission byte-span 前门，保留完整 IoResult。 */
        [[nodiscard]] auto ReadCarrierExact(std::span<std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>;

        [[nodiscard]] static auto Project(const Prism::IoResult Result,
                                          const std::size_t Expected) -> UdpResult;

        std::shared_ptr<Conn<>> Stream_;
        std::chrono::milliseconds Timeout_;
        Net::steady_timer Timer_;
        std::optional<Prism::Fault::Failure> PendingTerminal_; ///< 当前完整字段交付后的 sticky 终态。
    };
} // namespace Prism::Vless
