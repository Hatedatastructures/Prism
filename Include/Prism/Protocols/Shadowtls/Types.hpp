/**
 * @file Types.hpp
 * @brief ShadowTLS v3 正式错误与结果类型。
 * @details 协议边界保留 Fault 分类、原生 cause 与已推进的 wire 字节数。
 */
#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <functional>
#include <memory>
#include <span>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <system_error>

namespace Prism::Shadowtls
{
    namespace Net = boost::asio;
    /** @brief 一次 ShadowTLS 操作失败及其 wire 进度。 */
    struct Failure final
    {
        Prism::Fault::Code Code{Prism::Fault::Code::Success};
        std::error_code Native{};
        std::size_t Bytes{0};

        /** @brief 检查本结果是否包含领域或原生错误。 */
        [[nodiscard]] auto Failed() const noexcept -> bool
        {
            return Code != Prism::Fault::Code::Success || static_cast<bool>(Native);
        }
    };

    /** @brief 以单一 expected 表示 ShadowTLS 对外结果。 */
    template <class Value>
    using Result = std::expected<Value, Failure>;

    /** @brief 将协议状态映射为唯一的 ShadowTLS 失败值。 */
    [[nodiscard]] auto FailureFromError(
        const Prism::Error ErrorCode,
        const std::size_t Bytes = 0) noexcept -> Failure;

    /** @brief 保留通用传输边界的分类与原生错误，并附带协议 wire 进度。 */
    [[nodiscard]] auto FailureFromFault(
        const Prism::Fault::Failure &Value,
        const std::size_t Bytes = 0) noexcept -> Failure;

    /** @brief 将协议失败投递到通用 carrier 边界，不修改其 cause。 */
    [[nodiscard]] auto ToFaultFailure(const Failure &Value) noexcept
        -> Prism::Fault::Failure;

    /** @brief 将 ShadowTLS fault 收敛为 Facade carrier 的协议分类。 */
    [[nodiscard]] auto ToProtocolError(Prism::Fault::Code Code) noexcept -> Prism::Error;

    /// ShadowTLS 客户端认证配置。
    struct ClientConfig
    {
        std::string Password;
    };

    /// ShadowTLS 服务端认证配置。
    struct ServerConfig
    {
        std::string Password;
    };

    inline constexpr std::size_t TlsHdrsize = 5;
    inline constexpr std::uint8_t HsTypeClienthello = 1;
    inline constexpr std::size_t TlsRndSize = 32;
    inline constexpr std::size_t TlsSessionIdSz = 32;
    inline constexpr std::size_t HmacSize = 4;
    inline constexpr std::uint8_t TlsContentApplicationData = 23;
    inline constexpr std::uint8_t TlsRecordVersionMajor = 3;
    inline constexpr std::uint8_t TlsRecordVersionMinor = 3;
    inline constexpr std::size_t MaxTlsPlaintext = 16 * 1024;
    inline constexpr std::size_t SessionIdStart = 1 + 3 + 2 + TlsRndSize + 1;
    inline constexpr char TagClient = 'C';
    inline constexpr char TagServer = 'S';

    /** @brief 一端 ShadowTLS application-data 的方向标签。 */
    struct RecordDirections final
    {
        char Write{TagClient};
        char Read{TagServer};
    };

    enum class RecordSeed : std::uint8_t
    {
        Directional,
        ServerRandomOnly,
    };
    /** @brief ShadowTLS 服务端目标拨号能力，由一个会话按值拥有。 */
    struct ServerOptions final
    {
        std::function<Net::awaitable<Result<SharedTransmission>>(
            std::span<const std::uint8_t>)> DialTarget;
    };

    /** @brief ShadowTLS 对外字节流句柄；协议状态保留在 Detail owner。 */
    using SharedConn = std::shared_ptr<Prism::Transmission>;
}
