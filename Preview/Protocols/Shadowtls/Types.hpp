/**
 * @file Types.hpp
 * @brief ShadowTLS v3 正式错误与结果类型。
 * @details 协议边界保留 Fault 分类、原生 cause 与已推进的 wire 字节数。
 */
#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <boost/asio/awaitable.hpp>
#include <functional>
#include <memory>
#include <span>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <system_error>

namespace Preview::Shadowtls
{
    namespace Net = boost::asio;
    /** @brief 一次 ShadowTLS 操作失败及其 wire 进度。 */
    struct Failure final
    {
        Preview::Fault::Code Code{Preview::Fault::Code::Success};
        std::error_code Native{};
        std::size_t Bytes{0};

        /** @brief 检查本结果是否包含领域或原生错误。 */
        [[nodiscard]] auto Failed() const noexcept -> bool
        {
            return Code != Preview::Fault::Code::Success || static_cast<bool>(Native);
        }
    };

    /** @brief 以单一 expected 表示 ShadowTLS 对外结果。 */
    template <class Value>
    using Result = std::expected<Value, Failure>;

    /** @brief 将协议状态映射为唯一的 ShadowTLS 失败值。 */
    [[nodiscard]] inline auto FailureFromError(
        const Preview::Error ErrorCode,
        const std::size_t Bytes = 0) noexcept -> Failure
    {
        const auto Native = static_cast<std::error_code>(Preview::make_error_code(ErrorCode));
        return {Preview::Fault::ToCode(Native), Native, Bytes};
    }

    /** @brief 保留通用传输边界的分类与原生错误，并附带协议 wire 进度。 */
    [[nodiscard]] inline auto FailureFromFault(
        const Preview::Fault::Failure &Value,
        const std::size_t Bytes = 0) noexcept -> Failure
    {
        return {Value.Code, Value.Native, Bytes};
    }

    /** @brief 将协议失败投递到通用 carrier 边界，不修改其 cause。 */
    [[nodiscard]] inline auto ToFaultFailure(const Failure &Value) noexcept
        -> Preview::Fault::Failure
    {
        return {Value.Code, Value.Native};
    }

    /** @brief 将 ShadowTLS fault 收敛为 Facade carrier 的协议分类。 */
    [[nodiscard]] inline auto ToProtocolError(const Preview::Fault::Code Code) noexcept
        -> Preview::Error
    {
        switch (Code)
        {
        case Preview::Fault::Code::Success: return Preview::Error::None;
        case Preview::Fault::Code::Eof: return Preview::Error::UnexpectedEof;
        case Preview::Fault::Code::AuthFailed: return Preview::Error::BadAuth;
        case Preview::Fault::Code::Canceled: return Preview::Error::Canceled;
        case Preview::Fault::Code::Timeout: return Preview::Error::Timeout;
        case Preview::Fault::Code::NotSupported: return Preview::Error::Unsupported;
        case Preview::Fault::Code::BadMessage: return Preview::Error::BadMessage;
        default: return Preview::Error::IoError;
        }
    }

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
    using SharedConn = std::shared_ptr<Preview::Transmission>;
}
