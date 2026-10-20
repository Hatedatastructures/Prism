/**
 * @file RawIngressProbe.hpp
 * @brief 单端口入口的明文/TLS ClientHello 探测结果。
 */
#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/Types.hpp>
#include <Prism/Runtime/Recognition/Tls.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <system_error>

namespace Prism::Recognition
{

    namespace Net = boost::asio;

    enum class RawIngressKind : std::uint8_t
    {
        Cleartext,
        Tls,
        Rejected,
    };

    struct RawIngressProbeRequest final
    {
        Prism::SharedTransmission Transport;
        std::chrono::milliseconds Timeout{5000};
        /** @brief 由 worker/session 注入的连接级共享有界池。 */
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
    };

    struct RawIngressProbeResult final
    {
        RawIngressKind Kind{RawIngressKind::Rejected};
        Prism::Fault::Code Code{Prism::Fault::Code::NotSupported};
        std::error_code NativeError{};
        Prism::Error ProtocolError{Prism::Error::None};
        Prism::SharedTransmission Transport{};
        ClientHelloFeatures ClientHello{};
    };

    class ProbeBuffer;

    class RawIngressProbe final
    {
    public:
        [[nodiscard]] static auto Run(RawIngressProbeRequest Request) -> Net::awaitable<RawIngressProbeResult>;

    private:
        struct RejectedInput final
        {
            Prism::SharedTransmission Transport;
            Prism::Fault::Code Code{Prism::Fault::Code::IoError};
            std::error_code NativeError{};
            Prism::Error ProtocolError{Prism::Error::None};
        };

        [[nodiscard]] static auto Inspect(Prism::SharedTransmission Transport,
            std::shared_ptr<ProbeBuffer> Buffer) -> Net::awaitable<RawIngressProbeResult>;

        [[nodiscard]] static auto Rejected(RejectedInput Input) -> RawIngressProbeResult;

        [[nodiscard]] static auto MapFill(const RecognitionStatus Status,
            const Prism::Fault::Failure& Failure) noexcept -> Prism::Fault::Code;
    };

} // namespace Prism::Recognition
