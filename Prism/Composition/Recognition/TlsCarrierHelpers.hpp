/**
 * @file TlsCarrierHelpers.hpp
 * @brief 具体 TLS carrier 的服务端接入回调构造辅助函数。
 * @details 每个回调按值捕获长期依赖，并在成功时转移已完成 carrier
 *          握手的传输；失败通过 typed fault 返回给 Recognition commit。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Composition/Recognition/TlsCandidateModel.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Gun/Gun.hpp>
#include <Prism/Protocols/Gun/Grpc.hpp>
#include <Prism/Protocols/Native/Native.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Protocols/Reality/Prepared.hpp>
#include <Prism/Protocols/Reality/CarrierPreparation.hpp>
#include <Prism/Protocols/Shadowtls/Server.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <Prism/Protocols/Xhttp/Xhttp.hpp>
#include <Prism/Transport/NativeTls.hpp>

namespace Prism::Composition::Recognition
{

    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;

    namespace Detail
    {
        /** @brief 在 carrier wire 边界保留项目协议错误的 category/value 与领域码。 */
        [[nodiscard]] inline auto FailureFromProtocolError(Prism::Error Value) noexcept
            -> Prism::Fault::Failure
        {
            if (Value == Prism::Error::None) return {};
            const auto Native = Prism::make_error_code(Value);
            return {Prism::Fault::ToCode(Native), static_cast<std::error_code>(Native)};
        }

        inline auto SetCarrierFailure(
            Core::CarrierAcceptResult &Result,
            const Prism::Fault::Failure &Failure) -> void
        {
            Result.Code = Failure.Code;
            Result.NativeError = Failure.Native;
        }

        [[nodiscard]] inline auto RetireCarrierInput(
            Prism::SharedTransmission Inbound,
            Prism::Fault::Failure Cause)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            if (!Inbound) co_return Cause;
            auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(
                std::move(Inbound));
            if (!Prepared) co_return Cause;
            auto Admission = std::move(*Prepared);
            co_return co_await Admission.Retire(Cause);
        }
    }

    /** @brief 已通过 Application 配置校验的 Gun 服务模式。 */
    enum class GunServerMode : std::uint8_t
    {
        GunLite,
        Grpc,
    };

    /**
     * @struct GunServerAcceptOptions
     * @brief Gun carrier 的 owning 冷装配材料。
     * @details Mode 已由 Application 从配置字符串解析；运行期 callback 不再
     *          借用配置或按未知字符串隐式选择 GunLite。
     */
    struct GunServerAcceptOptions final
    {
        GunServerAcceptOptions(
            std::shared_ptr<Net::ssl::context> TlsContextValue,
            Prism::Gun::Config ConfigValue,
            const GunServerMode ModeValue)
            : TlsContext(std::move(TlsContextValue)), Config(std::move(ConfigValue)), Mode(ModeValue)
        {
        }

        std::shared_ptr<Net::ssl::context> TlsContext;
        Prism::Gun::Config Config;
        GunServerMode Mode;
    };

    [[nodiscard]] inline auto RunShadowtlsServerAccept(
        std::shared_ptr<Prism::Shadowtls::ServerSession> Session,
        Prism::Shadowtls::ServerConfig Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        auto ServerResult = co_await Session->Run(std::move(Input.Inbound), Config);
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "shadowtls";
        if (!ServerResult)
        {
            Result.Code = ServerResult.error().Code;
            Result.NativeError = boost::system::error_code(ServerResult.error().Native);
            co_return Result;
        }
        Result.Transport = std::move(*ServerResult);
        co_return Result;
    }

    /**
     * @brief 创建 ShadowTLS v3 服务端 carrier 接入回调。
     * @param Options relay 目标拨号选项。
     * @param Config ShadowTLS 认证配置。
     * @return 可长期捕获的服务端接入回调。
     * @details factory 只提交 named runner；runner 按值拥有 session、配置和
     *          typed carrier input，并在 inbound executor 上调用 ShadowTLS protocol owner。
     *          失败返回 typed fault，取消、半关闭和最终关闭由 protocol owner 承担。
     */
    [[nodiscard]] inline auto MakeShadowtlsServerAccept(Prism::Shadowtls::ServerOptions Options,
                                                        Prism::Shadowtls::ServerConfig Config)
        -> CarrierAcceptFn
    {
        auto Session = std::make_shared<Prism::Shadowtls::ServerSession>(std::move(Options));
        return [Session, Config = std::move(Config)](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunShadowtlsServerAccept(Session, Config, std::move(Input));
        };
    }

    [[nodiscard]] inline auto RunWebsocketServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Ws::ServerOptions Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "ws";
        auto Transport = std::move(Input.Inbound);
        auto Bytes = std::move(Input.Bytes);
        if (TlsContext)
        {
            auto Tls = co_await Prism::Native::Accept(
                Prism::Native::AcceptRequest{std::move(Transport), *TlsContext, Bytes});
            if (!Tls)
            {
                Detail::SetCarrierFailure(Result, Tls.error());
                co_return Result;
            }
            Result.Metadata.Sni = std::move(Tls->ServerName);
            Result.Metadata.Alpn = std::move(Tls->Alpn);
            Result.Metadata.TlsVersion = std::move(Tls->TlsVersion);
            Result.Metadata.EchAccepted = Tls->EchAccepted;
            Result.Metadata.NativeTlsEstablished = true;
            Transport = std::move(Tls->Transport);
        }
        auto Accepted = co_await Prism::Ws::Accept(
            Prism::Ws::AcceptOptions{std::move(Transport), std::move(Bytes), std::move(Config)});
        if (!Accepted)
        {
            Detail::SetCarrierFailure(Result, Accepted.error());
            co_return Result;
        }
        Result.Transport = std::move(Accepted->Connection);
        co_return Result;
    }

    /**
     * @brief 创建 WebSocket 服务端 carrier 接入回调。
     * @param TlsContext 按值复制的 TLS context shared owner；可为空表示明文 WS。
     * @param Config WebSocket path/Host 约束，按值进入 callback frame。
     * @return 在 carrier commit 阶段执行真实 HTTP Upgrade 的回调。
     * @details callback 在入站 transport executor 上运行；同一 Bytes shared owner
     *          分别交给 TLS 与 WS Conn。取消只取消在途操作；半关闭由 ConnClose 转交，
     *          最终关闭由 ConnClose 交付，活动排空后 ConnSession 释放 BytePool owner。
     */
    [[nodiscard]] inline auto MakeWebsocketServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Ws::ServerOptions Config) -> CarrierAcceptFn
    {
        return [TlsContext = std::move(TlsContext), Config = std::move(Config)](
                   Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunWebsocketServerAccept(TlsContext, Config, std::move(Input));
        };
    }

    [[nodiscard]] inline auto RunXhttpServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Xhttp::Config Config,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "xhttp";
        if (!TlsContext)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Result.Code = Failure.Code;
            Result.NativeError = Failure.Native;
            co_return Result;
        }
        auto Accepted = co_await Prism::Xhttp::Accept(
            Prism::Xhttp::AcceptRequest{
                std::move(Input.Inbound), *TlsContext, Config, std::move(Input.Bytes)});
        if (!Accepted)
        {
            Result.Code = Accepted.error().Code;
            Result.NativeError = Accepted.error().Native;
            co_return Result;
        }
        Result.Metadata.Sni = std::move(Accepted->Negotiated.ServerName);
        Result.Metadata.Alpn = std::move(Accepted->Negotiated.Alpn);
        Result.Metadata.TlsVersion = std::move(Accepted->Negotiated.Version);
        Result.Metadata.EchAccepted = Accepted->Negotiated.EchAccepted;
        Result.Metadata.NativeTlsEstablished = true;
        Result.Transport = std::move(Accepted->Transport);
        co_return Result;
    }

    /**
     * @brief 创建 XHTTP 服务端 carrier 接入回调。
     * @param TlsContext 按值复制的服务端 TLS context shared owner。
     * @param Config XHTTP path/authority/mode 约束，按值进入 callback frame。
     * @return 在 carrier commit 阶段执行真实 TLS + HTTP/2 握手的回调。
     * @details callback 不借用 Application configuration；取消、半关闭和最终
     *          transport 关闭由 XHTTP protocol owner 执行。
     */
    [[nodiscard]] inline auto MakeXhttpServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Prism::Xhttp::Config Config) -> CarrierAcceptFn
    {
        return [TlsContext = std::move(TlsContext), Config = std::move(Config)](
                   Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunXhttpServerAccept(TlsContext, Config, std::move(Input));
        };
    }

    [[nodiscard]] inline auto RunGunServerAccept(
        GunServerAcceptOptions Options,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "gun";
        if (!Options.TlsContext)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }
        if (Options.Mode != GunServerMode::GunLite &&
            Options.Mode != GunServerMode::Grpc)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Input.Inbound);
        if (!Prepared)
        {
            Detail::SetCarrierFailure(Result, Prepared.error());
            co_return Result;
        }
        auto Admission = std::move(*Prepared);
        std::exception_ptr Fatal;
        Prism::SharedTransmission TransportOwner;
        bool AdmissionReleased = false;
        try
        {
            auto Tls = co_await Prism::Native::Accept(
                Prism::Native::AcceptRequest{
                    std::move(Input.Inbound), *Options.TlsContext, std::move(Input.Bytes)});
            if (!Tls)
            {
                Detail::SetCarrierFailure(Result, co_await Admission.Retire(Tls.error()));
                co_return Result;
            }
            Result.Metadata.Sni = std::move(Tls->ServerName);
            Result.Metadata.Alpn = std::move(Tls->Alpn);
            Result.Metadata.TlsVersion = std::move(Tls->TlsVersion);
            Result.Metadata.EchAccepted = Tls->EchAccepted;
            Result.Metadata.NativeTlsEstablished = true;
            TransportOwner = std::static_pointer_cast<Prism::Transmission>(
                std::move(Tls->Transport));
            const auto Tracked = Admission.Track(
                TransportOwner);
            if (!Tracked)
            {
                auto Failure = co_await Admission.Retire(Tracked.error());
                Failure = co_await Detail::RetireCarrierInput(TransportOwner, Failure);
                Detail::SetCarrierFailure(Result, Failure);
                co_return Result;
            }
            if (Options.Mode == GunServerMode::Grpc)
            {
                auto Connection = co_await Prism::Gun::Grpc::StreamTransport::Accept(
                    TransportOwner,
                    Prism::Gun::Grpc::Config{
                        Options.Config.Path, {}, Prism::Gun::Grpc::DefaultMaxMessageBytes});
                if (!Connection)
                {
                    Detail::SetCarrierFailure(
                        Result, co_await Admission.Retire(Connection.error()));
                    co_return Result;
                }
                Result.Transport = std::move(*Connection);
                Admission.Release();
                co_return Result;
            }

            Admission.Release();
            AdmissionReleased = true;
            auto Accepted = co_await Prism::Gun::Accept(
                TransportOwner, Options.Config);
            if (!Accepted)
            {
                Detail::SetCarrierFailure(Result, Accepted.error());
                co_return Result;
            }
            Result.Transport = std::move(Accepted->Connection);
            co_return Result;
        }
        catch (const std::bad_alloc &)
        {
            Fatal = std::current_exception();
        }
        const auto Cause = Prism::Contract::InboundAdmission::ExceptionFailure(
            std::move(Fatal));
        auto Failure = Cause;
        if (AdmissionReleased)
        {
            Failure = co_await Detail::RetireCarrierInput(TransportOwner, Cause);
        }
        else
        {
            Failure = co_await Admission.Retire(Cause);
        }
        Detail::SetCarrierFailure(Result, Failure);
        co_return Result;
    }

    /**
     * @brief 创建 Gun 服务端 carrier 接入回调。
     * @param Options 已完成校验并按值拥有的 TLS/Gun/mode 材料。
     * @return 在 carrier commit 阶段执行真实 TLS + Gun CONNECT 握手的回调。
     */
    [[nodiscard]] inline auto MakeGunServerAccept(GunServerAcceptOptions Options)
        -> CarrierAcceptFn
    {
        return [Options = std::move(Options)](
                   Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunGunServerAccept(Options, std::move(Input));
        };
    }

    [[nodiscard]] inline auto RejectRealityAccept(
        Prism::SharedTransmission Inbound,
        Prism::Fault::Failure Cause) -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "reality";
        const auto Failure = co_await Detail::RetireCarrierInput(std::move(Inbound), Cause);
        Detail::SetCarrierFailure(Result, Failure);
        co_return Result;
    }

    [[nodiscard]] inline auto RunRealityServerAccept(
        Prism::Reality::PreparedConfig Config,
        Core::CarrierAcceptPreparedInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        const auto Features = std::static_pointer_cast<const Core::ClientHelloFeatures>(
            std::move(Input.PreparedState));
        if (!Input.Inbound || !Features || !Features->HasX25519 ||
            Features->RawMessage.empty() || Features->RawRecord.empty() ||
            Features->ConsumedBytes != Features->RawRecord.size() || Config.ShortIds.empty())
        {
            co_return co_await RejectRealityAccept(
                std::move(Input.Inbound),
                Detail::FailureFromProtocolError(Prism::Error::ProtocolError));
        }

        std::vector<std::byte> ClientHello(Features->ConsumedBytes);
        std::size_t Offset = 0;
        while (Offset < ClientHello.size())
        {
            const auto Part = co_await Prism::Protocol::Common::ReadExactIo(
                Input.Inbound,
                std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t *>(ClientHello.data() + Offset),
                    ClientHello.size() - Offset));
            const auto Read = Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return co_await RejectRealityAccept(std::move(Input.Inbound), Part.Failure);
            }
            Offset += Read;
        }
        const auto ExpectedRecord = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Features->RawRecord.data()),
            Features->RawRecord.size());
        if (!std::equal(ClientHello.begin(), ClientHello.end(),
                        ExpectedRecord.begin(), ExpectedRecord.end()))
        {
            co_return co_await RejectRealityAccept(
                std::move(Input.Inbound),
                Detail::FailureFromProtocolError(Prism::Error::BadMessage));
        }

        auto Accepted = co_await Prism::Reality::AcceptPrepared(
            Prism::Reality::PreparedRequest{
                Input.Inbound, std::move(Config),
                std::span<const std::uint8_t>(Features->Random),
                std::span<const std::uint8_t>(Features->SessionId),
                std::span<const std::uint8_t>(Features->X25519Key),
                std::span<const std::uint8_t>(Features->RawMessage), Features->ServerName});
        if (!Accepted)
        {
            Core::CarrierAcceptResult Result;
            Result.Metadata.Carrier = "reality";
            Detail::SetCarrierFailure(Result, Accepted.error());
            co_return Result;
        }

        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "reality";
        Result.Transport = std::move(*Accepted);
        co_return Result;
    }

    [[nodiscard]] inline auto MakeRealityServerAccept(
        Prism::Reality::PreparedConfig Config)
        -> CarrierAcceptPreparedFn
    {
        return [Config = std::move(Config)](
                   Core::CarrierAcceptPreparedInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            co_return co_await RunRealityServerAccept(Config, std::move(Input));
        };
    }

    /**
     * @brief 执行 Native TLS 服务端 carrier 接入。
     * @param TlsContext 按值持有的服务端 SSL context。
     * @param Input 按值接管的入站传输与 worker BytePool。
     * @return typed carrier 结果，保留 NativeError 和握手 fault。
     * @details Native 入口必须完成 TLS 握手；executor 与取消随传输传播，失败
     *          关闭由 admission ticket 排空，成功后的最终关闭由 session owner 负责。
     */
    [[nodiscard]] inline auto RunNativeTlsServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext,
        Core::CarrierAcceptInput Input)
        -> Net::awaitable<Core::CarrierAcceptResult>
    {
        Core::CarrierAcceptResult Result;
        Result.Metadata.Carrier = "native";
        if (!TlsContext)
        {
            const auto Failure = co_await Detail::RetireCarrierInput(
                std::move(Input.Inbound),
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            Detail::SetCarrierFailure(Result, Failure);
            co_return Result;
        }
        auto Accepted = co_await Prism::Native::Accept(
            Prism::Native::AcceptRequest{
                std::move(Input.Inbound), *TlsContext, std::move(Input.Bytes)});
        if (!Accepted)
        {
            Detail::SetCarrierFailure(Result, Accepted.error());
            co_return Result;
        }
        Result.Metadata.Sni = std::move(Accepted->ServerName);
        Result.Metadata.Alpn = std::move(Accepted->Alpn);
        Result.Metadata.TlsVersion = std::move(Accepted->TlsVersion);
        Result.Metadata.EchAccepted = Accepted->EchAccepted;
        Result.Metadata.NativeTlsEstablished = true;
        Result.Transport = std::move(Accepted->Transport);
        co_return Result;
    }

    /**
     * @brief 构造唯一 Native TLS 服务端 carrier callback。
     * @param TlsContext 按值接管的 shared SSL context；空值仍返回 typed callback，
     *        由 strict Native owner 产生明确失败结果。
     * @return 运行期只捕获 owning context 的 carrier callback。
     * @details callback 在入站 transport executor 上执行；必须完成 TLS handshake，
     *          不接受明文前缀直通。通用可选 TLS 前缀探测仍由 Transport owner 使用。
     */
    [[nodiscard]] inline auto MakeNativeTlsServerAccept(
        std::shared_ptr<Net::ssl::context> TlsContext) -> CarrierAcceptFn
    {
        return [TlsContext = std::move(TlsContext)](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return RunNativeTlsServerAccept(TlsContext, std::move(Input));
        };
    }

} // namespace Prism::Composition::Recognition
