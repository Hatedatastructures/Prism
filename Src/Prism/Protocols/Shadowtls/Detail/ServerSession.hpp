/**
 * @file ServerSession.hpp
 * @brief ShadowTLS v3 服务端标准 TLS relay。
 * @details 协议 owner 校验 ClientHello、转发握手 flight、认证首个 application-data，
 *          并仅在目标 TLS 传输真实关闭及 Activity 排空后交付内层连接。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Shadowtls/Detail/ClientHello.hpp>
#include <Prism/Protocols/Shadowtls/Detail/RecordProtector.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Conn.hpp>
#include <Prism/Protocols/Shadowtls/Detail/CarrierWire.hpp>
#include <Prism/Protocols/Shadowtls/Detail/Retirement.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Shadowtls::Detail
{
    namespace Net = boost::asio;
    using boost::asio::experimental::awaitable_operators::operator||;

    /** @brief ShadowTLS 服务端 relay 的操作状态。 */
    class ServerSession final
    {
        struct State final
        {
            SharedTransmission Client;
            SharedConn Accepted;
            SharedTransmission Target;
            std::string Password;
            std::vector<std::uint8_t> ServerRandom;
            std::optional<RecordProtector> ClientProtector;
            std::optional<RecordProtector> FlightProtector;
            std::vector<std::uint8_t> FirstPayload;
            std::optional<Failure> FirstFailure;
            std::optional<Failure> ClientReadTerminal;
            std::optional<Failure> TargetReadTerminal;
            bool Stop{false};
            bool Authenticated{false};
        };

    public:
        explicit ServerSession(ServerOptions Options);
        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;

        /**
         * @brief 执行认证 relay，并在成功时移交已推进的客户端连接。
         * @param Inbound 按值移交的客户端传输。
         * @param Config 按值持有的 ShadowTLS 凭据。
         * @return 唯一 typed handover；失败保留分类、Native 与协议进度。
         * @details 当前协程运行在入站 executor。失败关闭并等待 client/target 全链
         *          Activity 排空；成功先关闭并等待伪装 target，最终连接由调用方接管。
         */
        [[nodiscard]] auto Run(SharedTransmission Inbound, ServerConfig Config)
            -> Net::awaitable<Result<SharedConn>>
        {
            if (!Inbound) co_return std::unexpected(FailureFromError(Error::NotOpen));
            if (!Options_.DialTarget)
                co_return co_await FailAndRetire(std::move(Inbound), {}, FailureFromError(Error::Unsupported));

            auto Accepted = std::make_shared<Conn<>>(Inbound, Config.Password);
            auto Handshake = co_await Accepted->ReadStandardHandshake();
            if (!Handshake)
                co_return co_await FailAndRetire(Accepted, {}, Handshake.error());

            const auto ClientHello = Accepted->TakeClientHelloWire();
            auto Dialed = co_await DialTarget(ClientHello);
            if (!Dialed)
                co_return co_await FailAndRetire(Accepted, {}, Dialed.error());
            if (!*Dialed)
                co_return co_await FailAndRetire(Accepted, {}, FailureFromError(Error::NotOpen));
            co_await Net::post(Net::use_awaitable);

            auto Relay = std::make_shared<State>();
            Relay->Accepted = Accepted;
            Relay->Client = Accepted;
            Relay->Target = std::move(*Dialed);
            Relay->Password = std::move(Config.Password);
            auto Forward = co_await ForwardFirstFlight(Relay, ClientHello);
            if (!Forward)
            {
                Stop(Relay, false);
                co_return co_await FailAndRetire(Relay->Client, Relay->Target, Forward.error());
            }

            co_await (ClientLoop(Relay) || TargetLoop(Relay));
            if (!Relay->Authenticated || !Relay->ClientProtector || Relay->ServerRandom.empty())
            {
                Stop(Relay, false);
                const auto Cause = Relay->FirstFailure.value_or(FailureFromError(Error::BadAuth));
                co_return co_await FailAndRetire(Relay->Client, Relay->Target, Cause);
            }
            if (Relay->FirstFailure)
                co_return co_await FailAndRetire(
                    Relay->Client, Relay->Target, *Relay->FirstFailure);

            auto Handover = MakeHandover(Relay);
            if (!Handover)
            {
                Stop(Relay, false);
                co_return co_await FailAndRetire(Relay->Client, Relay->Target, Handover.error());
            }
            auto TargetRetired = co_await TransportRetirement::RetireAndDrain(std::move(Relay->Target));
            if (!TargetRetired)
                co_return co_await FailAndRetire(Relay->Client, {}, TargetRetired.error());
            Relay->Target.reset();
            co_return std::move(*Handover);
        }

    private:
        /** @brief 调用唯一拨号器并把异常 Native 身份收敛到协议失败值。 */
        [[nodiscard]] auto DialTarget(std::span<const std::uint8_t> ClientHello)
            -> Net::awaitable<Result<SharedTransmission>>
        {
            try
            {
                co_return co_await Options_.DialTarget(ClientHello);
            }
            catch (const boost::system::system_error &Exception)
            {
                const auto Native = static_cast<std::error_code>(Exception.code());
                co_return std::unexpected(Failure{Prism::Fault::ToCode(Native), Native, 0});
            }
            catch (const std::system_error &Exception)
            {
                co_return std::unexpected(Failure{
                    Prism::Fault::ToCode(Exception.code()), Exception.code(), 0});
            }
            catch (...)
            {
                co_return std::unexpected(FailureFromError(Error::IoError));
            }
        }

        /** @brief 关闭失败路径上的完整传输链，返回原始首因。 */
        [[nodiscard]] static auto FailAndRetire(
            SharedTransmission Client,
            SharedTransmission Target,
            Failure Cause) -> Net::awaitable<Result<SharedConn>>
        {
            if (Target)
            {
                auto Retired = co_await TransportRetirement::RetireAndDrain(std::move(Target));
                if (!Retired)
                {
                    if (!Cause.Failed()) Cause = Retired.error();
                    else if (!Cause.Native) Cause.Native = Retired.error().Native;
                }
            }
            if (Client)
            {
                auto Retired = co_await TransportRetirement::RetireAndDrain(std::move(Client));
                if (!Retired)
                {
                    if (!Cause.Failed()) Cause = Retired.error();
                    else if (!Cause.Native) Cause.Native = Retired.error().Native;
                }
            }
            co_return std::unexpected(Cause);
        }

        /** @brief 解析 TLS record 并保持精确读取的底层进度。 */
        [[nodiscard]] static auto ReadRecord(
            const SharedTransmission &Transport,
            std::optional<Failure> &PendingTerminal)
            -> Net::awaitable<Result<std::vector<std::uint8_t>>>
        {
            co_return co_await Io::ReadRecord(Transport, PendingTerminal);
        }

        /** @brief 按唯一 typed writer 转发一条 TLS wire。 */
        [[nodiscard]] static auto WriteAll(
            const SharedTransmission &Transport,
            std::span<const std::uint8_t> Data) -> Net::awaitable<Result<void>>
        {
            auto Written = co_await Io::SendBytes(Transport, Data);
            if (!Written) co_return std::unexpected(Written.error());
            co_return Result<void>{};
        }

        /** @brief 第一条 server flight 先到客户端，再初始化双向 record 状态。 */
        [[nodiscard]] static auto ForwardFirstFlight(
            const std::shared_ptr<State> &Relay,
            std::span<const std::uint8_t> ClientHello) -> Net::awaitable<Result<void>>
        {
            auto ClientHelloSent = co_await WriteAll(Relay->Target, ClientHello);
            if (!ClientHelloSent) co_return std::unexpected(ClientHelloSent.error());
            auto ServerHelloResult = co_await ReadRecord(
                Relay->Target, Relay->TargetReadTerminal);
            if (!ServerHelloResult) co_return std::unexpected(ServerHelloResult.error());
            auto ServerHello = std::move(*ServerHelloResult);
            if (ServerHello.size() < TlsHdrsize + 6 || ServerHello[5] != 2)
                co_return std::unexpected(FailureFromError(Error::BadMessage, ServerHello.size()));

            ServerHelloRecord Parsed;
            const auto ParseError = ParseServerHelloRecord(ServerHello, Parsed);
            if (ParseError != Error::None)
                co_return std::unexpected(FailureFromError(ParseError, ServerHello.size()));
            InitRecordProtection(Relay, Parsed.Random);
            if (!Relay->ClientProtector->IsValid() || !Relay->FlightProtector->IsValid())
                co_return std::unexpected(FailureFromError(Error::IoError, ServerHello.size()));
            Relay->ServerRandom.assign(Parsed.Random.begin(), Parsed.Random.end());
            co_return co_await WriteAll(Relay->Client, ServerHello);
        }

        /** @brief 初始化 ShadowTLS client/server flight 双向保护器。 */
        static auto InitRecordProtection(
            const std::shared_ptr<State> &Relay,
            std::span<const std::uint8_t> ServerRandom) -> void
        {
            Relay->ClientProtector.emplace(RecordProtectionOptions{
                Relay->Password, ServerRandom, TagClient});
            Relay->FlightProtector.emplace(RecordProtectionOptions{
                Relay->Password, ServerRandom, TagServer,
                RecordSeed::ServerRandomOnly, ProtectionMode::ServerFlight});
        }

        /** @brief 创建可交给内层协议的已推进连接。 */
        [[nodiscard]] static auto MakeHandover(const std::shared_ptr<State> &Relay)
            -> Result<SharedConn>
        {
            RecordProtector ServerWriter({Relay->Password, Relay->ServerRandom, TagServer});
            if (!ServerWriter.IsValid())
                return std::unexpected(FailureFromError(Error::IoError));
            auto Connection = std::move(Relay->Accepted);
            if (!Connection)
                return std::unexpected(FailureFromError(Error::NotOpen));
            auto Adopted = Connection->AdoptRecordProtection(
                RecordProtectionHandover{
                    std::move(ServerWriter), std::move(*Relay->ClientProtector),
                    std::move(Relay->FirstPayload), std::move(Relay->ClientReadTerminal)});
            if (!Adopted) return std::unexpected(Adopted.error());
            return Connection;
        }

        /** @brief 记录首因并请求相关读协程退出，最终关闭留给 Drain owner。 */
        static auto Stop(const std::shared_ptr<State> &Relay, const bool KeepClient) -> void
        {
            Relay->Stop = true;
            RequestCancel(Relay, Relay->Target);
            if (!KeepClient) RequestCancel(Relay, Relay->Client);
        }

        /** @brief 请求取消并保留控制交付失败。 */
        static auto RequestCancel(
            const std::shared_ptr<State> &Relay,
            const SharedTransmission &Transport) -> void
        {
            if (!Transport) return;
            auto Canceled = Transport->Cancel();
            if (!Canceled) RecordFailure(Relay, FailureFromFault(Canceled.error()));
        }

        /** @brief 首次真实 I/O、协议或控制失败优先成为 relay 结果。 */
        static auto RecordFailure(
            const std::shared_ptr<State> &Relay,
            const Failure &Cause) -> void
        {
            if (!Relay->FirstFailure) Relay->FirstFailure = Cause;
        }

        /** @brief 检查 TLS record 类型。 */
        [[nodiscard]] static auto IsApplicationRecord(
            const std::vector<std::uint8_t> &Record) noexcept -> bool
        {
            return Record.size() >= TlsHdrsize && Record[0] == TlsContentApplicationData;
        }

        /** @brief 读取、认证客户端 record 并转发至目标 TLS 服务。 */
        [[nodiscard]] static auto ClientLoop(const std::shared_ptr<State> &Relay)
            -> Net::awaitable<void>
        {
            while (!Relay->Stop)
            {
                auto RecordResult = co_await ReadRecord(
                    Relay->Client, Relay->ClientReadTerminal);
                if (!RecordResult)
                {
                    if (!Relay->Stop && !Relay->Authenticated)
                    {
                        RecordFailure(Relay, RecordResult.error());
                        Stop(Relay, false);
                    }
                    co_return;
                }
                auto Record = std::move(*RecordResult);
                if (Relay->ClientProtector && IsApplicationRecord(Record))
                {
                    std::vector<std::uint8_t> Payload;
                    const auto VerifyError = Relay->ClientProtector->Decode(Record, Payload);
                    if (VerifyError == Error::None && !Relay->Authenticated)
                    {
                        Relay->FirstPayload = std::move(Payload);
                        Relay->Authenticated = true;
                        Stop(Relay, true);
                        co_return;
                    }
                }
                auto Forwarded = co_await WriteAll(Relay->Target, Record);
                if (!Forwarded)
                {
                    RecordFailure(Relay, Forwarded.error());
                    Stop(Relay, false);
                    co_return;
                }
            }
        }

        /** @brief 读取目标 TLS flight、初始化保护状态并转发给客户端。 */
        [[nodiscard]] static auto TargetLoop(const std::shared_ptr<State> &Relay)
            -> Net::awaitable<void>
        {
            while (!Relay->Stop)
            {
                auto RecordResult = co_await ReadRecord(
                    Relay->Target, Relay->TargetReadTerminal);
                if (!RecordResult)
                {
                    if (!Relay->Stop && !Relay->Authenticated)
                    {
                        RecordFailure(Relay, RecordResult.error());
                        Stop(Relay, false);
                    }
                    co_return;
                }
                auto Record = std::move(*RecordResult);
                if (Relay->ServerRandom.empty() && IsServerHello(Record))
                {
                    const auto Initialized = InitializeFromServerHello(Relay, Record);
                    if (!Initialized)
                    {
                        RecordFailure(Relay, Initialized.error());
                        Stop(Relay, false);
                        co_return;
                    }
                }
                auto Outbound = ProtectServerRecord(Relay, Record);
                if (!Outbound)
                {
                    RecordFailure(Relay, Outbound.error());
                    Stop(Relay, false);
                    co_return;
                }
                auto Forwarded = co_await WriteAll(Relay->Client, *Outbound);
                if (!Forwarded)
                {
                    if (!Relay->Stop && !Relay->Authenticated)
                    {
                        RecordFailure(Relay, Forwarded.error());
                        Stop(Relay, false);
                    }
                    co_return;
                }
            }
        }

        /** @brief 判断 record 是否为未处理的 ServerHello。 */
        [[nodiscard]] static auto IsServerHello(
            const std::vector<std::uint8_t> &Record) noexcept -> bool
        {
            return Record.size() >= TlsHdrsize + 6 && Record[5] == 2;
        }

        /** @brief 根据实际 ServerHello 初始化两个协议保护器。 */
        [[nodiscard]] static auto InitializeFromServerHello(
            const std::shared_ptr<State> &Relay,
            const std::vector<std::uint8_t> &Record) -> Result<void>
        {
            ServerHelloRecord Parsed;
            const auto ParseError = ParseServerHelloRecord(Record, Parsed);
            if (ParseError != Error::None)
                return std::unexpected(FailureFromError(ParseError, Record.size()));
            InitRecordProtection(Relay, Parsed.Random);
            if (!Relay->ClientProtector->IsValid() || !Relay->FlightProtector->IsValid())
                return std::unexpected(FailureFromError(Error::IoError, Record.size()));
            Relay->ServerRandom.assign(Parsed.Random.begin(), Parsed.Random.end());
            return {};
        }

        /** @brief 按 server flight 规则保护 application-data。 */
        [[nodiscard]] static auto ProtectServerRecord(
            const std::shared_ptr<State> &Relay,
            const std::vector<std::uint8_t> &Record) -> Result<std::vector<std::uint8_t>>
        {
            std::vector<std::uint8_t> Outbound = Record;
            if (Relay->FlightProtector && IsApplicationRecord(Record))
            {
                const auto Payload = std::span<const std::uint8_t>(Record).subspan(TlsHdrsize);
                const auto EncodeError = Relay->FlightProtector->Encode(Payload, Outbound);
                if (EncodeError != Error::None)
                    return std::unexpected(FailureFromError(EncodeError, Record.size()));
            }
            return Outbound;
        }

        ServerOptions Options_;
    };
} // namespace Prism::Shadowtls::Detail
