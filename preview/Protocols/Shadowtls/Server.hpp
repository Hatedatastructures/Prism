/**
 * @file Server.hpp
 * @brief ShadowTLS v3 服务端标准 TLS relay
 * @details 只负责 ShadowTLS carrier 的服务端编排：校验 ClientHello、将原始
 *          ClientHello 转发到目标 TLS 服务、转换握手 flight，并在首个客户端
 *          application-data 认证 record 到达后交付已推进的内层连接。
 * @note 本模块不实现 TLS 状态机；目标 TLS 服务负责证书、密钥交换和 Finished。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Shadowtls/Codec.hpp>
#include <preview/Protocols/Shadowtls/Conn.hpp>
#include <preview/Transport/Transmission.hpp>

namespace Preview::Shadowtls
{

    namespace Net = boost::asio;
    using boost::asio::experimental::awaitable_operators::operator||;

    /**
     * @struct ServerOptions
     * @brief ShadowTLS server relay 目标拨号配置
     */
    struct ServerOptions
    {
        /// 根据已认证的 ClientHello 建立目标 TLS 传输
        std::function<Net::awaitable<SharedTransmission>(std::span<const std::uint8_t>)> DialTarget;
    };

    /**
     * @struct ServerResult
     * @brief ShadowTLS server relay 结果
     */
    struct ServerResult
    {
        Error Status{Error::IoError};
        SharedConn Connection;
    };

    namespace Detail
    {

        [[nodiscard]] inline auto ReadExact(
            const SharedTransmission &Transport,
            std::span<std::uint8_t> Buffer) -> Net::awaitable<Error>
        {
            if (!Transport)
            {
                co_return Error::NotOpen;
            }
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                std::error_code Ec;
                const auto ReadWindow = std::span<std::byte>(
                    reinterpret_cast<std::byte *>(Buffer.data() + Done),
                    Buffer.size() - Done);
                const auto Count = co_await Transport->async_read_some(ReadWindow, Ec);
                if (Ec)
                {
                    if (Count == 0)
                    {
                        co_return Error::UnexpectedEof;
                    }
                    co_return Error::IoError;
                }
                if (Count == 0)
                {
                    co_return Error::UnexpectedEof;
                }
                if (Count > Buffer.size() - Done)
                {
                    co_return Error::BadLength;
                }
                Done += Count;
            }
            co_return Error::None;
        }

        [[nodiscard]] inline auto WriteAll(
            const SharedTransmission &Transport,
            std::span<const std::uint8_t> Data) -> Net::awaitable<Error>
        {
            if (!Transport)
            {
                co_return Error::NotOpen;
            }
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code Ec;
                const auto WriteWindow = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Data.data() + Done),
                    Data.size() - Done);
                const auto Count = co_await Transport->async_write_some(WriteWindow, Ec);
                if (Ec)
                {
                    co_return Error::IoError;
                }
                if (Count == 0 || Count > Data.size() - Done)
                {
                    co_return Error::BrokenPipe;
                }
                Done += Count;
            }
            co_return Error::None;
        }

        [[nodiscard]] inline auto ReadRecord(
            const SharedTransmission &Transport,
            std::vector<std::uint8_t> &Record) -> Net::awaitable<Error>
        {
            Record.clear();
            std::array<std::uint8_t, TlsHdrsize> Header{};
            auto Err = co_await ReadExact(Transport, Header);
            if (Err != Error::None)
            {
                co_return Err;
            }
            const auto Length = (static_cast<std::size_t>(Header[3]) << 8) | Header[4];
            if (Length > MaxTlsPlaintext)
            {
                co_return Error::BadLength;
            }
            Record.resize(TlsHdrsize + Length);
            std::copy(Header.begin(), Header.end(), Record.begin());
            const auto PayloadWindow = std::span<std::uint8_t>(Record).subspan(TlsHdrsize);
            Err = co_await ReadExact(Transport, PayloadWindow);
            if (Err != Error::None)
            {
                Record.clear();
            }
            co_return Err;
        }

        auto Close(const SharedTransmission &Transport) -> void
        {
            if (Transport)
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

    } // namespace Detail

    /**
     * @class ServerSession
     * @brief ShadowTLS v3 服务端 carrier relay 会话
     */
    class ServerSession final
    {
    private:
        struct State
        {
            SharedTransmission Client;
            SharedConn Accepted;
            SharedTransmission Target;
            std::string Password;
            std::vector<std::uint8_t> ServerRandom;
            std::optional<RecordProtector> ClientProtector;
            std::optional<RecordProtector> FlightProtector;
            std::vector<std::uint8_t> FirstPayload;
            Error Failure{Error::None};
            bool Stop{false};
            bool Authenticated{false};
        };

    public:
        explicit ServerSession(ServerOptions Options) : Options_(std::move(Options))
        {
        }

        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;

        /**
         * @brief 运行一次服务端标准 carrier relay
         * @param Inbound 客户端原始 TCP 传输（所有权移交）
         * @param Config ShadowTLS 认证配置
         * @return relay 状态与已推进的内层连接
         */
        [[nodiscard]] auto Run(
            SharedTransmission Inbound,
            ServerConfig Config) -> Net::awaitable<ServerResult>
        {
            ServerResult Result;
            if (!Inbound || !Options_.DialTarget)
            {
                Detail::Close(Inbound);
                if (!Inbound)
                {
                    Result.Status = Error::NotOpen;
                }
                else
                {
                    Result.Status = Error::NotSupported;
                }
                co_return Result;
            }

            auto Accepted = std::make_shared<Conn<>>(Inbound, Config.password);
            const auto AcceptError = co_await Accepted->ReadStandardHandshake();
            auto ClientHello = Accepted->TakeClientHelloWire();
            if (AcceptError != Error::None || !Accepted)
            {
                Detail::Close(Inbound);
                Result.Status = AcceptError;
                co_return Result;
            }
            auto Client = std::move(Accepted);
            if (!Client)
            {
                Result.Status = Error::NotOpen;
                co_return Result;
            }

            SharedTransmission Target;
            try
            {
                Target = co_await Options_.DialTarget(ClientHello);
            }
            catch (...)
            {
                Detail::Close(Client);
                Result.Status = Error::IoError;
                co_return Result;
            }
            if (!Target)
            {
                Detail::Close(Client);
                Result.Status = Error::IoError;
                co_return Result;
            }

            auto StateValue = std::make_shared<State>();
            StateValue->Accepted = Client;
            StateValue->Client = std::move(Client);
            StateValue->Target = std::move(Target);
            StateValue->Password = Config.password;
            const auto ForwardError = co_await Detail::WriteAll(StateValue->Target, ClientHello);
            if (ForwardError != Error::None)
            {
                Stop(StateValue, false);
                Result.Status = ForwardError;
                co_return Result;
            }

            (void)co_await (ClientLoop(StateValue) || TargetLoop(StateValue));
            if (!StateValue->Authenticated || !StateValue->ClientProtector || StateValue->ServerRandom.empty())
            {
                Stop(StateValue, false);
                if (StateValue->Failure == Error::None)
                {
                    Result.Status = Error::BadAuth;
                }
                else
                {
                    Result.Status = StateValue->Failure;
                }
                co_return Result;
            }

            RecordProtector ServerWriter(StateValue->Password, StateValue->ServerRandom, TagServer);
            if (!ServerWriter.IsValid())
            {
                Stop(StateValue, false);
                Result.Status = Error::IoError;
                co_return Result;
            }
            auto Connection = std::move(StateValue->Accepted);
            if (!Connection)
            {
                Stop(StateValue, false);
                Result.Status = Error::NotOpen;
                co_return Result;
            }
            const auto AdoptError = Connection->AdoptRecordProtection(
                std::move(ServerWriter), std::move(*StateValue->ClientProtector), std::move(StateValue->FirstPayload));
            if (AdoptError != Error::None)
            {
                Stop(StateValue, false);
                Result.Status = AdoptError;
                co_return Result;
            }
            StateValue->Target.reset();
            Result.Status = Error::None;
            Result.Connection = std::move(Connection);
            co_return Result;
        }

    private:
        static auto Stop(const std::shared_ptr<State> &StateValue, const bool KeepClient) -> void
        {
            StateValue->Stop = true;
            Detail::Close(StateValue->Target);
            if (!KeepClient)
            {
                Detail::Close(StateValue->Client);
            }
        }

        [[nodiscard]] static auto IsApplicationRecord(const std::vector<std::uint8_t> &Record) noexcept -> bool
        {
            return Record.size() >= TlsHdrsize && Record[0] == TlsContentApplicationData;
        }

        [[nodiscard]] auto ClientLoop(
            const std::shared_ptr<State> &StateValue) -> Net::awaitable<Error>
        {
            while (!StateValue->Stop)
            {
                std::vector<std::uint8_t> Record;
                const auto ReadError = co_await Detail::ReadRecord(StateValue->Client, Record);
                if (ReadError != Error::None)
                {
                    if (StateValue->Stop)
                    {
                        co_return Error::None;
                    }
                    StateValue->Failure = ReadError;
                    Stop(StateValue, false);
                    co_return ReadError;
                }

                if (StateValue->ClientProtector && IsApplicationRecord(Record))
                {
                    std::vector<std::uint8_t> Payload;
                    const auto VerifyError = StateValue->ClientProtector->Decode(Record, Payload);
                    if (VerifyError == Error::None && !StateValue->Authenticated)
                    {
                        StateValue->FirstPayload = std::move(Payload);
                        StateValue->Authenticated = true;
                        Stop(StateValue, true);
                        co_return Error::None;
                    }
                }

                const auto ForwardError = co_await Detail::WriteAll(StateValue->Target, Record);
                if (ForwardError != Error::None)
                {
                    StateValue->Failure = ForwardError;
                    Stop(StateValue, false);
                    co_return ForwardError;
                }
            }
            co_return Error::None;
        }

        [[nodiscard]] auto TargetLoop(
            const std::shared_ptr<State> &StateValue) -> Net::awaitable<Error>
        {
            while (!StateValue->Stop)
            {
                std::vector<std::uint8_t> Record;
                const auto ReadError = co_await Detail::ReadRecord(StateValue->Target, Record);
                if (ReadError != Error::None)
                {
                    if (StateValue->Stop || StateValue->Authenticated)
                    {
                        co_return Error::None;
                    }
                    StateValue->Failure = ReadError;
                    Stop(StateValue, false);
                    co_return ReadError;
                }

                if (StateValue->ServerRandom.empty() && Record.size() >= TlsHdrsize + 6 && Record[5] == 2)
                {
                    ServerHelloRecord Parsed;
                    const auto ParseError = ParseServerHelloRecord(Record, Parsed);
                    if (ParseError != Error::None)
                    {
                        StateValue->Failure = ParseError;
                        Stop(StateValue, false);
                        co_return ParseError;
                    }
                    StateValue->ServerRandom.assign(Parsed.Random.begin(), Parsed.Random.end());
                    StateValue->ClientProtector.emplace(StateValue->Password, StateValue->ServerRandom, TagClient);
                    StateValue->FlightProtector.emplace(StateValue->Password, StateValue->ServerRandom, TagServer,
                                                        RecordSeed::ServerRandomOnly, true, false);
                    if (!StateValue->ClientProtector->IsValid() || !StateValue->FlightProtector->IsValid())
                    {
                        StateValue->Failure = Error::IoError;
                        Stop(StateValue, false);
                        co_return Error::IoError;
                    }
                }

                std::vector<std::uint8_t> Outbound = Record;
                if (StateValue->FlightProtector && IsApplicationRecord(Record))
                {
                    const auto PayloadWindow = std::span<const std::uint8_t>(Record).subspan(TlsHdrsize);
                    const auto EncodeError = StateValue->FlightProtector->Encode(
                        PayloadWindow,
                        Outbound);
                    if (EncodeError != Error::None)
                    {
                        StateValue->Failure = EncodeError;
                        Stop(StateValue, false);
                        co_return EncodeError;
                    }
                }
                const auto ForwardError = co_await Detail::WriteAll(StateValue->Client, Outbound);
                if (ForwardError != Error::None)
                {
                    if (StateValue->Stop || StateValue->Authenticated)
                    {
                        co_return Error::None;
                    }
                    StateValue->Failure = ForwardError;
                    Stop(StateValue, false);
                    co_return ForwardError;
                }
            }
            co_return Error::None;
        }

        ServerOptions Options_;
    };

} // namespace Preview::Shadowtls
