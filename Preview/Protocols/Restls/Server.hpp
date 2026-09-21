/**
 * @file Server.hpp
 * @brief Restls 服务端中间人握手与首帧接管。
 * @details 将客户端 TLS flight 转发到真实后端，提取 ServerHello random，
 *          对后端首个 ApplicationData 应用 ServerMask，并在捕获客户端
 *          首个加密记录后把原始连接交给 Restls Conn。
 */
#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Restls/Codec.hpp>
#include <Preview/Protocols/Restls/Conn.hpp>
#include <Preview/Protocols/Restls/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Restls
{

    namespace Net = boost::asio;
    using Net::experimental::awaitable_operators::operator||;

    /** @brief Restls 后端拨号回调。 */
    using DialTargetFn = std::function<Net::awaitable<std::pair<Preview::Fault::Code,
                                                                  SharedTransmission>>(
        std::span<const std::uint8_t>)>;

    /** @brief Restls 服务端认证配置。 */
    struct ServerConfig final
    {
        std::string password;
        bool Tls13{false}; ///< 允许 TLS 1.3 加密 close_notify 作为 clean EOF
    };

    /** @brief Restls 服务端中间人配置。 */
    struct ServerOptions final
    {
        DialTargetFn DialTarget;
    };

    /** @brief Restls 服务端握手结果。 */
    struct ServerResult final
    {
        Error Status{Error::None};
        Preview::Fault::Code FaultCode{Preview::Fault::Code::Success};
        SharedConn Connection{};
    };

    namespace Detail
    {

        [[nodiscard]] inline auto MapIoError(const std::error_code &ErrorCode) noexcept -> Error
        {
            if (ErrorCode == std::make_error_code(std::errc::operation_canceled))
            {
                return Error::Canceled;
            }
            if (ErrorCode == std::make_error_code(std::errc::timed_out))
            {
                return Error::Timeout;
            }
            return Error::IoError;
        }

        [[nodiscard]] inline auto ReadExact(
            const SharedTransmission &Transport,
            std::span<std::uint8_t> Buffer) -> Net::awaitable<Error>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code ErrorCode;
                const auto Read = co_await Transport->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(Buffer.data() + Offset),
                                         Buffer.size() - Offset),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return MapIoError(ErrorCode);
                }
                if (Read == 0 || Read > Buffer.size() - Offset)
                {
                    co_return Error::UnexpectedEof;
                }
                Offset += Read;
            }
            co_return Error::None;
        }

        [[nodiscard]] inline auto ReadRecord(
            const SharedTransmission &Transport,
            std::vector<std::uint8_t> &Record) -> Net::awaitable<Error>
        {
            Record.clear();
            std::array<std::uint8_t, TlsHdrlen> Header{};
            const auto HeaderError = co_await ReadExact(Transport, Header);
            if (HeaderError != Error::None)
            {
                co_return HeaderError;
            }
            const auto PayloadLength = (static_cast<std::size_t>(Header[3]) << 8U) | Header[4];
            if (PayloadLength == 0 || PayloadLength > 0xffffU)
            {
                co_return Error::BadLength;
            }
            Record.resize(TlsHdrlen + PayloadLength);
            std::copy(Header.begin(), Header.end(), Record.begin());
            co_return co_await ReadExact(
                Transport,
                std::span<std::uint8_t>(Record).subspan(TlsHdrlen));
        }

        [[nodiscard]] inline auto WriteAll(
            const SharedTransmission &Transport,
            std::span<const std::uint8_t> Buffer) -> Net::awaitable<Error>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code ErrorCode;
                const auto Written = co_await Transport->async_write_some(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Buffer.data() + Offset),
                        Buffer.size() - Offset),
                    ErrorCode);
                if (ErrorCode)
                {
                    co_return MapIoError(ErrorCode);
                }
                if (Written == 0 || Written > Buffer.size() - Offset)
                {
                    co_return Error::IoError;
                }
                Offset += Written;
            }
            co_return Error::None;
        }

        auto Stop(const SharedTransmission &Transport) -> void
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
     * @brief 单个 Restls 服务端中间人会话。
     */
    class ServerSession final
    {
    private:
        struct State final
        {
            explicit State(Net::any_io_executor Executor) : Signal(std::move(Executor))
            {
                Signal.expires_at(std::chrono::steady_clock::time_point::max());
            }

            SharedTransmission Client;
            SharedTransmission Target;
            std::array<std::uint8_t, 32> Secret{};
            std::array<std::uint8_t, 32> ServerRandom{};
            std::vector<std::uint8_t> ClientFinished;
            std::vector<std::uint8_t> FirstEncrypted;
            Error Failure{Error::None};
            bool Stop{false};
            Net::steady_timer Signal;
        };

    public:
        explicit ServerSession(ServerOptions Options) : Options_(std::move(Options))
        {
        }

        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;

        /**
         * @brief 完成一次 Restls 中间人握手。
         * @param Inbound 客户端原始传输，所有权移交
         * @param Config Restls 密码配置
         * @return 已完成首帧接管的 Conn
         */
        [[nodiscard]] auto Run(
            SharedTransmission Inbound,
            const ServerConfig &Config) -> Net::awaitable<ServerResult>
        {
            ServerResult Result;
            if (!Inbound || !Options_.DialTarget || Config.password.empty())
            {
                Detail::Stop(Inbound);
                Result.Status = !Inbound ? Error::NotOpen : Error::NotSupported;
                co_return Result;
            }

            std::vector<std::uint8_t> ClientHello;
            const auto ClientHelloError = co_await Detail::ReadRecord(Inbound, ClientHello);
            if (ClientHelloError != Error::None || ClientHello.empty() || ClientHello[0] != 0x16)
            {
                Detail::Stop(Inbound);
                Result.FaultCode = Preview::Fault::Code::ProtocolError;
                Result.Status = ClientHelloError == Error::None
                                    ? Error::BadMessage
                                    : ClientHelloError;
                co_return Result;
            }

            SharedTransmission Target;
            try
            {
                auto DialResult = co_await Options_.DialTarget(
                    std::span<const std::uint8_t>(ClientHello));
                Result.FaultCode = DialResult.first;
                Target = std::move(DialResult.second);
            }
            catch (...)
            {
                Detail::Stop(Inbound);
                Result.FaultCode = Preview::Fault::Code::ConnectionRefused;
                Result.Status = Error::IoError;
                co_return Result;
            }
            if (!Target)
            {
                Detail::Stop(Inbound);
                if (Result.FaultCode == Preview::Fault::Code::Success)
                {
                    Result.FaultCode = Preview::Fault::Code::BadGateway;
                }
                Result.Status = Error::IoError;
                co_return Result;
            }
            Result.FaultCode = Preview::Fault::Code::BadGateway;

            auto StateValue = std::make_shared<State>(Inbound->Executor());
            StateValue->Client = Inbound;
            StateValue->Target = Target;
            StateValue->Secret = DeriveSecret(Config.password);

            auto ForwardError = co_await Detail::WriteAll(
                Target, std::span<const std::uint8_t>(ClientHello));
            if (ForwardError != Error::None)
            {
                Stop(StateValue);
                Result.FaultCode = Preview::Fault::Code::BadGateway;
                Result.Status = ForwardError;
                co_return Result;
            }

            std::vector<std::uint8_t> ServerHello;
            const auto ServerHelloError = co_await Detail::ReadRecord(Target, ServerHello);
            const auto ParsedRandom = ParseServerHelloRandom(ServerHello);
            if (ServerHelloError != Error::None || !ParsedRandom)
            {
                Stop(StateValue);
                Result.FaultCode = Preview::Fault::Code::BadGateway;
                Result.Status = ServerHelloError == Error::None
                                    ? Error::BadMessage
                                    : ServerHelloError;
                co_return Result;
            }
            StateValue->ServerRandom = *ParsedRandom;
            ForwardError = co_await Detail::WriteAll(
                Inbound, std::span<const std::uint8_t>(ServerHello));
            if (ForwardError != Error::None)
            {
                Stop(StateValue);
                Result.FaultCode = Preview::Fault::Code::IoError;
                Result.Status = ForwardError;
                co_return Result;
            }

            (void)co_await (ClientLoop(StateValue) || BackendLoop(StateValue));
            if (StateValue->Failure != Error::None ||
                StateValue->ClientFinished.empty() || StateValue->FirstEncrypted.empty())
            {
                Stop(StateValue);
                Result.FaultCode = Preview::Fault::Code::BadGateway;
                Result.Status = StateValue->Failure == Error::None
                                    ? Error::BadAuth
                                    : StateValue->Failure;
                co_return Result;
            }

            auto Connection = std::make_shared<Conn<>>(std::move(Inbound), Config.password);
            const auto InitError = co_await Connection->ReadHandshake(
                StateValue->ServerRandom, StateValue->ClientFinished);
            Detail::Stop(Target);
            if (InitError != Error::None)
            {
                Connection->Close();
                Result.Status = InitError;
                co_return Result;
            }
            if (Config.Tls13)
            {
                Connection->AllowTls13EncryptedCloseNotify();
            }
            Result.Connection = std::move(Connection);
            Result.Status = Error::None;
            Result.FaultCode = Preview::Fault::Code::Success;
            co_return Result;
        }

    private:
        static auto Stop(const std::shared_ptr<State> &StateValue) -> void
        {
            StateValue->Stop = true;
            Detail::Stop(StateValue->Target);
            StateValue->Signal.cancel();
        }

        [[nodiscard]] static auto IsApplicationData(
            const std::vector<std::uint8_t> &Record) noexcept -> bool
        {
            return Record.size() >= TlsHdrlen && Record[0] == TlsApplicationData;
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
                    if (!StateValue->Stop)
                    {
                        StateValue->Failure = ReadError;
                        Stop(StateValue);
                    }
                    co_return ReadError;
                }
                if (IsApplicationData(Record) && StateValue->ClientFinished.empty())
                {
                    StateValue->ClientFinished = Record;
                    const auto ForwardError = co_await Detail::WriteAll(
                        StateValue->Target, std::span<const std::uint8_t>(Record));
                    if (ForwardError != Error::None)
                    {
                        StateValue->Failure = ForwardError;
                    }
                    if (StateValue->FirstEncrypted.empty() && StateValue->Failure == Error::None)
                    {
                        boost::system::error_code WaitError;
                        co_await StateValue->Signal.async_wait(
                            Net::redirect_error(Net::use_awaitable, WaitError));
                    }
                    Stop(StateValue);
                    co_return StateValue->Failure;
                }
                const auto ForwardError = co_await Detail::WriteAll(
                    StateValue->Target, std::span<const std::uint8_t>(Record));
                if (ForwardError != Error::None)
                {
                    StateValue->Failure = ForwardError;
                    Stop(StateValue);
                    co_return ForwardError;
                }
            }
            co_return Error::None;
        }

        [[nodiscard]] auto BackendLoop(
            const std::shared_ptr<State> &StateValue) -> Net::awaitable<Error>
        {
            while (!StateValue->Stop)
            {
                std::vector<std::uint8_t> Record;
                const auto ReadError = co_await Detail::ReadRecord(StateValue->Target, Record);
                if (ReadError != Error::None)
                {
                    if (!StateValue->Stop)
                    {
                        StateValue->Failure = ReadError;
                        Stop(StateValue);
                    }
                    co_return ReadError;
                }
                if (IsApplicationData(Record) && StateValue->FirstEncrypted.empty())
                {
                    StateValue->FirstEncrypted = Record;
                    const auto Protected = ProtectFirstEncrypted(
                        Record,
                        std::span<const std::uint8_t, 32>(StateValue->Secret),
                        std::span<const std::uint8_t, 32>(StateValue->ServerRandom));
                    if (Protected.first != Error::None)
                    {
                        StateValue->Failure = Protected.first;
                        Stop(StateValue);
                        co_return Protected.first;
                    }
                    const auto ForwardError = co_await Detail::WriteAll(
                        StateValue->Client, std::span<const std::uint8_t>(Protected.second));
                    if (ForwardError != Error::None)
                    {
                        StateValue->Failure = ForwardError;
                        Stop(StateValue);
                        co_return ForwardError;
                    }
                    StateValue->Signal.cancel();
                    if (!StateValue->ClientFinished.empty())
                    {
                        Stop(StateValue);
                    }
                    continue;
                }
                const auto ForwardError = co_await Detail::WriteAll(
                    StateValue->Client, std::span<const std::uint8_t>(Record));
                if (ForwardError != Error::None)
                {
                    if (!StateValue->Stop)
                    {
                        StateValue->Failure = ForwardError;
                        Stop(StateValue);
                    }
                    co_return ForwardError;
                }
            }
            co_return Error::None;
        }

        ServerOptions Options_;
    };

} // namespace Preview::Restls
