/**
 * @file SocksClient.hpp
 * @brief SOCKS5 测试客户端的 inline socket 与 wire 封装。
 */
#pragma once
#include "SocksCore.hpp"
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <array>
#include <chrono>
#include <span>
#include <thread>
namespace Prism::Testing::Socks5AccountIngress
{

    namespace
    {

        namespace Net = boost::asio;
        using Tcp = Net::ip::tcp;
        using Clock = std::chrono::steady_clock;
        using TimePoint = Clock::time_point;

        inline constexpr auto IoTimeout = std::chrono::milliseconds{1000};

        struct IoResult final
        {
            bool Success{false};
            std::size_t Transferred{0};
            std::string Error;
        };

        [[nodiscard]] auto ConnectSocket(Tcp::socket &Socket,
                                          const std::uint16_t Port,
                                          const TimePoint Deadline) -> bool
        {
            boost::system::error_code Error;
            Socket.connect(
                Tcp::endpoint(Net::ip::address_v4::loopback(), Port), Error);
            if (Error || Clock::now() >= Deadline)
            {
                return false;
            }
            Socket.non_blocking(true, Error);
            return !Error;
        }

        [[nodiscard]] auto WriteAll(Tcp::socket &Socket,
                                    const std::string_view Bytes,
                                    const TimePoint Deadline) -> IoResult
        {
            std::size_t Offset = 0;
            while (Offset < Bytes.size())
            {
                if (Clock::now() >= Deadline)
                {
                    return {false, Offset, "deadline_exceeded"};
                }
                boost::system::error_code Error;
                const auto Count = Socket.write_some(
                    Net::buffer(Bytes.data() + Offset, Bytes.size() - Offset), Error);
                if (!Error)
                {
                    if (Count == 0U)
                    {
                        return {false, Offset, "zero_byte_write"};
                    }
                    Offset += Count;
                    continue;
                }
                if (Error == Net::error::would_block || Error == Net::error::try_again)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                return {false, Offset, Error.message()};
            }
            return {true, Offset, {}};
        }

        template <typename Element, std::size_t Extent>
        [[nodiscard]] auto ReadExact(Tcp::socket &Socket,
                                     const std::span<Element, Extent> Bytes,
                                     const TimePoint Deadline) -> IoResult
        {
            std::size_t Offset = 0;
            while (Offset < Bytes.size())
            {
                if (Clock::now() >= Deadline)
                {
                    return {false, Offset, "deadline_exceeded"};
                }
                boost::system::error_code Error;
                const auto Count = Socket.read_some(
                    Net::buffer(Bytes.data() + Offset, Bytes.size() - Offset), Error);
                if (!Error)
                {
                    if (Count == 0U)
                    {
                        return {false, Offset, "zero_byte_read"};
                    }
                    Offset += Count;
                    continue;
                }
                if (Error == Net::error::would_block || Error == Net::error::try_again)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                return {false, Offset, Error.message()};
            }
            return {true, Offset, {}};
        }

        auto AppendHex(std::string &Output,
                       const std::span<const std::uint8_t> Bytes) -> void
        {
            static constexpr char Hex[] = "0123456789abcdef";
            for (const auto Byte : Bytes)
            {
                if (!Output.empty())
                {
                    Output.push_back(' ');
                }
                Output.push_back(Hex[Byte >> 4U]);
                Output.push_back(Hex[Byte & 0x0FU]);
            }
        }

        auto CloseSocket(Tcp::socket &Socket) noexcept -> void
        {
            boost::system::error_code Error;
            Socket.shutdown(Tcp::socket::shutdown_both, Error);
            Socket.close(Error);
        }

    } // namespace

    class Socks5Client::State final
    {
    public:
        boost::asio::io_context Io;
        boost::asio::ip::tcp::socket Socket{Io};
    };

    inline auto ConnectResult::Diagnostic() const -> std::string
    {
        const auto Error = SocketError.empty() ? std::string("none") : SocketError;
        const auto Wire = ReplyHex.empty() ? std::string("none") : ReplyHex;
        std::string Result = "stage=";
        Result += Stage;
        Result += " bytes_written=";
        Result += std::to_string(BytesWritten);
        Result += " bytes_received=";
        Result += std::to_string(BytesReceived);
        Result += " socket_error=";
        Result += Error;
        Result += " elapsed_ms=";
        Result += std::to_string(Elapsed.count());
        Result += " reply_hex=";
        Result += Wire;
        return Result;
    }

    inline Socks5Client::Socks5Client()
        : State_(std::make_unique<State>())
    {
    }

    inline Socks5Client::~Socks5Client()
    {
        Close();
    }

    inline auto Socks5Client::Connect(const std::uint16_t Port) -> bool
    {
        Close();
        return ConnectSocket(State_->Socket, Port, Clock::now() + IoTimeout);
    }

    inline auto Socks5Client::Authenticate(const std::string_view User,
                                    const std::string_view Password) -> UserPassResult
    {
        UserPassResult Result;
        if (!State_ || !State_->Socket.is_open() || User.size() > 255U || Password.size() > 255U)
        {
            return Result;
        }

        const auto Deadline = Clock::now() + IoTimeout;
        const std::array<std::uint8_t, 3> Greeting{0x05U, 0x01U, 0x02U};
        const std::string GreetingBytes(
            reinterpret_cast<const char *>(Greeting.data()), Greeting.size());
        if (!WriteAll(State_->Socket, GreetingBytes, Deadline).Success)
        {
            return Result;
        }

        std::array<std::uint8_t, 2> MethodReply{};
        if (!ReadExact(State_->Socket, std::span(MethodReply), Deadline).Success)
        {
            return Result;
        }
        if (MethodReply[0] != 0x05U || MethodReply[1] != 0x02U)
        {
            Result.TransportOk = true;
            Result.Status = MethodReply[1];
            return Result;
        }

        std::string Request;
        Request.reserve(3U + User.size() + Password.size());
        Request.push_back(static_cast<char>(0x01U));
        Request.push_back(static_cast<char>(User.size()));
        Request.append(User.data(), User.size());
        Request.push_back(static_cast<char>(Password.size()));
        Request.append(Password.data(), Password.size());
        if (!WriteAll(State_->Socket, Request, Deadline).Success)
        {
            return Result;
        }

        std::array<std::uint8_t, 2> AuthReply{};
        if (!ReadExact(State_->Socket, std::span(AuthReply), Deadline).Success ||
            AuthReply[0] != 0x01U)
        {
            return Result;
        }
        Result.TransportOk = true;
        Result.Status = AuthReply[1];
        return Result;
    }

    inline auto Socks5Client::ConnectTarget(const ConnectAttempt Attempt) -> ConnectResult
    {
        const auto Started = Clock::now();
        ConnectResult Result;
        const auto Finish = [&Result, Started]() -> ConnectResult
        {
            Result.Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                Clock::now() - Started);
            return Result;
        };
        if (!State_ || !State_->Socket.is_open() || Attempt.Host.empty() ||
            Attempt.Host.size() > 255U)
        {
            Result.Stage = "precondition";
            Result.SocketError = "invalid_client_state_or_target";
            return Finish();
        }

        const auto Deadline = Clock::now() + Attempt.ReplyTimeout;
        std::string Request;
        Request.reserve(7U + Attempt.Host.size());
        Request.push_back(static_cast<char>(0x05U));
        Request.push_back(static_cast<char>(0x01U));
        Request.push_back(static_cast<char>(0x00U));
        Request.push_back(static_cast<char>(0x03U));
        Request.push_back(static_cast<char>(Attempt.Host.size()));
        Request.append(Attempt.Host.data(), Attempt.Host.size());
        Request.push_back(static_cast<char>((Attempt.Port >> 8U) & 0xFFU));
        Request.push_back(static_cast<char>(Attempt.Port & 0xFFU));
        Result.Stage = "write_request";
        const auto RequestWrite = WriteAll(State_->Socket, Request, Deadline);
        Result.BytesWritten = RequestWrite.Transferred;
        if (!RequestWrite.Success)
        {
            Result.SocketError = RequestWrite.Error;
            return Finish();
        }

        std::array<std::uint8_t, 4> ReplyHeader{};
        Result.Stage = "read_header";
        const auto HeaderRead = ReadExact(State_->Socket, std::span(ReplyHeader), Deadline);
        Result.BytesReceived = HeaderRead.Transferred;
        AppendHex(Result.ReplyHex,
                   std::span<const std::uint8_t>(ReplyHeader.data(), HeaderRead.Transferred));
        if (!HeaderRead.Success)
        {
            Result.SocketError = HeaderRead.Error;
            return Finish();
        }
        Result.Reply = static_cast<Prism::Socks5::ReplyCode>(ReplyHeader[1]);
        Result.Stage = "validate_header";
        if (ReplyHeader[0] != 0x05U || ReplyHeader[2] != 0x00U)
        {
            Result.SocketError = "invalid_socks5_reply_header";
            return Finish();
        }

        std::size_t AddressSize = 0;
        if (ReplyHeader[3] == 0x01U)
        {
            AddressSize = 6U;
        }
        else if (ReplyHeader[3] == 0x04U)
        {
            AddressSize = 18U;
        }
        else if (ReplyHeader[3] == 0x03U)
        {
            std::array<std::uint8_t, 1> DomainSize{};
            Result.Stage = "read_address_length";
            const auto DomainRead = ReadExact(State_->Socket, std::span(DomainSize), Deadline);
            Result.BytesReceived += DomainRead.Transferred;
            AppendHex(Result.ReplyHex,
                       std::span<const std::uint8_t>(DomainSize.data(), DomainRead.Transferred));
            if (!DomainRead.Success)
            {
                Result.SocketError = DomainRead.Error;
                return Finish();
            }
            AddressSize = static_cast<std::size_t>(DomainSize[0]) + 2U;
        }
        else
        {
            Result.Stage = "validate_address_type";
            Result.SocketError = "unsupported_socks5_address_type";
            return Finish();
        }

        std::array<std::uint8_t, 18> Address{};
        Result.Stage = "validate_address_length";
        if (AddressSize > Address.size())
        {
            Result.SocketError = "socks5_address_too_large";
            return Finish();
        }
        Result.Stage = "read_address";
        const auto AddressRead = ReadExact(
            State_->Socket, std::span<std::uint8_t>(Address.data(), AddressSize), Deadline);
        Result.BytesReceived += AddressRead.Transferred;
        AppendHex(Result.ReplyHex,
                   std::span<const std::uint8_t>(Address.data(), AddressRead.Transferred));
        if (!AddressRead.Success)
        {
            Result.SocketError = AddressRead.Error;
            return Finish();
        }
        Result.TransportOk = true;
        Result.Stage = "complete";
        return Finish();
    }

    inline auto Socks5Client::Write(const std::string_view Bytes) -> bool
    {
        return State_ && State_->Socket.is_open() &&
               WriteAll(State_->Socket, Bytes, Clock::now() + IoTimeout).Success;
    }

    inline auto Socks5Client::Read(const std::size_t Size) -> std::optional<std::string>
    {
        if (!State_ || !State_->Socket.is_open())
        {
            return std::nullopt;
        }
        std::string Result(Size, '\0');
        if (!ReadExact(State_->Socket,
                       std::span<char>(Result.data(), Result.size()),
                       Clock::now() + IoTimeout)
                 .Success)
        {
            return std::nullopt;
        }
        return Result;
    }

    inline auto Socks5Client::ReadClosed() -> bool
    {
        if (!State_ || !State_->Socket.is_open())
        {
            return false;
        }
        std::array<char, 1> Buffer{};
        const auto Deadline = Clock::now() + IoTimeout;
        while (Clock::now() < Deadline)
        {
            boost::system::error_code Error;
            const auto Count = State_->Socket.read_some(Net::buffer(Buffer), Error);
            if (Count != 0U)
            {
                return false;
            }
            if (Error == Net::error::eof)
            {
                return true;
            }
            if (Error == Net::error::would_block || Error == Net::error::try_again)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            return false;
        }
        return false;
    }

    inline auto Socks5Client::Close() noexcept -> void
    {
        if (State_)
        {
            CloseSocket(State_->Socket);
        }
    }
} // namespace Prism::Testing::Socks5AccountIngress

