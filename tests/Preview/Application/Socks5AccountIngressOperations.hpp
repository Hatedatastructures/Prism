/**
 * @file Socks5AccountIngressOperations.hpp
 * @brief SOCKS5 入口 Operations 查询的 inline 封装。
 */
#pragma once
#include "Socks5AccountIngressCore.hpp"
#include <glaze/glaze.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
namespace Preview::Testing::Socks5AccountIngress
{

    namespace
    {

        namespace Net = boost::asio;
        using Tcp = Net::ip::tcp;
        using Clock = std::chrono::steady_clock;
        using TimePoint = Clock::time_point;

        inline constexpr auto OperationsWaitTimeout = std::chrono::seconds{4};

        [[nodiscard]] auto OperationsConnectSocket(Tcp::socket &Socket,
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

        [[nodiscard]] auto OperationsWriteAll(Tcp::socket &Socket,
                                    const std::string_view Bytes,
                                    const TimePoint Deadline) -> bool
        {
            std::size_t Offset = 0;
            while (Offset < Bytes.size())
            {
                if (Clock::now() >= Deadline)
                {
                    return false;
                }
                boost::system::error_code Error;
                const auto Count = Socket.write_some(
                    Net::buffer(Bytes.data() + Offset, Bytes.size() - Offset), Error);
                if (!Error)
                {
                    if (Count == 0U)
                    {
                        return false;
                    }
                    Offset += Count;
                    continue;
                }
                if (Error == Net::error::would_block || Error == Net::error::try_again)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                return false;
            }
            return true;
        }

        [[nodiscard]] auto OperationsReadUntilClose(Tcp::socket &Socket,
                                          const TimePoint Deadline) -> std::string
        {
            std::array<char, 4096> Buffer{};
            std::string Response;
            while (Clock::now() < Deadline)
            {
                boost::system::error_code Error;
                const auto Count = Socket.read_some(Net::buffer(Buffer), Error);
                if (Count != 0U)
                {
                    Response.append(Buffer.data(), Count);
                }
                if (!Error)
                {
                    continue;
                }
                if (Error == Net::error::eof)
                {
                    return Response;
                }
                if (Error == Net::error::would_block || Error == Net::error::try_again)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                return Response;
            }
            return Response;
        }

        auto OperationsCloseSocket(Tcp::socket &Socket) noexcept -> void
        {
            boost::system::error_code Error;
            Socket.shutdown(Tcp::socket::shutdown_both, Error);
            Socket.close(Error);
        }

        [[nodiscard]] auto SendOperationsWire(const std::uint16_t Port,
                                              const std::string_view Wire,
                                              const TimePoint Deadline) -> std::string
        {
            Net::io_context Io;
            Tcp::socket Socket(Io);
            if (!OperationsConnectSocket(Socket, Port, Deadline) ||
                !OperationsWriteAll(Socket, Wire, Deadline))
            {
                OperationsCloseSocket(Socket);
                return {};
            }
            auto Response = OperationsReadUntilClose(Socket, Deadline);
            OperationsCloseSocket(Socket);
            return Response;
        }

        [[nodiscard]] auto ReadOperationsCommandToken(const std::string_view Response)
            -> std::optional<std::string>
        {
            constexpr std::string_view Key{"\"command_token\":\""};
            const auto HeaderEnd = Response.find("\r\n\r\n");
            if (HeaderEnd == std::string_view::npos)
            {
                return std::nullopt;
            }
            const auto Begin = Response.find(Key, HeaderEnd + 4U);
            if (Begin == std::string_view::npos)
            {
                return std::nullopt;
            }
            const auto First = Begin + Key.size();
            const auto End = Response.find('"', First);
            if (End == std::string_view::npos || End - First != 64U)
            {
                return std::nullopt;
            }
            for (const auto Character : Response.substr(First, End - First))
            {
                const auto IsDigit = Character >= '0' && Character <= '9';
                const auto IsLowerHex = Character >= 'a' && Character <= 'f';
                const auto IsUpperHex = Character >= 'A' && Character <= 'F';
                if (!IsDigit && !IsLowerHex && !IsUpperHex)
                {
                    return std::nullopt;
                }
            }
            return std::string(Response.substr(First, End - First));
        }

        [[nodiscard]] auto ReadOperationsCommandToken(const std::uint16_t Port,
                                                      const TimePoint Deadline)
            -> std::optional<std::string>
        {
            const auto Authority = "127.0.0.1:" + std::to_string(Port);
            const auto Wire = "GET /Operations/Bootstrap HTTP/1.1\r\nHost: " +
                Authority + "\r\nConnection: close\r\n\r\n";
            return ReadOperationsCommandToken(SendOperationsWire(Port, Wire, Deadline));
        }

        [[nodiscard]] auto FindJsonValue(const glz::generic &Document,
                                         const std::string_view Key) -> const glz::generic *
        {
            if (!Document.is_object())
            {
                return nullptr;
            }
            const auto &Object = Document.get_object();
            const auto Found = Object.find(Key);
            return Found == Object.end() ? nullptr : &Found->second;
        }

        [[nodiscard]] auto ParseOperationsBody(const std::string_view Response)
            -> std::optional<glz::generic>
        {
            const auto HeaderEnd = Response.find("\r\n\r\n");
            if (HeaderEnd == std::string_view::npos)
            {
                return std::nullopt;
            }
            glz::generic Document;
            if (glz::read_json(Document, Response.substr(HeaderEnd + 4U)))
            {
                return std::nullopt;
            }
            return Document;
        }

        [[nodiscard]] auto FindOperationsItems(const glz::generic &Document)
            -> const glz::generic *
        {
            const auto *Status = FindJsonValue(Document, "status");
            if (Status == nullptr || !Status->is_string() ||
                Status->get<std::string>() != "ok")
            {
                return nullptr;
            }
            const auto *Value = FindJsonValue(Document, "value");
            if (Value == nullptr || !Value->is_object())
            {
                return nullptr;
            }
            const auto *Items = FindJsonValue(*Value, "items");
            return Items != nullptr && Items->is_array() ? Items : nullptr;
        }

        [[nodiscard]] auto MatchesOperations(const OperationsSnapshot &Snapshot,
                                             const bool Active) -> bool
        {
            const auto Accounts = ParseOperationsBody(Snapshot.Accounts);
            const auto Sessions = ParseOperationsBody(Snapshot.Sessions);
            if (!Accounts || !Sessions)
            {
                return false;
            }

            const auto *AccountItems = FindOperationsItems(*Accounts);
            const auto *SessionItems = FindOperationsItems(*Sessions);
            if (AccountItems == nullptr || SessionItems == nullptr)
            {
                return false;
            }
            if (AccountItems->get_array().size() != 1U)
            {
                return false;
            }
            if (SessionItems->get_array().size() != (Active ? 1U : 0U))
            {
                return false;
            }

            const auto *ActiveSessions =
                FindJsonValue(AccountItems->get_array().front(), "active_sessions");
            return ActiveSessions != nullptr && ActiveSessions->is_number() &&
                   ActiveSessions->get_number() == (Active ? 1.0 : 0.0);
        }

        struct OperationsRequest final
        {
            std::string_view Method;
            std::string_view Target;
        };

        [[nodiscard]] auto SendOperations(const std::uint16_t Port,
                                           const OperationsRequest RequestValue,
                                           const TimePoint Deadline) -> std::string
        {
            std::string Authorization;
            if (RequestValue.Method == "POST")
            {
                const auto Token = ReadOperationsCommandToken(Port, Deadline);
                if (!Token)
                {
                    return {};
                }
                Authorization = "Authorization: Bearer " + *Token + "\r\n";
            }
            auto Target = std::string(RequestValue.Target);
            if (RequestValue.Method == "GET")
            {
                Target += "?correlation=1";
            }
            std::string Wire = std::string(RequestValue.Method) + " " + Target +
                               " HTTP/1.1\r\nHost: 127.0.0.1:" +
                               std::to_string(Port) + "\r\nConnection: close\r\n" +
                               Authorization;
            if (RequestValue.Method == "POST")
            {
                Wire += "Content-Length: 0\r\n";
            }
            Wire += "\r\n";
            return SendOperationsWire(Port, Wire, Deadline);
        }

        [[nodiscard]] auto QueryOperations(const std::uint16_t Port,
                                            const std::string_view Target,
                                            const TimePoint Deadline) -> std::string
        {
            return SendOperations(Port, OperationsRequest{"GET", Target}, Deadline);
        }

    } // namespace

    inline auto Socks5AccountIngressFixture::WaitForOperations(const bool Active)
        -> OperationsWaitResult
    {
        OperationsWaitResult Result;
        if (State_ == nullptr)
        {
            return Result;
        }

        const auto Deadline = Clock::now() + OperationsWaitTimeout;
        while (Clock::now() < Deadline)
        {
            OperationsSnapshot Current;
            Current.Accounts = QueryOperations(State_->OperationsPort(),
                                               "/Operations/Accounts", Deadline);
            Current.Sessions = QueryOperations(State_->OperationsPort(),
                                               "/Operations/Sessions", Deadline);
            Result.Last = Current;
            if (MatchesOperations(Current, Active))
            {
                Result.Matched = true;
                return Result;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return Result;
    }

    inline auto Socks5AccountIngressFixture::CommandOperations(const std::string_view Target)
        -> std::string
    {
        if (State_ == nullptr)
        {
            return {};
        }
        return SendOperations(State_->OperationsPort(), OperationsRequest{"POST", Target},
                              Clock::now() + OperationsWaitTimeout);
    }
} // namespace Preview::Testing::Socks5AccountIngress

