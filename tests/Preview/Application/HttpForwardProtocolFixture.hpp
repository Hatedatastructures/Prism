/**
 * @file HttpForwardProtocolFixture.hpp
 * @brief HTTP 入口客户端与 Operations inline 封装。
 */
#pragma once
#include "HttpForwardApplicationFixture.hpp"
#include <glaze/glaze.hpp>
#include <array>
#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>
#include <utility>
namespace Preview::Testing::HttpForward
{

    inline auto Connect(Tcp::socket &Socket, const std::uint16_t Port,
                 boost::system::error_code *Failure) -> bool
    {
        boost::system::error_code Error;
        Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Port), Error);
        if (Error)
        {
            if (Failure != nullptr)
            {
                *Failure = Error;
            }
            return false;
        }
        Socket.non_blocking(true, Error);
        if (Error && Failure != nullptr)
        {
            *Failure = Error;
        }
        return !Error;
    }

    inline auto WriteAll(Tcp::socket &Socket, const std::string_view Bytes) -> bool
    {
        std::size_t Offset = 0;
        const auto Deadline = std::chrono::steady_clock::now() + IoTimeout;
        while (Offset < Bytes.size() && std::chrono::steady_clock::now() < Deadline)
        {
            boost::system::error_code Error;
            const auto Count = Socket.write_some(
                Net::buffer(Bytes.data() + Offset, Bytes.size() - Offset), Error);
            if (!Error)
            {
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
        return Offset == Bytes.size();
    }

    auto ReadObservation::Description() const -> std::string
    {
        std::string Result;
        if (Closed)
        {
            Result = "closed";
        }
        else if (TimedOut)
        {
            Result = "timeout";
        }
        else if (Error)
        {
            Result = "read error: " + Error.message();
        }
        else
        {
            Result = "incomplete";
        }
        Result.append(" bytes=").append(std::to_string(Bytes.size()));
        if (!Bytes.empty())
        {
            Result.append(" prefix=").append(Bytes.substr(0, 256));
        }
        return Result;
    }

    inline auto ReadUntilClose(Tcp::socket &Socket, const std::chrono::milliseconds Timeout)
        -> ReadObservation
    {
        ReadObservation Result;
        std::array<char, 4096> Buffer{};
        const auto Deadline = std::chrono::steady_clock::now() + Timeout;
        while (std::chrono::steady_clock::now() < Deadline)
        {
            boost::system::error_code Error;
            const auto Count = Socket.read_some(Net::buffer(Buffer), Error);
            if (!Error)
            {
                Result.Bytes.append(Buffer.data(), Count);
                continue;
            }
            if (Error == Net::error::eof)
            {
                Result.Closed = true;
                return Result;
            }
            if (Error == Net::error::would_block || Error == Net::error::try_again)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            Result.Error = Error;
            return Result;
        }
        Result.TimedOut = true;
        return Result;
    }

    inline auto CloseSocket(Tcp::socket &Socket) -> void
    {
        boost::system::error_code Error;
        Socket.shutdown(Tcp::socket::shutdown_both, Error);
        Socket.close(Error);
    }

    inline auto MakeOriginHost(const std::uint16_t Port) -> std::string
    {
        return "127.0.0.1:" + std::to_string(Port);
    }


    namespace
    {

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

        [[nodiscard]] auto FindOperationsItems(const glz::generic &Document,
                                               std::string &State) -> const glz::generic *
        {
            if (!Document.is_object())
            {
                State = "root not object";
                return nullptr;
            }
            const auto *Status = FindJsonValue(Document, "status");
            if (Status == nullptr)
            {
                State = "missing status";
                return nullptr;
            }
            if (!Status->is_string())
            {
                State = "status not string";
                return nullptr;
            }
            const auto StatusText = std::string_view(Status->get<std::string>());
            if (StatusText != "ok")
            {
                State = "status=" + std::string(StatusText);
                return nullptr;
            }
            const auto *Value = FindJsonValue(Document, "value");
            if (Value == nullptr)
            {
                State = "missing value";
                return nullptr;
            }
            if (!Value->is_object())
            {
                State = "value not object";
                return nullptr;
            }
            const auto *Items = FindJsonValue(*Value, "items");
            if (Items == nullptr)
            {
                State = "missing items";
                return nullptr;
            }
            if (!Items->is_array())
            {
                State = "items not array";
                return nullptr;
            }
            State = "ok";
            return Items;
        }

        [[nodiscard]] auto OperationsResourcesEmpty(const std::string_view Sessions,
                                                    const std::string_view Accounts,
                                                    OperationsDrainObservation &Observation) -> bool
        {
            Observation.SessionItemCount.reset();
            Observation.SessionItemsState = "unknown";
            Observation.AccountsItemsParsed = false;
            Observation.AccountItemsState = "unknown";
            Observation.AccountActiveSessions.clear();
            const auto SessionsDocument = ParseOperationsBody(Sessions);
            const auto AccountsDocument = ParseOperationsBody(Accounts);
            bool Empty = true;
            if (!SessionsDocument)
            {
                Observation.SessionItemsState = "parse failed";
                Empty = false;
            }
            else
            {
                const auto *SessionItems =
                    FindOperationsItems(*SessionsDocument, Observation.SessionItemsState);
                if (SessionItems == nullptr)
                {
                    Empty = false;
                }
                else
                {
                    Observation.SessionItemCount = SessionItems->get_array().size();
                    Empty = Empty && SessionItems->get_array().empty();
                }
            }
            if (!AccountsDocument)
            {
                Observation.AccountItemsState = "parse failed";
                Empty = false;
            }
            else
            {
                const auto *AccountItems =
                    FindOperationsItems(*AccountsDocument, Observation.AccountItemsState);
                if (AccountItems == nullptr)
                {
                    Empty = false;
                }
                else
                {
                    Observation.AccountsItemsParsed = true;
                    Empty = Empty && !AccountItems->get_array().empty();
                    for (const auto &Account : AccountItems->get_array())
                    {
                        const auto *ActiveSessions = FindJsonValue(Account, "active_sessions");
                        if (ActiveSessions == nullptr)
                        {
                            Observation.AccountActiveSessions.emplace_back("missing");
                            Empty = false;
                            continue;
                        }
                        if (ActiveSessions->is_string())
                        {
                            const auto &Decimal = ActiveSessions->get<std::string>();
                            std::uint64_t Count = 0U;
                            const auto [End, ParseError] = std::from_chars(
                                Decimal.data(), Decimal.data() + Decimal.size(), Count);
                            if (ParseError != std::errc{} ||
                                End != Decimal.data() + Decimal.size())
                            {
                                Observation.AccountActiveSessions.emplace_back("invalid decimal");
                                Empty = false;
                                continue;
                            }
                            Observation.AccountActiveSessions.push_back(std::to_string(Count));
                            Empty = Empty && Count == 0U;
                            continue;
                        }
                        if (!ActiveSessions->is_number())
                        {
                            Observation.AccountActiveSessions.emplace_back("non-number");
                            Empty = false;
                            continue;
                        }
                        Observation.AccountActiveSessions.push_back(
                            std::to_string(ActiveSessions->get_number()));
                        Empty = Empty && ActiveSessions->get_number() == 0.0;
                    }
                }
            }
            return Empty;
        }

        [[nodiscard]] auto ReadOperationsQuery(const std::uint16_t Port,
                                                const std::string_view Target) -> OperationsQuery
        {
            OperationsQuery Result;
            Result.Target = Target;
            Net::io_context Io;
            Tcp::socket Socket(Io);
            if (!Connect(Socket, Port, &Result.Error))
            {
                return Result;
            }
            Result.Connected = true;
            const auto Request = "GET " + std::string(Target) +
                                 "?correlation=1 HTTP/1.1\r\n"
                                 "Host: 127.0.0.1:" + std::to_string(Port) +
                                 "\r\n"
                                 "Connection: close\r\n\r\n";
            if (!WriteAll(Socket, Request))
            {
                CloseSocket(Socket);
                return Result;
            }
            Result.RequestWritten = true;
            Result.Read = ReadUntilClose(Socket);
            CloseSocket(Socket);
            return Result;
        }

    } // namespace

    inline auto OperationsQuery::StatusLine() const -> std::string
    {
        if (Read.Bytes.empty())
        {
            return "none";
        }
        const auto LineEnd = Read.Bytes.find("\r\n");
        return LineEnd == std::string::npos ? "partial"
                                             : Read.Bytes.substr(0, LineEnd);
    }

    inline auto OperationsQuery::Description() const -> std::string
    {
        std::string Result = Target;
        Result.append(" status=").append(StatusLine());
        if (Error)
        {
            Result.append(" error=").append(Error.message());
        }
        else if (!Connected)
        {
            Result.append(" error=connect failed");
        }
        else if (!RequestWritten)
        {
            Result.append(" error=write failed");
        }
        else if (Read.TimedOut)
        {
            Result.append(" error=timeout");
        }
        else if (Read.Error)
        {
            Result.append(" error=read: ").append(Read.Error.message());
        }
        else if (!Read.Closed)
        {
            Result.append(" error=incomplete");
        }
        Result.append(" bytes=").append(std::to_string(Read.Bytes.size()));
        return Result;
    }

    inline auto OperationsDrainObservation::Description() const -> std::string
    {
        std::string Result = Sessions.Description();
        Result.append(" sessions_items=");
        if (SessionItemCount)
        {
            Result.append(std::to_string(*SessionItemCount));
        }
        else
        {
            Result.append(SessionItemsState);
        }
        Result.append("; ").append(Accounts.Description());
        Result.append(" accounts_active_sessions=");
        if (!AccountsItemsParsed)
        {
            return Result.append(AccountItemsState);
        }
        Result.push_back('[');
        for (std::size_t Index = 0; Index < AccountActiveSessions.size(); ++Index)
        {
            if (Index != 0U)
            {
                Result.append(", ");
            }
            Result.append(AccountActiveSessions[Index]);
        }
        return Result.append("]");
    }

    inline auto ReadOperationsSessions(const std::uint16_t Port) -> OperationsQuery
    {
        return ReadOperationsQuery(Port, "/Operations/Sessions");
    }

    inline auto ReadOperationsAccounts(const std::uint16_t Port) -> OperationsQuery
    {
        return ReadOperationsQuery(Port, "/Operations/Accounts");
    }

    inline auto WaitForResourcesEmpty(const std::uint16_t Port,
                               const std::chrono::milliseconds Timeout,
                               OperationsDrainObservation *Last) -> bool
    {
        const auto Deadline = std::chrono::steady_clock::now() + Timeout;
        while (std::chrono::steady_clock::now() < Deadline)
        {
            auto Sessions = ReadOperationsSessions(Port);
            auto Accounts = ReadOperationsAccounts(Port);
            OperationsDrainObservation Current;
            Current.Sessions = std::move(Sessions);
            Current.Accounts = std::move(Accounts);
            const auto Empty = OperationsResourcesEmpty(Current.Sessions.Read.Bytes,
                                                         Current.Accounts.Read.Bytes, Current);
            if (Last != nullptr)
            {
                *Last = std::move(Current);
            }
            if (Empty)
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return false;
    }
} // namespace Preview::Testing::HttpForward

