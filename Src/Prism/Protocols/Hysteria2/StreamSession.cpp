/**
 * @file StreamSession.cpp
 * @brief Hysteria2 stream 会话实现。
 */
#include <Prism/Protocols/Hysteria2/StreamSession.hpp>
#include <Prism/Protocols/Quic/StreamAdapter.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Hysteria2
{
    namespace StreamDetail
    {
        auto ReadVarint(
            const std::span<const std::byte> Data,
            std::size_t &Offset,
            std::uint64_t &Value) -> ParseResult
        {
            if (Offset >= Data.size())
            {
                return ParseResult::NeedMore;
            }
            const auto First = std::to_integer<std::uint8_t>(Data[Offset]);
            const auto Width = std::size_t{1U} << (First >> 6U);
            if (Width > Data.size() - Offset)
            {
                return ParseResult::NeedMore;
            }
            Value = First & 0x3FU;
            for (std::size_t Index = 1; Index < Width; ++Index)
            {
                Value = (Value << 8U) | std::to_integer<std::uint8_t>(Data[Offset + Index]);
            }
            Offset += Width;
            return ParseResult::Ready;
        }

        auto ParseRawRequest(
            const std::span<const std::byte> Data,
            RawRequest &Output) -> ParseResult
        {
            constexpr std::uint64_t TcpFrame{0x401};
            constexpr std::size_t MaxAddress{2048};
            constexpr std::size_t MaxPadding{4096};
            std::size_t Offset = 0;
            std::uint64_t Value = 0;
            auto Result = ReadVarint(Data, Offset, Value);
            if (Result != ParseResult::Ready)
            {
                return Result;
            }
            if (Value != TcpFrame)
            {
                return ParseResult::Invalid;
            }
            Result = ReadVarint(Data, Offset, Value);
            if (Result != ParseResult::Ready)
            {
                return Result;
            }
            if (Value == 0 || Value > MaxAddress)
            {
                return Value > MaxAddress ? ParseResult::Invalid : ParseResult::NeedMore;
            }
            if (Value > Data.size() - Offset)
            {
                return ParseResult::NeedMore;
            }
            const auto AddressText = std::string_view(
                reinterpret_cast<const char *>(Data.data() + Offset),
                static_cast<std::size_t>(Value));
            std::string_view Host;
            std::string_view PortText;
            if (AddressText.starts_with('['))
            {
                const auto Close = AddressText.find(']');
                if (Close == std::string_view::npos || Close + 2 > AddressText.size() ||
                    AddressText[Close + 1] != ':')
                {
                    return ParseResult::Invalid;
                }
                Host = AddressText.substr(1, Close - 1);
                PortText = AddressText.substr(Close + 2);
            }
            else
            {
                const auto Separator = AddressText.rfind(':');
                if (Separator == std::string_view::npos || Separator == 0 ||
                    Separator + 1 >= AddressText.size())
                {
                    return ParseResult::Invalid;
                }
                Host = AddressText.substr(0, Separator);
                PortText = AddressText.substr(Separator + 1);
            }
            std::uint32_t Port = 0;
            const auto PortResult = std::from_chars(
                PortText.data(), PortText.data() + PortText.size(), Port);
            if (Host.empty() || PortResult.ec != std::errc{} ||
                PortResult.ptr != PortText.data() + PortText.size() || Port == 0 || Port > 65535)
            {
                return ParseResult::Invalid;
            }
            auto ParsedHost = Prism::Network::ParseHost(Host);
            if (!ParsedHost) return ParseResult::Invalid;
            Output.Target = {
                std::move(*ParsedHost),
                static_cast<std::uint16_t>(Port),
                Prism::Network::RouteKind::Forward};
            Offset += static_cast<std::size_t>(Value);
            Result = ReadVarint(Data, Offset, Value);
            if (Result != ParseResult::Ready)
            {
                return Result;
            }
            if (Value > MaxPadding)
            {
                return ParseResult::Invalid;
            }
            if (Value > Data.size() - Offset)
            {
                return ParseResult::NeedMore;
            }
            Output.Consumed = Offset + static_cast<std::size_t>(Value);
            return ParseResult::Ready;
        }

        auto WriteTcpResponseHeader(
            const Prism::Quic::SharedStreamProvider &Provider) -> Net::awaitable<bool>
        {
            const std::array<std::byte, 3> Header{std::byte{0}, std::byte{0}, std::byte{0}};
            std::size_t Offset = 0;
            while (Offset < Header.size())
            {
                std::error_code Error;
                const auto Written =
                    co_await Provider->Write(std::span<const std::byte>(Header).subspan(Offset), Error);
                if (Error || Written == 0 || Written > Header.size() - Offset)
                {
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }
    }

    auto StreamSession::Create(Options OptionsValue) -> std::shared_ptr<StreamSession>
    {
        if (!OptionsValue.Executor || !OptionsValue.Provider || !OptionsValue.Lease)
        {
            return {};
        }
        return std::shared_ptr<StreamSession>(new StreamSession(std::move(OptionsValue)));
    }

    StreamSession::StreamSession(Options OptionsValue)
        : Options_(std::move(OptionsValue)), Cancellation_(std::make_shared<Net::cancellation_signal>())
    {
    }

    StreamSession::~StreamSession() noexcept
    {
        Close();
    }

    auto StreamSession::Start() -> void
    {
        if (Started_)
        {
            return;
        }
        Started_ = true;
        auto Self = shared_from_this();
        Net::co_spawn(Options_.Executor, Self->Run(),
            Net::bind_cancellation_slot(Cancellation_->slot(),
                [Self](std::exception_ptr Error)
                {
                    Self->Complete(Error?Prism::Fault::Code::GenericError:Self->Result_);
                }));
    }

    auto StreamSession::Close() noexcept -> void
    {
        if (Cancellation_)
        {
            Cancellation_->emit(Net::cancellation_type::all);
        }
        if (Options_.Provider)
        {
            try
            {
                const auto Closed = Options_.Provider->Close();
                if (!Closed) Result_ = Closed.error().Code;
            }
            catch (...)
            {
                Result_ = Prism::Fault::Code::GenericError;
            }
        }
        if (Outbound_)
        {
            try
            {
                const auto Closed = Outbound_->Close();
                if (!Closed) Result_ = Closed.error().Code;
            }
            catch (...)
            {
                Result_ = Prism::Fault::Code::GenericError;
            }
        }
    }

    auto StreamSession::Run() -> Net::awaitable<void>
    {
        auto Status = Prism::Fault::Code::Success;
        try
        {
            std::vector<std::byte> Wire;
            Wire.reserve(2048);
            RawRequest Request;
            ParseResult Parsed = ParseResult::NeedMore;
            std::optional<Prism::Fault::Failure> InitialReadTerminal;
            std::array<std::byte, 16384> Buffer{};
            while (Parsed == ParseResult::NeedMore)
            {
                std::error_code Error;
                const auto Count = co_await Options_.Provider->Read(Buffer, Error);
                if (Count > Buffer.size())
                {
                    Status = Prism::Fault::Code::InvalidArgument;
                    Result_=Status;
                    co_return;
                }
                if (Count != 0)
                {
                    Wire.insert(Wire.end(), Buffer.begin(), Buffer.begin() + Count);
                    Parsed = ParseRawRequest(Wire, Request);
                }
                if (Error)
                {
                    const auto Failure = Prism::Fault::FromNative(Error);
                    if (Failure.Code != Prism::Fault::Code::Eof)
                    {
                        Status = Failure.Code;
                        Result_=Status;
                        co_return;
                    }
                    if (Parsed != ParseResult::Ready)
                    {
                        Status = Wire.empty() ? Prism::Fault::Code::Eof
                                              : Prism::Fault::Code::BadMessage;
                        Result_=Status;
                        co_return;
                    }
                    InitialReadTerminal = Failure;
                }
                if (Count == 0)
                {
                    Status = Wire.empty() ? Prism::Fault::Code::Eof
                                          : Prism::Fault::Code::BadMessage;
                    Result_=Status;
                    co_return;
                }
            }
            if (Parsed != ParseResult::Ready)
            {
                Status = Prism::Fault::Code::BadMessage;
                Result_=Status;
                co_return;
            }
            if (!Options_.Services.Dial)
            {
                Status = Prism::Fault::Code::NotSupported;
                Result_=Status;
                co_return;
            }
            auto Dialed = co_await Options_.Services.Dial(DialRequest{Request.Target});
            if (!Dialed)
            {
                Status = Dialed.error().Code;
                if (Status == Prism::Fault::Code::Success)
                {
                    Status = Prism::Fault::Code::BadGateway;
                }
                Result_=Status;
                co_return;
            }
            Outbound_ = std::move(*Dialed);
            if (!co_await WriteTcpResponseHeader(Options_.Provider))
            {
                Status = Prism::Fault::Code::IoError;
                Result_=Status;
                co_return;
            }
            if (!Options_.Services.RelayStream)
            {
                Status = Prism::Fault::Code::NotSupported;
                Result_=Status;
                co_return;
            }
            const auto Begin = Wire.begin() + static_cast<std::ptrdiff_t>(Request.Consumed);
            const auto Relayed = co_await Options_.Services.RelayStream(StreamRelayRequest{Options_.Provider, Outbound_,
                Request.Target, std::vector<std::byte>(Begin, Wire.end()), false, Options_.AccountId,
                Options_.Identity, std::move(Options_.Lease), Options_.Metadata,
                std::move(InitialReadTerminal)});
            if (!Relayed) Status = Relayed.error().Code;
        }
        catch (...)
        {
            Status = Prism::Fault::Code::GenericError;
        }
        Result_=Status;
        co_return;
    }

    auto StreamSession::Complete(const Prism::Fault::Code Status) noexcept -> void
    {
        if (Completed_)
        {
            return;
        }
        Completed_ = true;
        Close();
        const auto ReportedStatus = Status == Prism::Fault::Code::Success
            ? Result_
            : Status;
        Options_.Lease.Release();
        if (Options_.Services.ReportStream)
        {
            try
            {
                Options_.Services.ReportStream(
                    StreamReport{Options_.AccountId, ReportedStatus, Options_.Metadata});
            }
            catch (...)
            {
            }
        }
        if (Options_.Completed)
        {
            Options_.Completed(Options_.Id, ReportedStatus);
        }
    }
}
