/**
 * @file StreamSession.hpp
 * @brief 一个 Hysteria2 原始 stream 的子 owner。
 */

#pragma once

#include <Preview/Account/Lease.hpp>
#include <Preview/Protocols/Hysteria2/Admission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Hysteria2
{

    class StreamSession final : public std::enable_shared_from_this<StreamSession>
    {
    public:
        struct Options final
        {
            boost::asio::any_io_executor Executor{};
            std::uint64_t Id{0};
            Preview::Quic::SharedStreamProvider Provider{};
            Preview::AccountId AccountId{};
            std::string Identity;
            Preview::Account::StreamLease Lease;
            AdmissionServices Services;
            std::function<void(std::uint64_t, Preview::Fault::Code)> Completed;
            Preview::Contract::RequestMetadata Metadata{};
        };

        [[nodiscard]] static auto Create(Options OptionsValue) -> std::shared_ptr<StreamSession>;

        ~StreamSession() noexcept;

        StreamSession(const StreamSession&) = delete;
        auto operator=(const StreamSession&) -> StreamSession& = delete;

        auto Start() -> void;
        auto Close() noexcept -> void;

        [[nodiscard]] auto Id() const noexcept -> std::uint64_t
        {
            return Options_.Id;
        }

    private:
        explicit StreamSession(Options OptionsValue);

        [[nodiscard]] auto Run() -> boost::asio::awaitable<void>;
        auto Complete(Preview::Fault::Code Status) noexcept -> void;

        Options Options_;
        std::shared_ptr<boost::asio::cancellation_signal> Cancellation_;
        Preview::SharedTransmission Outbound_{};
        bool Completed_{false};
        bool Started_{false};
        Preview::Fault::Code Result_{Preview::Fault::Code::Success};
    };

    namespace StreamDetail
    {

        enum class ParseResult : std::uint8_t
        {
            NeedMore,
            Invalid,
            Ready,
        };

        struct RawRequest final
        {
            Preview::Network::Target Target;
            std::size_t Consumed{0};
        };

        [[nodiscard]] inline auto ReadVarint(std::span<const std::byte> Data, std::size_t& Offset,
            std::uint64_t& Value) -> ParseResult
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

        [[nodiscard]] inline auto ParseRawRequest(std::span<const std::byte> Data, RawRequest& Output) -> ParseResult
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
            const auto AddressText = std::string_view(reinterpret_cast<const char*>(Data.data() + Offset),
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
            const auto PortResult = std::from_chars(PortText.data(), PortText.data() + PortText.size(), Port);
            if (Host.empty() || PortResult.ec != std::errc{} ||
                PortResult.ptr != PortText.data() + PortText.size() || Port == 0 || Port > 65535)
            {
                return ParseResult::Invalid;
            }
            auto ParsedHost = Preview::Network::ParseHost(Host);
            if (!ParsedHost) return ParseResult::Invalid;
            Output.Target = {std::move(*ParsedHost), static_cast<std::uint16_t>(Port), Preview::Network::RouteKind::Forward};
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

        [[nodiscard]] inline auto WriteTcpResponseHeader(const Preview::Quic::SharedStreamProvider& Provider)
            -> Net::awaitable<bool>
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

    } // namespace StreamDetail

    using StreamDetail::ParseRawRequest;
    using StreamDetail::ParseResult;
    using StreamDetail::RawRequest;
    using StreamDetail::WriteTcpResponseHeader;

    inline auto StreamSession::Create(Options OptionsValue) -> std::shared_ptr<StreamSession>
    {
        if (!OptionsValue.Executor || !OptionsValue.Provider || !OptionsValue.Lease)
        {
            return {};
        }
        return std::shared_ptr<StreamSession>(new StreamSession(std::move(OptionsValue)));
    }

    inline StreamSession::StreamSession(Options OptionsValue)
        : Options_(std::move(OptionsValue)), Cancellation_(std::make_shared<Net::cancellation_signal>())
    {
    }

    inline StreamSession::~StreamSession() noexcept
    {
        Close();
    }

    inline auto StreamSession::Start() -> void
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
                    Self->Complete(Error?Preview::Fault::Code::GenericError:Self->Result_);
                }));
    }

    inline auto StreamSession::Close() noexcept -> void
    {
        if (Cancellation_)
        {
            Cancellation_->emit(Net::cancellation_type::all);
        }
        if (Options_.Provider)
        {
            try
            {
                Options_.Provider->Close();
            }
            catch (...)
            {
            }
        }
        if (Outbound_)
        {
            Outbound_->Close();
        }
    }

    inline auto StreamSession::Run() -> Net::awaitable<void>
    {
        auto Status = Preview::Fault::Code::Success;
        try
        {
            std::vector<std::byte> Wire;
            Wire.reserve(2048);
            RawRequest Request;
            ParseResult Parsed = ParseResult::NeedMore;
            std::array<std::byte, 16384> Buffer{};
            while (Parsed == ParseResult::NeedMore)
            {
                std::error_code Error;
                const auto Count = co_await Options_.Provider->Read(Buffer, Error);
                if (Error || Count == 0)
                {
                    Status = Preview::Fault::Code::Canceled;
                    Result_=Status;
                    co_return;
                }
                Wire.insert(Wire.end(), Buffer.begin(), Buffer.begin() + Count);
                Parsed = ParseRawRequest(Wire, Request);
            }
            if (Parsed != ParseResult::Ready)
            {
                Status = Preview::Fault::Code::BadMessage;
                Result_=Status;
                co_return;
            }
            if (!Options_.Services.Dial)
            {
                Status = Preview::Fault::Code::NotSupported;
                Result_=Status;
                co_return;
            }
            auto Dialed = co_await Options_.Services.Dial(DialRequest{Request.Target});
            if (!Dialed)
            {
                Status = Dialed.error().Code;
                if (Status == Preview::Fault::Code::Success)
                {
                    Status = Preview::Fault::Code::BadGateway;
                }
                Result_=Status;
                co_return;
            }
            Outbound_ = std::move(*Dialed);
            if (!co_await WriteTcpResponseHeader(Options_.Provider))
            {
                Status = Preview::Fault::Code::IoError;
                Result_=Status;
                co_return;
            }
            if (!Options_.Services.RelayStream)
            {
                Status = Preview::Fault::Code::NotSupported;
                Result_=Status;
                co_return;
            }
            const auto Begin = Wire.begin() + static_cast<std::ptrdiff_t>(Request.Consumed);
            const auto Relayed = co_await Options_.Services.RelayStream(StreamRelayRequest{Options_.Provider, Outbound_,
                Request.Target, std::vector<std::byte>(Begin, Wire.end()), false, Options_.AccountId,
                Options_.Identity, std::move(Options_.Lease), Options_.Metadata});
            if (!Relayed) Status = Relayed.error().Code;
        }
        catch (...)
        {
            Status = Preview::Fault::Code::GenericError;
        }
        Result_=Status;
        co_return;
    }

    inline auto StreamSession::Complete(const Preview::Fault::Code Status) noexcept -> void
    {
        if (Completed_)
        {
            return;
        }
        Completed_ = true;
        Close();
        Options_.Lease.Release();
        if (Options_.Services.ReportStream)
        {
            try
            {
                Options_.Services.ReportStream(StreamReport{Options_.AccountId, Status, Options_.Metadata});
            }
            catch (...)
            {
            }
        }
        if (Options_.Completed)
        {
            Options_.Completed(Options_.Id, Status);
        }
    }

} // namespace Preview::Hysteria2
