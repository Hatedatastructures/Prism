/**
 * @file SingMux.hpp
 * @brief sing-mux 会话协商、虚拟流请求与服务端响应适配。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Protocols/Mux/SessionReadLoop.hpp>
#include <Preview/Net/Target.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Composition::SingMux
{

    namespace Net = boost::asio;

    enum class Protocol : std::uint8_t
    {
        Smux = 0,
        Yamux = 1,
        H2Mux = 2,
    };

    struct SessionRequest final
    {
        std::uint8_t Version{0};
        Protocol ProtocolValue{Protocol::Smux};
        bool Padding{false};
    };

    struct StreamRequest final
    {
        bool Udp{false};
        bool PacketAddr{false};
        Preview::Network::Target Target{};
    };

    [[nodiscard]] inline auto ReadSessionRequest(Preview::SharedTransmission Raw)
        -> Net::awaitable<std::optional<SessionRequest>>
    {
        if (!Raw)
        {
            co_return std::nullopt;
        }
        std::array<std::uint8_t, 2> Prefix{};
        if (!co_await Preview::Mux::Detail::ReadExact(Raw, Prefix))
        {
            co_return std::nullopt;
        }
        if (Prefix[0] > 1U || Prefix[1] > 2U)
        {
            co_return std::nullopt;
        }

        bool Padding = false;
        if (Prefix[0] == 1U)
        {
            std::array<std::uint8_t, 1> PaddingFlag{};
            if (!co_await Preview::Mux::Detail::ReadExact(Raw, PaddingFlag) ||
                PaddingFlag[0] > 1U)
            {
                co_return std::nullopt;
            }
            Padding = PaddingFlag[0] != 0U;
            if (Padding)
            {
                std::array<std::uint8_t, 2> PaddingLengthWire{};
                if (!co_await Preview::Mux::Detail::ReadExact(Raw, PaddingLengthWire))
                {
                    co_return std::nullopt;
                }
                const auto PaddingLength =
                    static_cast<std::size_t>(PaddingLengthWire[0] << 8U | PaddingLengthWire[1]);
                std::vector<std::uint8_t> PaddingBytes(PaddingLength);
                if (!co_await Preview::Mux::Detail::ReadExact(Raw, PaddingBytes))
                {
                    co_return std::nullopt;
                }
            }
        }
        co_return SessionRequest{Prefix[0], static_cast<Protocol>(Prefix[1]), Padding};
    }

    [[nodiscard]] inline auto ReadStreamRequest(Preview::SharedTransmission Raw)
        -> Net::awaitable<std::optional<StreamRequest>>
    {
        if (!Raw)
        {
            co_return std::nullopt;
        }
        std::array<std::uint8_t, 3> Prefix{};
        if (!co_await Preview::Mux::Detail::ReadExact(Raw, Prefix))
        {
            co_return std::nullopt;
        }
        const auto Flags = static_cast<std::uint16_t>(Prefix[0] << 8U | Prefix[1]);
        const auto AddressFamily = Prefix[2];
        Preview::Network::Target Target;
        switch (AddressFamily)
        {
        case 0x00:
            break;
        case 0x01: {
            std::array<std::uint8_t, 4> Address{};
            if (!co_await Preview::Mux::Detail::ReadExact(Raw, Address))
            {
                co_return std::nullopt;
            }
            Target.Host = std::to_string(Address[0]) + "." + std::to_string(Address[1]) + "." +
                          std::to_string(Address[2]) + "." + std::to_string(Address[3]);
            break;
        }
        case 0x03: {
            std::array<std::uint8_t, 1> Length{};
            if (!co_await Preview::Mux::Detail::ReadExact(Raw, Length) || Length[0] == 0U)
            {
                co_return std::nullopt;
            }
            std::vector<std::uint8_t> Host(Length[0]);
            if (!co_await Preview::Mux::Detail::ReadExact(Raw, Host))
            {
                co_return std::nullopt;
            }
            Target.Host.assign(reinterpret_cast<const char *>(Host.data()), Host.size());
            break;
        }
        case 0x04: {
            std::array<std::uint8_t, 16> Address{};
            if (!co_await Preview::Mux::Detail::ReadExact(Raw, Address))
            {
                co_return std::nullopt;
            }
            boost::asio::ip::address_v6::bytes_type Bytes{};
            std::copy(Address.begin(), Address.end(), Bytes.begin());
            Target.Host = boost::asio::ip::make_address_v6(Bytes).to_string();
            break;
        }
        default:
            co_return std::nullopt;
        }
        if (AddressFamily != 0x00)
        {
            std::array<std::uint8_t, 2> Port{};
            if (!co_await Preview::Mux::Detail::ReadExact(Raw, Port))
            {
                co_return std::nullopt;
            }
            Target.Port = std::to_string(
                static_cast<std::uint16_t>(Port[0] << 8U | Port[1]));
        }
        co_return StreamRequest{
            (Flags & 0x0001U) != 0U,
            (Flags & 0x0002U) != 0U,
            std::move(Target)};
    }

    class ServerStream final : public Preview::Transmission
    {
    public:
        ServerStream(Preview::SharedTransmission Next, Preview::Network::Target TargetValue)
            : Next_(std::move(Next)), Target_(std::move(TargetValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Next_ ? Next_->Executor() : Net::any_io_executor{};
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!Next_)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            co_return co_await Next_->async_read_some(Buffer, ErrorCode);
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (!Next_)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (!ResponseWritten_)
            {
                const std::array<std::byte, 1> Status{std::byte{0x00}};
                if (!co_await WriteAll(Status, ErrorCode))
                {
                    co_return 0;
                }
                ResponseWritten_ = true;
            }
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            if (!co_await WriteAll(Buffer, ErrorCode))
            {
                co_return 0;
            }
            ErrorCode.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            if (Next_)
            {
                Next_->Close();
            }
        }

        auto Cancel() -> void override
        {
            if (Next_)
            {
                Next_->Cancel();
            }
        }

        auto Shutdown() -> void override
        {
            if (Next_)
            {
                Next_->Shutdown();
            }
        }

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (Next_)
            {
                Next_->SetTimeout(Timeout);
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Next_ && Next_->IsOpen();
        }

        [[nodiscard]] auto Target() const noexcept -> const Preview::Network::Target &
        {
            return Target_;
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Next_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return Next_.get();
        }

    private:
        [[nodiscard]] auto WriteAll(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                const auto Remaining = Buffer.size() - Offset;
                const auto Written = co_await Next_->async_write_some(
                    Buffer.subspan(Offset), ErrorCode);
                if (ErrorCode || Written == 0 || Written > Remaining)
                {
                    if (!ErrorCode)
                    {
                        ErrorCode = std::make_error_code(std::errc::broken_pipe);
                    }
                    co_return false;
                }
                Offset += Written;
            }
            co_return true;
        }

        Preview::SharedTransmission Next_;
        Preview::Network::Target Target_;
        bool ResponseWritten_{false};
    };

} // namespace Preview::Composition::SingMux
