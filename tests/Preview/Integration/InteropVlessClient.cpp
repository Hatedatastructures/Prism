/**
 * @file InteropVlessClient.cpp
 * @brief Preview VLESS 客户端与独立 Go reference 的真实 TCP/UDP/XUDP 互操作端点。
 * @details 保留普通 TCP、标准 UDP packet framing 和 `-xudp` association wire；
 *          server accept/echo 由 InteropVlessServer.cpp 独立拥有。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Protocols/Vless/Xudp/Codec.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    struct Options
    {
        std::string Address{"127.0.0.1:19084"};
        bool Udp{false};
        bool Xudp{false};
        std::array<std::uint8_t, 16> Uuid{
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
            0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        std::string Target{"example.com:443"};
        bool Invalid{false};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        if (Value.empty())
        {
            return std::nullopt;
        }
        std::uint32_t Port = 0;
        const auto *Begin = Value.data();
        const auto *End = Begin + Value.size();
        const auto [Parsed, Error] = std::from_chars(Begin, End, Port);
        if (Error != std::errc{} || Parsed != End || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        if (Value.starts_with('['))
        {
            const auto Closing = Value.find(']');
            if (Closing == std::string_view::npos || Closing + 2 > Value.size() ||
                Value[Closing + 1] != ':')
            {
                return std::nullopt;
            }
            const auto Port = ParsePort(Value.substr(Closing + 2));
            if (!Port)
            {
                return std::nullopt;
            }
            return HostPort{std::string(Value.substr(1, Closing - 1)), *Port};
        }
        const auto Separator = Value.find_last_of(':');
        if (Separator == std::string_view::npos || Separator == 0)
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Separator + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Separator)), *Port};
    }

    [[nodiscard]] auto MakeTarget(std::string_view Value) -> std::optional<Preview::Vless::Address>
    {
        const auto HostPortValue = SplitHostPort(Value);
        if (!HostPortValue)
        {
            return std::nullopt;
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(HostPortValue->Host, Error);
        Preview::Vless::AddressType Type;
        if (Error)
        {
            Type = Preview::Vless::AddressType::Domain;
        }
        else if (Address.is_v4())
        {
            Type = Preview::Vless::AddressType::Ipv4;
        }
        else
        {
            Type = Preview::Vless::AddressType::Ipv6;
        }
        return Preview::Vless::Address{Type, HostPortValue->Host, HostPortValue->Port};
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> Options
    {
        Options Result;
        if ((Argc - 1) % 2 != 0) { Result.Invalid = true; return Result; }
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-target")
            {
                Result.Target = Value;
            }
            else if (Key == "-udp")
            {
                if (Value == "1" || Value == "true") Result.Udp = true;
                else if (Value == "0" || Value == "false") Result.Udp = false;
                else Result.Invalid = true;
            }
            else if (Key == "-xudp")
            {
                if (Value == "1" || Value == "true") Result.Xudp = true;
                else if (Value == "0" || Value == "false") Result.Xudp = false;
                else Result.Invalid = true;
            }
            else Result.Invalid = true;
        }
        return Result;
    }

    [[nodiscard]] auto XudpAddressBody(const Preview::Vless::Address &Target)
        -> std::optional<std::vector<std::uint8_t>>
    {
        std::vector<std::uint8_t> Body;
        Body.push_back(static_cast<std::uint8_t>(Target.Port >> 8U));
        Body.push_back(static_cast<std::uint8_t>(Target.Port));
        if (Target.Type == Preview::Vless::AddressType::Domain)
        {
            if (Target.Host.empty() || Target.Host.size() > 255U)
            {
                return std::nullopt;
            }
            Body.push_back(Preview::Vless::Xudp::FamilyFqdn);
            Body.push_back(static_cast<std::uint8_t>(Target.Host.size()));
            Body.insert(Body.end(), Target.Host.begin(), Target.Host.end());
            return Body;
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(Target.Host, Error);
        if (Error)
        {
            return std::nullopt;
        }
        if (Target.Type == Preview::Vless::AddressType::Ipv4 && Address.is_v4())
        {
            Body.push_back(Preview::Vless::Xudp::FamilyIpv4);
            const auto Bytes = Address.to_v4().to_bytes();
            Body.insert(Body.end(), Bytes.begin(), Bytes.end());
            return Body;
        }
        if (Target.Type == Preview::Vless::AddressType::Ipv6 && Address.is_v6())
        {
            Body.push_back(Preview::Vless::Xudp::FamilyIpv6);
            const auto Bytes = Address.to_v6().to_bytes();
            Body.insert(Body.end(), Bytes.begin(), Bytes.end());
            return Body;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto BuildXudpNewFrame(
        const std::uint16_t SessionId,
        const Preview::Vless::Address &Target,
        std::span<const std::uint8_t> Payload) -> std::optional<std::vector<std::byte>>
    {
        const auto Address = XudpAddressBody(Target);
        if (!Address || Payload.size() > Preview::Vless::Xudp::MaxDatagram)
        {
            return std::nullopt;
        }
        const auto Length = static_cast<std::uint16_t>(4U + 1U + Address->size());
        std::vector<std::byte> Wire{
            std::byte{static_cast<std::uint8_t>(Length >> 8U)}, std::byte{static_cast<std::uint8_t>(Length)},
            std::byte{static_cast<std::uint8_t>(SessionId >> 8U)}, std::byte{static_cast<std::uint8_t>(SessionId)},
            std::byte{static_cast<std::uint8_t>(Preview::Vless::Xudp::Status::New)},
            std::byte{Preview::Vless::Xudp::OptionData}, std::byte{Preview::Vless::Xudp::NetworkUdp}};
        for (const auto Byte : *Address) Wire.push_back(std::byte{Byte});
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Payload.size() >> 8U)});
        Wire.push_back(std::byte{static_cast<std::uint8_t>(Payload.size())});
        for (const auto Byte : Payload) Wire.push_back(std::byte{Byte});
        return Wire;
    }

    [[nodiscard]] auto BuildXudpKeepFrame(
        const std::uint16_t SessionId, std::span<const std::uint8_t> Payload)
        -> std::optional<std::vector<std::byte>>
    {
        if (Payload.size() > Preview::Vless::Xudp::MaxDatagram)
        {
            return std::nullopt;
        }
        std::vector<std::byte> Wire{
            std::byte{0}, std::byte{4}, std::byte{static_cast<std::uint8_t>(SessionId >> 8U)},
            std::byte{static_cast<std::uint8_t>(SessionId)},
            std::byte{static_cast<std::uint8_t>(Preview::Vless::Xudp::Status::Keep)},
            std::byte{Preview::Vless::Xudp::OptionData},
            std::byte{static_cast<std::uint8_t>(Payload.size() >> 8U)},
            std::byte{static_cast<std::uint8_t>(Payload.size())}};
        for (const auto Byte : Payload) Wire.push_back(std::byte{Byte});
        return Wire;
    }

    auto WriteXudpWire(const Preview::SharedTransmission &Transport, std::span<const std::byte> Wire)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Wire.size())
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_write_some(Wire.subspan(Offset), Error);
            if (Error || Count == 0U)
            {
                co_return false;
            }
            Offset += Count;
        }
        co_return true;
    }

    struct RawXudpFrame final
    {
        std::uint16_t SessionId{0};
        Preview::Vless::Xudp::Status StatusValue{Preview::Vless::Xudp::Status::Keep};
        std::uint8_t Option{0};
        std::vector<std::uint8_t> Payload;
    };

    auto ReadXudpBytes(const Preview::SharedTransmission &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer.subspan(Offset), Error);
            if (Error || Count == 0U)
            {
                co_return false;
            }
            Offset += Count;
        }
        co_return true;
    }

    auto ReadRawXudpFrame(const Preview::SharedTransmission &Transport)
        -> Net::awaitable<std::optional<RawXudpFrame>>
    {
        std::array<std::byte, 6> Header{};
        if (!co_await ReadXudpBytes(Transport, Header))
        {
            co_return std::nullopt;
        }
        const auto Length = static_cast<std::size_t>(std::to_integer<std::uint8_t>(Header[0]) << 8U |
            std::to_integer<std::uint8_t>(Header[1]));
        RawXudpFrame Result;
        Result.SessionId = static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Header[2]) << 8U |
            std::to_integer<std::uint8_t>(Header[3]));
        Result.StatusValue = static_cast<Preview::Vless::Xudp::Status>(
            std::to_integer<std::uint8_t>(Header[4]));
        Result.Option = std::to_integer<std::uint8_t>(Header[5]);
        if (Result.StatusValue == Preview::Vless::Xudp::Status::End)
        {
            co_return Length == 4U ? std::optional<RawXudpFrame>(std::move(Result)) : std::nullopt;
        }
        if ((Result.StatusValue != Preview::Vless::Xudp::Status::New &&
                Result.StatusValue != Preview::Vless::Xudp::Status::Keep &&
                Result.StatusValue != Preview::Vless::Xudp::Status::KeepAlive) || Length < 4U)
        {
            co_return std::nullopt;
        }
        if (Length > 4U)
        {
            std::vector<std::byte> Body(Length - 4U);
            const auto BodyRead = co_await ReadXudpBytes(Transport, Body);
            if (!BodyRead || Body.empty() ||
                std::to_integer<std::uint8_t>(Body.front()) != Preview::Vless::Xudp::NetworkUdp ||
                !Preview::Vless::Xudp::ReadAddress(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Body.data() + 1), Body.size() - 1U)))
            {
                co_return std::nullopt;
            }
        }
        if ((Result.Option & Preview::Vless::Xudp::OptionData) != 0U)
        {
            std::array<std::byte, 2> SizeWire{};
            if (!co_await ReadXudpBytes(Transport, SizeWire))
            {
                co_return std::nullopt;
            }
            const auto Size = static_cast<std::size_t>(std::to_integer<std::uint8_t>(SizeWire[0]) << 8U |
                std::to_integer<std::uint8_t>(SizeWire[1]));
            Result.Payload.resize(Size);
            if (!co_await ReadXudpBytes(Transport, std::span<std::byte>(
                    reinterpret_cast<std::byte *>(Result.Payload.data()), Result.Payload.size())))
            {
                co_return std::nullopt;
            }
        }
        co_return Result;
    }

    auto ReadXudpPayload(
        const Preview::SharedTransmission &Transport,
        const std::uint16_t SessionId,
        std::span<const std::uint8_t> Expected) -> Net::awaitable<bool>
    {
        const auto Frame = co_await ReadRawXudpFrame(Transport);
        co_return Frame.has_value() && Frame->SessionId == SessionId &&
            Frame->StatusValue == Preview::Vless::Xudp::Status::Keep &&
            Frame->Option == Preview::Vless::Xudp::OptionData &&
            Frame->Payload.size() == Expected.size() &&
            std::memcmp(Frame->Payload.data(), Expected.data(), Expected.size()) == 0;
    }

    auto ReadXudpEndHeader(const Preview::SharedTransmission &Transport, const std::uint16_t SessionId)
        -> Net::awaitable<bool>
    {
        std::array<std::byte, 6> Header{};
        if (!co_await ReadXudpBytes(Transport, Header))
        {
            co_return false;
        }
        const auto Expected = Preview::Vless::Xudp::EncodeEnd(SessionId);
        co_return Expected.size() == Header.size() &&
            std::memcmp(Header.data(), Expected.data(), Header.size()) == 0;
    }

    struct ExpectedXudpPayload final
    {
        std::uint16_t SessionId{0};
        std::span<const std::uint8_t> Bytes;
        bool Seen{false};
    };

    auto ReadXudpPayloads(
        const Preview::SharedTransmission &Transport,
        std::array<ExpectedXudpPayload, 2> &Expected) -> Net::awaitable<bool>
    {
        while (!Expected[0].Seen || !Expected[1].Seen)
        {
            const auto Frame = co_await ReadRawXudpFrame(Transport);
            if (!Frame)
            {
                co_return false;
            }
            if (Frame->StatusValue != Preview::Vless::Xudp::Status::Keep ||
                Frame->Option != Preview::Vless::Xudp::OptionData)
            {
                co_return false;
            }
            for (auto &Value : Expected)
            {
                if (Value.SessionId == Frame->SessionId)
                {
                    if (Value.Seen)
                    {
                        co_return false;
                    }
                    Value.Seen = Frame->Payload.size() == Value.Bytes.size() &&
                        std::memcmp(Frame->Payload.data(), Value.Bytes.data(), Value.Bytes.size()) == 0;
                    if (!Value.Seen)
                    {
                        co_return false;
                    }
                }
            }
            if (std::none_of(Expected.begin(), Expected.end(),
                    [&Frame](const auto &Value) { return Value.SessionId == Frame->SessionId; }))
            {
                co_return false;
            }
        }
        co_return true;
    }

    [[nodiscard]] auto XudpPayload(std::string_view Value) -> std::span<const std::uint8_t>
    {
        return {reinterpret_cast<const std::uint8_t *>(Value.data()), Value.size()};
    }

    [[nodiscard]] auto XudpFailure(const std::shared_ptr<Preview::Vless::Conn<>> &Connection,
        const char *Message) -> Net::awaitable<int>
    {
        if (Connection)
        {
            Connection->Close();
        }
        std::fprintf(stderr, "FAIL: %s\n", Message);
        co_return 1;
    }

    /**
     * @brief 使用真实 VLESS Mux 连接驱动两个 XUDP association 的外部互操作客户端。
     * @param OptionsValue 按值接管 CLI 配置；UUID/目标只借用到握手和帧构造完成。
     * @return 成功完成双 association、End、未知 ID 拒绝和 sibling continuation 时返回 0。
     * @note 所有 I/O 在调用 executor；失败由 Conn Close/取消收口，成功显式 Shutdown/Close
     *       后等待 io_context 自然退出，不把 Io.stop 当作业务成功或 drain 证据。
     */
    [[nodiscard]] auto RunXudpClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto Target = MakeTarget(OptionsValue.Target);
        if (!Server || !Target)
        {
            std::fprintf(stderr, "FAIL: malformed XUDP server or target address\n");
            co_return 2;
        }
        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({Preview::Network::ParseHost(Server->Host).value_or(Preview::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: XUDP TCP dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);
        const Preview::Vless::ClientConfig Config{OptionsValue.Uuid};
        auto ConnectResult = co_await Preview::Vless::Connect(
            Preview::Vless::ConnectParameters{std::move(Raw), Config, *Target, Preview::Vless::Command::Mux});
        if (!ConnectResult)
        {
            const auto &Failure = ConnectResult.error();
            std::fprintf(stderr, "FAIL: VLESS XUDP mux handshake Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Connection = std::move(*ConnectResult);
        Preview::SharedTransmission Transport = Connection;
        constexpr std::string_view FirstPayload{"prism-vless-xudp-association-one"};
        constexpr std::string_view SecondPayload{"prism-vless-xudp-association-two"};
        constexpr std::string_view ContinuationPayload{"prism-vless-xudp-association-two-continuation"};
        constexpr std::uint16_t FirstId = 1U;
        constexpr std::uint16_t SecondId = 2U;
        const auto First = BuildXudpNewFrame(FirstId, *Target, XudpPayload(FirstPayload));
        const auto Second = BuildXudpNewFrame(SecondId, *Target, XudpPayload(SecondPayload));
        if (!First || !Second || !co_await WriteXudpWire(Transport, *First) ||
            !co_await WriteXudpWire(Transport, *Second))
        {
            co_return co_await XudpFailure(Connection, "XUDP association bootstrap write failed");
        }
        std::array<ExpectedXudpPayload, 2> Expected{{
            {FirstId, XudpPayload(FirstPayload), false}, {SecondId, XudpPayload(SecondPayload), false}}};
        if (!co_await ReadXudpPayloads(Transport, Expected))
        {
            co_return co_await XudpFailure(Connection, "XUDP association echo mismatch");
        }
        const auto FirstEnd = Preview::Vless::Xudp::EncodeEnd(FirstId);
        if (!co_await WriteXudpWire(Transport, FirstEnd))
        {
            co_return co_await XudpFailure(Connection, "XUDP first End write failed");
        }
        const auto UnknownKeep = BuildXudpKeepFrame(0xFF00U, XudpPayload("unknown-keep"));
        const auto UnknownEnd = Preview::Vless::Xudp::EncodeEnd(0xFF01U);
        if (!UnknownKeep || !co_await WriteXudpWire(Transport, *UnknownKeep) ||
            !co_await ReadXudpEndHeader(Transport, 0xFF00U) ||
            !co_await WriteXudpWire(Transport, UnknownEnd))
        {
            co_return co_await XudpFailure(Connection, "XUDP unknown association was not rejected");
        }
        const auto Keep = BuildXudpKeepFrame(SecondId, XudpPayload(ContinuationPayload));
        if (!Keep || !co_await WriteXudpWire(Transport, *Keep) ||
            !co_await ReadXudpPayload(Transport, SecondId, XudpPayload(ContinuationPayload)))
        {
            co_return co_await XudpFailure(Connection, "XUDP sibling continuation mismatch");
        }
        Connection->Shutdown();
        Connection->Close();
        std::printf("PASS: Preview VLESS XUDP two associations, End, sibling continuation\n");
        co_return 0;
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        if (OptionsValue.Xudp)
        {
            co_return co_await RunXudpClient(std::move(OptionsValue));
        }
        const auto Server = SplitHostPort(OptionsValue.Address);
        const auto Target = MakeTarget(OptionsValue.Target);
        if (!Server || !Target)
        {
            std::fprintf(stderr, "FAIL: malformed server or target address\n");
            co_return 2;
        }

        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        auto DialResult = co_await Dialer.Connect({Preview::Network::ParseHost(Server->Host).value_or(Preview::Network::Host{}), Server->Port});
        if (!DialResult)
        {
            const auto &Failure = DialResult.error();
            std::fprintf(stderr, "FAIL: TCP dial: Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        auto Raw = std::move(*DialResult);
        const Preview::Vless::ClientConfig Config{OptionsValue.Uuid};
        if (OptionsValue.Udp)
        {
            auto ConnectResult = co_await Preview::Vless::ConnectPacket(
                std::move(Raw), Config, *Target);
            if (!ConnectResult)
            {
                const auto &Failure = ConnectResult.error();
                std::fprintf(stderr, "FAIL: VLESS UDP client handshake Code=%d Native=%s:%d\n",
                    static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
                co_return 1;
            }
            if (!*ConnectResult)
            {
                std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
                co_return 1;
            }
            auto Datagram = std::move(*ConnectResult);
            constexpr std::string_view Payload{"prism-vless-external-udp-payload"};
            const auto PayloadBytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Payload.data()), Payload.size());
            const auto Send = co_await Datagram->AsyncSendDatagram(PayloadBytes);
            if (Send.Failure.Failed())
            {
                Datagram->Close();
                std::fprintf(stderr, "FAIL: VLESS UDP client write\n");
                co_return 1;
            }
            std::vector<std::uint8_t> Echo;
            const auto Receive = co_await Datagram->AsyncReceiveDatagram(Echo);
            if (Receive.Failure.Failed() ||
                Echo.size() != PayloadBytes.size() ||
                !std::equal(Echo.begin(), Echo.end(), PayloadBytes.begin()))
            {
                Datagram->Close();
                std::fprintf(stderr, "FAIL: VLESS UDP external echo mismatch\n");
                co_return 1;
            }
            Datagram->Close();
            std::printf("PASS: Preview VLESS UDP client -> Go reference server\n");
            co_return 0;
        }
        auto ConnectResult = co_await Preview::Vless::Connect(
            Preview::Vless::ConnectParameters{std::move(Raw), Config, *Target, Preview::Vless::Command::Tcp});
        if (!ConnectResult)
        {
            const auto &Failure = ConnectResult.error();
            std::fprintf(stderr, "FAIL: VLESS client handshake Code=%d Native=%s:%d\n",
                static_cast<int>(Failure.Code), Failure.Native.category().name(), Failure.Native.value());
            co_return 1;
        }
        if (!*ConnectResult)
        {
            std::fprintf(stderr, "FAIL: protocol Connect returned an empty owner\n");
            co_return 1;
        }
        auto Conn = std::move(*ConnectResult);

        constexpr std::string_view Payload{"prism-vless-external-interop-payload"};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        std::error_code Error;
        const auto Written = co_await Conn->AsyncWrite(PayloadBytes, Error);
        if (Error || Written != PayloadBytes.size())
        {
            Conn->Close();
            std::fprintf(stderr, "FAIL: VLESS client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        const auto Read = co_await Conn->AsyncRead(Echo, Error);
        Conn->Close();
        if (Error || Read != Payload.size() ||
            std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: VLESS external echo mismatch\n");
            co_return 1;
        }
        std::printf("PASS: Preview VLESS client -> Go reference server\n");
        co_return 0;
    }

    auto HandleCompletion(Net::io_context &Io, std::exception_ptr Exception) -> void
    {
        if (!Exception)
        {
            return;
        }
        try
        {
            std::rethrow_exception(Exception);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: VLESS interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: VLESS interop coroutine exception: unknown\n");
        }
        Io.stop();
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto OptionsValue = ParseOptions(Argc, Argv);
    if (OptionsValue.Invalid)
    {
        std::fprintf(stderr, "FAIL: unsupported VLESS client option\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    auto Run = [OptionsValue, &Io, &ExitCode]() -> Net::awaitable<void>
    {
        ExitCode = co_await RunClient(OptionsValue);
    };
    Net::co_spawn(Io, Run(), [&Io](std::exception_ptr Exception)
        { HandleCompletion(Io, std::move(Exception)); });
    Io.run();
    return ExitCode;
}
