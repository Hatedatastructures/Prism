/**
 * @file AnytlsService.hpp
 * @brief Preview-owned AnyTLS native stream session and target relay.
 * @details Mihomo AnyTLS uses its own SETTINGS/SYN/PSH/FIN framing after the
 *          authentication frame; it is not the generic smux wire format.
 */
#pragma once

#include <Preview/Protocols/Anytls/Anytls.hpp>
#include <Preview/Composition/MuxService.hpp>
#include <Preview/Composition/AnytlsWire.hpp>
#include <Preview/Runtime/Middleware/Builtin/Dial.hpp>
#include <Preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Lifecycle/TaskState.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/address.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Composition
{

    namespace Net = boost::asio;

    class AnytlsService final
    {
    private:
        enum class Command : std::uint8_t
        {
            Waste = 0x00,
            Syn = 0x01,
            Push = 0x02,
            Fin = 0x03,
            Settings = 0x04,
            Alert = 0x05,
            UpdatePadding = 0x06,
            SynAck = 0x07,
            HeartRequest = 0x08,
            HeartResponse = 0x09,
            ServerSettings = 0x0A,
        };

        struct Frame final
        {
            Command CommandValue{Command::Waste};
            std::uint32_t StreamId{0};
            std::vector<std::byte> Payload;
        };

        using Channel = Net::experimental::channel<void(
            boost::system::error_code, std::vector<std::byte>)>;
        using DialFn = Preview::Middleware::Builtin::DialMiddleware::DialFn;

        struct StreamState final
        {
            explicit StreamState(Net::any_io_executor Executor)
                : Data(std::make_shared<Channel>(Executor, 32))
            {
            }

            std::shared_ptr<Channel> Data;
            bool Started{false};
        };

        struct State final : std::enable_shared_from_this<State>
        {
            State(Preview::Anytls::SharedConn ConnectionValue, DialFn DialValue,
                  std::shared_ptr<Preview::Runtime::SessionControl> ControlValue,
                  Preview::Foundation::TrafficSink *TrafficValue,
                  std::string IdentityValue)
                : Connection(std::move(ConnectionValue)),
                  Dial(std::move(DialValue)),
                  Control(std::move(ControlValue)),
                  Traffic(TrafficValue),
                  Identity(std::move(IdentityValue)),
                  WriteStrand(Connection->Executor())
            {
            }

            Preview::Anytls::SharedConn Connection;
            DialFn Dial;
            std::shared_ptr<Preview::Runtime::SessionControl> Control;
            Preview::Foundation::TrafficSink *Traffic{nullptr};
            std::string Identity;
            Net::strand<Net::any_io_executor> WriteStrand;
            std::unordered_map<std::uint32_t, std::shared_ptr<StreamState>> Streams;
            bool SettingsReceived{false};
        };

        [[nodiscard]] static auto ReadExact(
            const Preview::Anytls::SharedConn &Connection,
            std::span<std::byte> Buffer) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code Error;
                const auto Count = co_await Connection->async_read_some(
                    Buffer.subspan(Offset), Error);
                if (Error || Count == 0U || Count > Buffer.size() - Offset)
                {
                    co_return false;
                }
                Offset += Count;
            }
            co_return true;
        }

        [[nodiscard]] static auto WriteAll(
            const Preview::Anytls::SharedConn &Connection,
            std::span<const std::byte> Buffer) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code Error;
                const auto Count = co_await Connection->async_write_some(
                    Buffer.subspan(Offset), Error);
                if (Error || Count == 0U || Count > Buffer.size() - Offset)
                {
                    co_return false;
                }
                Offset += Count;
            }
            co_return true;
        }

        [[nodiscard]] static auto WriteAll(
            const Preview::SharedTransmission &Connection,
            std::span<const std::byte> Buffer) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code Error;
                const auto Count = co_await Connection->async_write_some(
                    Buffer.subspan(Offset), Error);
                if (Error || Count == 0U || Count > Buffer.size() - Offset)
                {
                    co_return false;
                }
                Offset += Count;
            }
            co_return true;
        }

        [[nodiscard]] static auto ReadFrame(
            const Preview::Anytls::SharedConn &Connection) -> Net::awaitable<std::optional<Frame>>
        {
            std::array<std::byte, 7> Header{};
            if (!co_await ReadExact(Connection, Header))
            {
                co_return std::nullopt;
            }
            Frame Result;
            Result.CommandValue = static_cast<Command>(std::to_integer<std::uint8_t>(Header[0]));
            Result.StreamId = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Header[1])) << 24U) |
                              (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Header[2])) << 16U) |
                              (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Header[3])) << 8U) |
                              static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Header[4]));
            const auto Length = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Header[5])) << 8U) |
                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Header[6])));
            Result.Payload.resize(Length);
            if (!Result.Payload.empty() && !co_await ReadExact(Connection, Result.Payload))
            {
                co_return std::nullopt;
            }
            co_return Result;
        }

        [[nodiscard]] static auto WriteFrame(
            const std::shared_ptr<State> &StateValue,
            const Command CommandValue,
            const std::uint32_t StreamId,
            std::span<const std::byte> Payload) -> Net::awaitable<bool>
        {
            if (Payload.size() > 65535U)
            {
                co_return false;
            }
            co_await Net::dispatch(StateValue->WriteStrand, Net::use_awaitable);
            std::vector<std::byte> Wire(7U + Payload.size());
            Wire[0] = static_cast<std::byte>(CommandValue);
            Wire[1] = static_cast<std::byte>((StreamId >> 24U) & 0xFFU);
            Wire[2] = static_cast<std::byte>((StreamId >> 16U) & 0xFFU);
            Wire[3] = static_cast<std::byte>((StreamId >> 8U) & 0xFFU);
            Wire[4] = static_cast<std::byte>(StreamId & 0xFFU);
            Wire[5] = static_cast<std::byte>((Payload.size() >> 8U) & 0xFFU);
            Wire[6] = static_cast<std::byte>(Payload.size() & 0xFFU);
            std::memcpy(Wire.data() + 7U, Payload.data(), Payload.size());
            co_return co_await WriteAll(StateValue->Connection, Wire);
        }

        class StreamTransport final : public Preview::Transmission
        {
        public:
            StreamTransport(std::shared_ptr<State> StateValue,
                            std::shared_ptr<StreamState> StreamValue,
                            const std::uint32_t StreamIdValue)
                : State_(std::move(StateValue)), Stream_(std::move(StreamValue)),
                  StreamId_(StreamIdValue)
            {
            }

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override
            {
                return State_->Connection->Executor();
            }

            [[nodiscard]] auto async_read_some(
                std::span<std::byte> Buffer,
                std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
            {
                if (PendingOffset_ < Pending_.size())
                {
                    const auto Count = (std::min)(Buffer.size(), Pending_.size() - PendingOffset_);
                    std::memcpy(Buffer.data(), Pending_.data() + PendingOffset_, Count);
                    PendingOffset_ += Count;
                    if (PendingOffset_ == Pending_.size())
                    {
                        Pending_.clear();
                        PendingOffset_ = 0;
                    }
                    ErrorCode.clear();
                    co_return Count;
                }
                if (Closed_.load(std::memory_order_acquire))
                {
                    ErrorCode = std::make_error_code(std::errc::operation_canceled);
                    co_return 0;
                }
                boost::system::error_code ReceiveError;
                auto Payload = co_await Stream_->Data->async_receive(
                    Net::redirect_error(Net::use_awaitable, ReceiveError));
                if (ReceiveError)
                {
                    ErrorCode = std::error_code(ReceiveError.value(), std::generic_category());
                    co_return 0;
                }
                const auto Count = (std::min)(Buffer.size(), Payload.size());
                std::memcpy(Buffer.data(), Payload.data(), Count);
                if (Count < Payload.size())
                {
                    Pending_.assign(Payload.begin() + Count, Payload.end());
                }
                ErrorCode.clear();
                co_return Count;
            }

            [[nodiscard]] auto async_write_some(
                std::span<const std::byte> Buffer,
                std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
            {
                if (Closed_.load(std::memory_order_acquire))
                {
                    ErrorCode = std::make_error_code(std::errc::operation_canceled);
                    co_return 0;
                }
                if (!co_await WriteFrame(
                        State_, Command::Push, StreamId_, Buffer))
                {
                    ErrorCode = std::make_error_code(std::errc::broken_pipe);
                    co_return 0;
                }
                ErrorCode.clear();
                co_return Buffer.size();
            }

            auto Close() -> void override
            {
                if (Closed_.exchange(true, std::memory_order_acq_rel))
                {
                    return;
                }
                Stream_->Data->close();
                const auto StateValue = State_;
                const auto StreamId = StreamId_;
                Net::co_spawn(
                    Executor(),
                    [StateValue, StreamId]() -> Net::awaitable<void>
                    {
                        (void)co_await WriteFrame(StateValue, Command::Fin, StreamId, {});
                    },
                    Net::detached);
            }

            auto Cancel() -> void override { Close(); }

            [[nodiscard]] auto IsOpen() const -> bool override
            {
                return !Closed_.load(std::memory_order_acquire) &&
                       State_->Connection->IsOpen();
            }

        private:
            std::shared_ptr<State> State_;
            std::shared_ptr<StreamState> Stream_;
            std::uint32_t StreamId_{0};
            std::vector<std::byte> Pending_;
            std::size_t PendingOffset_{0};
            std::atomic_bool Closed_{false};
        };

        struct ParsedTarget final
        {
            Preview::Network::Target Target;
            bool MuxMarker{false};
        };

        [[nodiscard]] static auto ParseTarget(std::span<const std::byte> Data)
            -> std::optional<ParsedTarget>
        {
            if (Data.empty())
            {
                return std::nullopt;
            }
            const auto Type = std::to_integer<std::uint8_t>(Data[0]);
            std::size_t Offset = 1;
            std::string Host;
            if (Type == 1U)
            {
                if (Data.size() < Offset + 4U + 2U)
                {
                    return std::nullopt;
                }
                boost::asio::ip::address_v4::bytes_type Bytes{};
                for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
                {
                    Bytes[Index] = std::to_integer<std::uint8_t>(Data[Offset + Index]);
                }
                Host = boost::asio::ip::address_v4(Bytes).to_string();
                Offset += 4U;
            }
            else if (Type == 4U)
            {
                if (Data.size() < Offset + 16U + 2U)
                {
                    return std::nullopt;
                }
                boost::asio::ip::address_v6::bytes_type Bytes{};
                for (std::size_t Index = 0; Index < Bytes.size(); ++Index)
                {
                    Bytes[Index] = std::to_integer<std::uint8_t>(Data[Offset + Index]);
                }
                Host = boost::asio::ip::address_v6(Bytes).to_string();
                Offset += 16U;
            }
            else if (Type == 3U)
            {
                if (Data.size() < Offset + 1U)
                {
                    return std::nullopt;
                }
                const auto Length = std::to_integer<std::uint8_t>(Data[Offset++]);
                if (Length == 0U || Data.size() < Offset + Length + 2U)
                {
                    return std::nullopt;
                }
                Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), Length);
                Offset += Length;
            }
            else
            {
                return std::nullopt;
            }
            if (Data.size() < Offset + 2U)
            {
                return std::nullopt;
            }
            auto Port = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[Offset])) << 8U) |
                static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Data[Offset + 1U])));
            if (Port == 0U)
            {
                return std::nullopt;
            }
            const bool MuxMarker = Host == "sp.mux.sing-box.arpa";
            Preview::Network::Target Target;
            Target.Host.assign(Host);
            Target.Port.assign(std::to_string(Port));
            Target.Positive = true;
            return ParsedTarget{std::move(Target), MuxMarker};
        }

        [[nodiscard]] static auto ReadExactTransmission(
            const Preview::SharedTransmission &Connection,
            std::span<std::byte> Buffer) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                std::error_code Error;
                const auto Count = co_await Connection->async_read_some(
                    Buffer.subspan(Offset), Error);
                if (Error || Count == 0U || Count > Buffer.size() - Offset)
                {
                    co_return false;
                }
                Offset += Count;
            }
            co_return true;
        }

        struct SingRequestData final
        {
            Preview::Composition::AnytlsWire::StreamRequest Request;
            std::vector<std::byte> Remaining;
        };

        [[nodiscard]] static auto ReadSingRequest(
            const Preview::SharedTransmission &Stream) -> Net::awaitable<
                std::expected<SingRequestData, Preview::Error>>
        {
            std::vector<std::byte> Buffer;
            std::array<std::byte, 4096> ReadBuffer{};
            while (true)
            {
                const auto Parsed = Preview::Composition::AnytlsWire::ParseStreamRequest(Buffer);
                if (Parsed)
                {
                    SingRequestData Result{*Parsed, {}};
                    if (Parsed->Consumed < Buffer.size())
                    {
                        Result.Remaining.assign(
                            Buffer.begin() + Parsed->Consumed, Buffer.end());
                    }
                    co_return Result;
                }
                if (Parsed.error() != Preview::Error::NeedMore)
                {
                    co_return std::unexpected(Parsed.error());
                }
                std::error_code Error;
                const auto Count = co_await Stream->async_read_some(ReadBuffer, Error);
                if (Error || Count == 0U)
                {
                    co_return std::unexpected(Preview::Error::UnexpectedEof);
                }
                Buffer.insert(Buffer.end(), ReadBuffer.begin(), ReadBuffer.begin() + Count);
                if (Buffer.size() > 65535U)
                {
                    co_return std::unexpected(Preview::Error::BadLength);
                }
            }
        }

        [[nodiscard]] static auto ConsumeSingMuxBootstrap(
            const Preview::SharedTransmission &Stream) -> Net::awaitable<bool>
        {
            std::vector<std::byte> Header(2U);
            if (!co_await ReadExactTransmission(Stream, Header))
            {
                co_return false;
            }
            if (std::to_integer<std::uint8_t>(Header[0]) > 0U)
            {
                Header.resize(3U);
                if (!co_await ReadExactTransmission(Stream, std::span<std::byte>(
                                                        Header.data() + 2U, 1U)))
                {
                    co_return false;
                }
                if (std::to_integer<std::uint8_t>(Header[2]) != 0U)
                {
                    Header.resize(5U);
                    if (!co_await ReadExactTransmission(Stream, std::span<std::byte>(
                                                            Header.data() + 3U, 2U)))
                    {
                        co_return false;
                    }
                    const auto PaddingLength = static_cast<std::size_t>(
                        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Header[3])) << 8U) |
                        static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Header[4])));
                    if (PaddingLength != 0U)
                    {
                        const auto OriginalSize = Header.size();
                        Header.resize(OriginalSize + PaddingLength);
                        if (!co_await ReadExactTransmission(Stream, std::span<std::byte>(
                                                                Header.data() + OriginalSize,
                                                                PaddingLength)))
                        {
                            co_return false;
                        }
                    }
                }
            }
            const auto Bootstrap = Preview::Composition::AnytlsWire::ParseBootstrap(Header);
            co_return Bootstrap && Bootstrap->Protocol == 0U;
        }

        static auto RelayToTarget(
            std::shared_ptr<State> StateValue,
            std::shared_ptr<StreamState> Stream,
            Preview::SharedTransmission Outbound,
            const std::uint32_t StreamId) -> Net::awaitable<void>
        {
            try
            {
                std::array<std::byte, 16384> Buffer{};
                while (StateValue->Connection->IsOpen() && Outbound && Outbound->IsOpen())
                {
                    std::error_code ReadError;
                    const auto Count = co_await Outbound->async_read_some(Buffer, ReadError);
                    if (ReadError || Count == 0U)
                    {
                        break;
                    }
                    if (!co_await WriteFrame(StateValue, Command::Push, StreamId,
                                             std::span<const std::byte>(Buffer.data(), Count)))
                    {
                        break;
                    }
                }
                if (StateValue->Connection->IsOpen())
                {
                    (void)co_await WriteFrame(StateValue, Command::Fin, StreamId, {});
                }
            }
            catch (const std::exception &Error)
            {
                std::fprintf(stderr, "Preview AnyTLS target relay exception: %s\n", Error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "Preview AnyTLS target relay exception: unknown\n");
            }
            Stream->Data->close();
            co_return;
        }

        static auto RelayFromClient(
            std::shared_ptr<State> StateValue,
            std::shared_ptr<StreamState> Stream,
            Preview::SharedTransmission Outbound) -> Net::awaitable<void>
        {
            try
            {
                while (StateValue->Connection->IsOpen() && Outbound && Outbound->IsOpen())
                {
                    boost::system::error_code Error;
                    auto Payload = co_await Stream->Data->async_receive(
                        Net::redirect_error(Net::use_awaitable, Error));
                    if (Error)
                    {
                        break;
                    }
                    if (!Payload.empty() && !co_await WriteAll(Outbound, Payload))
                    {
                        break;
                    }
                }
            }
            catch (const std::exception &Error)
            {
                std::fprintf(stderr, "Preview AnyTLS client relay exception: %s\n", Error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "Preview AnyTLS client relay exception: unknown\n");
            }
            Outbound->Close();
            co_return;
        }

        [[nodiscard]] static auto RunSingMux(
            const std::shared_ptr<State> &StateValue,
            const std::shared_ptr<StreamState> &Stream,
            const std::uint32_t StreamId) -> Net::awaitable<Preview::Fault::Code>
        {
            auto Transport = std::make_shared<StreamTransport>(StateValue, Stream, StreamId);
            if (!co_await ConsumeSingMuxBootstrap(Transport))
            {
                Transport->Close();
                co_return Preview::Fault::Code::ProtocolError;
            }

            const auto Handler = [StateValue](
                                     Preview::SharedTransmission Inner,
                                     const Preview::Lifecycle::TaskIdentity &)
                -> Net::awaitable<Preview::Fault::Code>
            {
                const auto Parsed = co_await ReadSingRequest(Inner);
                if (!Parsed)
                {
                    co_return Preview::Fault::Code::ProtocolError;
                }
                if (Parsed->Request.Udp || !StateValue->Dial)
                {
                    co_return Preview::Fault::Code::NotSupported;
                }

                auto [DialCode, Outbound] = co_await StateValue->Dial(Parsed->Request.Target);
                if (Preview::Fault::Failed(DialCode) || !Outbound)
                {
                    const std::array<std::byte, 1> Failure{std::byte{0x01}};
                    (void)co_await WriteAll(Inner, Failure);
                    co_return Preview::Fault::Failed(DialCode)
                                 ? DialCode
                                 : Preview::Fault::Code::BadGateway;
                }

                const std::array<std::byte, 1> Success{std::byte{0x00}};
                if (!co_await WriteAll(Inner, Success))
                {
                    Outbound->Close();
                    co_return Preview::Fault::Code::ConnectionReset;
                }
                if (!Parsed->Remaining.empty() &&
                    !co_await WriteAll(Outbound, Parsed->Remaining))
                {
                    Outbound->Close();
                    co_return Preview::Fault::Code::IoError;
                }

                Preview::Middleware::Context RelayContext;
                RelayContext.Inbound = Inner;
                RelayContext.Outbound = Outbound;
                RelayContext.Target = Parsed->Request.Target;
                RelayContext.identity = StateValue->Identity;
                RelayContext.traffic = StateValue->Traffic;
                RelayContext.Control = StateValue->Control;
                Preview::Middleware::Builtin::RelayMiddleware Relay(
                    nullptr, std::chrono::seconds(30));
                co_return co_await Relay.Handle(RelayContext.Inbound, RelayContext);
            };

            Preview::Composition::MuxService Service(
                Preview::Composition::MuxServiceOptions{
                    .Mode = Preview::Composition::MuxMode::Smux,
                    .Control = StateValue->Control,
                    .Identity = {},
                    .MaxStreams = 256,
                    .Timeout = std::chrono::milliseconds(0),
                    .StreamHandlerFn = Handler});
            Preview::Middleware::Context MuxContext;
            MuxContext.Control = StateValue->Control;
            MuxContext.TaskIdentity = {};
            co_return co_await Service.Run(Transport, MuxContext);
        }

        [[nodiscard]] static auto HandlePush(
            const std::shared_ptr<State> &StateValue,
            const Frame &FrameValue) -> Net::awaitable<bool>
        {
            auto It = StateValue->Streams.find(FrameValue.StreamId);
            if (It == StateValue->Streams.end())
            {
                co_return false;
            }
            const auto &Stream = It->second;
            if (!Stream->Started)
            {
                if (!StateValue->Dial)
                {
                    co_return false;
                }
                const auto Target = ParseTarget(FrameValue.Payload);
                if (!Target)
                {
                    std::fprintf(stderr, "Preview AnyTLS target parse failed stream=%u bytes=%zu\n",
                                 FrameValue.StreamId, FrameValue.Payload.size());
                    co_return false;
                }
                if (Target->MuxMarker)
                {
                    if (!co_await WriteFrame(StateValue, Command::SynAck, FrameValue.StreamId, {}))
                    {
                        std::fprintf(stderr, "Preview AnyTLS mux synack failed stream=%u\n",
                                     FrameValue.StreamId);
                        co_return false;
                    }
                    Stream->Started = true;
                    const auto KeepState = StateValue;
                    const auto KeepStream = Stream;
                    const auto OnMuxFailure = [KeepState](
                                                   std::exception_ptr Failure,
                                                   Preview::Fault::Code) noexcept
                    {
                        if (Failure)
                        {
                            KeepState->Connection->Close();
                        }
                    };
                    Net::co_spawn(
                        StateValue->Connection->Executor(),
                        RunSingMux(KeepState, KeepStream, FrameValue.StreamId),
                        OnMuxFailure);
                    co_return true;
                }
                auto [DialCode, Outbound] = co_await StateValue->Dial(Target->Target);
                if (Preview::Fault::Failed(DialCode) || !Outbound)
                {
                    std::fprintf(stderr, "Preview AnyTLS dial failed stream=%u code=%d host=%s port=%s\n",
                                 FrameValue.StreamId, static_cast<int>(DialCode),
                                 Target->Target.Host.c_str(), Target->Target.Port.c_str());
                    co_return false;
                }
                if (!co_await WriteFrame(StateValue, Command::SynAck, FrameValue.StreamId, {}))
                {
                    std::fprintf(stderr, "Preview AnyTLS synack failed stream=%u\n",
                                 FrameValue.StreamId);
                    Outbound->Close();
                    co_return false;
                }
                Stream->Started = true;
                auto KeepState = StateValue;
                auto KeepStream = Stream;
                const auto OnRelayFailure = [KeepState](std::exception_ptr Failure) noexcept
                {
                    if (Failure)
                    {
                        KeepState->Connection->Close();
                    }
                };
                Net::co_spawn(
                    StateValue->Connection->Executor(),
                    RelayFromClient(KeepState, KeepStream, Outbound),
                    OnRelayFailure);
                Net::co_spawn(
                    StateValue->Connection->Executor(),
                    RelayToTarget(KeepState, KeepStream, std::move(Outbound), FrameValue.StreamId),
                    OnRelayFailure);
                co_return true;
            }
            if (!FrameValue.Payload.empty() && !Stream->Data->try_send(
                    boost::system::error_code{}, FrameValue.Payload))
            {
                co_return false;
            }
            co_return true;
        }

    public:
        [[nodiscard]] static auto Run(
            Preview::SharedTransmission Inbound,
            Preview::Middleware::Context &Context,
            DialFn Dial) -> Net::awaitable<Preview::Fault::Code>
        {
            auto Connection = std::dynamic_pointer_cast<Preview::Anytls::Conn<>>(Inbound);
            if (!Connection)
            {
                co_return Preview::Fault::Code::ProtocolError;
            }
            auto StateValue = std::make_shared<State>(
                std::move(Connection), std::move(Dial), Context.Control,
                Context.traffic, Context.identity);
            try
            {
                while (StateValue->Connection->IsOpen())
                {
                    auto FrameValue = co_await ReadFrame(StateValue->Connection);
                    if (!FrameValue)
                    {
                        break;
                    }
                    switch (FrameValue->CommandValue)
                    {
                case Command::Settings: {
                    StateValue->SettingsReceived = true;
                    static constexpr std::string_view Settings{"v=2\nserver=prism\n"};
                    if (!co_await WriteFrame(
                            StateValue, Command::ServerSettings, 0,
                            std::as_bytes(std::span(Settings))))
                    {
                        StateValue->Connection->Close();
                    }
                    break;
                }
                case Command::Syn:
                    if (FrameValue->StreamId == 0U || !StateValue->SettingsReceived)
                    {
                        StateValue->Connection->Close();
                        break;
                    }
                    StateValue->Streams.emplace(
                        FrameValue->StreamId,
                        std::make_shared<StreamState>(StateValue->Connection->Executor()));
                    break;
                case Command::Push:
                    if (!co_await HandlePush(StateValue, *FrameValue))
                    {
                        StateValue->Connection->Close();
                    }
                    break;
                case Command::Fin:
                    if (const auto It = StateValue->Streams.find(FrameValue->StreamId);
                        It != StateValue->Streams.end())
                    {
                        It->second->Data->close();
                        StateValue->Streams.erase(It);
                    }
                    break;
                case Command::HeartRequest:
                    (void)co_await WriteFrame(StateValue, Command::HeartResponse, 0, {});
                    break;
                case Command::Waste:
                case Command::Alert:
                case Command::UpdatePadding:
                case Command::SynAck:
                case Command::HeartResponse:
                case Command::ServerSettings:
                    break;
                    }
                }
            }
            catch (const std::exception &Error)
            {
                std::fprintf(stderr, "Preview AnyTLS frame loop exception: %s\n", Error.what());
            }
            catch (...)
            {
                std::fprintf(stderr, "Preview AnyTLS frame loop exception: unknown\n");
            }
            for (auto &[Id, Stream] : StateValue->Streams)
            {
                (void)Id;
                Stream->Data->close();
            }
            StateValue->Connection->Close();
            co_return Preview::Fault::Code::Success;
        }
    };

} // namespace Preview::Composition
