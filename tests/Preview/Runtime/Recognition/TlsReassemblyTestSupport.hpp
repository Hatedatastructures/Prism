/**
 * @file TlsReassemblyTestSupport.hpp
 * @brief TlsReassemblyTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file TlsReassemblyTest.cpp
 * @brief TLS ClientHello incremental reassembly and route precedence tests.
 */

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <Preview/Runtime/Recognition/RawIngressProbe.hpp>
#include <tests/Experiments/Preview/ProbeRecognition.hpp>
#include <Experiments/Preview/Route.hpp>
#include <Experiments/Preview/SchemeExecutor.hpp>
#include <Preview/Runtime/Recognition/Tls.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace rec = Preview::Recognition;

    struct ReadStep
    {
        std::vector<std::byte> Data;
        std::error_code Error{};
    };

    class ScriptedTransport final : public Preview::Transmission
    {
    public:
        explicit ScriptedTransport(Net::any_io_executor Executor) : Executor_(std::move(Executor)) {}

        auto Push(std::vector<std::byte> Data, std::error_code Error = {}) -> void
        {
            Steps_.push_back(ReadStep{std::move(Data), Error});
        }

        [[nodiscard]] auto ReadRequests() const -> const std::vector<std::size_t> &
        {
            return ReadRequests_;
        }

        [[nodiscard]] auto RemainingBytes() const -> std::size_t
        {
            std::size_t Result = 0;
            for (const auto &Step : Steps_)
            {
                Result += Step.Data.size();
            }
            return Result;
        }

        [[nodiscard]] auto Cancels() const noexcept -> std::size_t
        {
            return Cancels_;
        }

        [[nodiscard]] auto Closes() const noexcept -> std::size_t
        {
            return Closes_;
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ReadRequests_.push_back(Buffer.size());
            Error.clear();
            if (Buffer.empty() || Steps_.empty())
            {
                co_return 0;
            }

            auto &Step = Steps_.front();
            const auto Count = (std::min)(Buffer.size(), Step.Data.size());
            std::copy_n(Step.Data.begin(), Count, Buffer.begin());
            Step.Data.erase(Step.Data.begin(), Step.Data.begin() + static_cast<std::ptrdiff_t>(Count));
            if (Step.Data.empty())
            {
                Error = Step.Error;
                Steps_.pop_front();
            }
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            Error.clear();
            co_return Buffer.size();
        }

        auto Close() -> void override
        {
            ++Closes_;
        }

        auto Cancel() -> void override
        {
            ++Cancels_;
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Closes_ == 0;
        }

    private:
        Net::any_io_executor Executor_;
        std::deque<ReadStep> Steps_;
        std::vector<std::size_t> ReadRequests_;
        std::size_t Cancels_{0};
        std::size_t Closes_{0};
    };

    auto AsBytes(const std::vector<std::uint8_t> &Data) -> std::vector<std::byte>
    {
        std::vector<std::byte> Result;
        Result.reserve(Data.size());
        for (const auto Byte : Data)
        {
            Result.push_back(static_cast<std::byte>(Byte));
        }
        return Result;
    }

    auto AppendU16(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    auto AppendU24(std::vector<std::uint8_t> &Data, std::size_t Value) -> void
    {
        Data.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFF));
        Data.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
        Data.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    struct TestKeyShare
    {
        std::uint16_t Group;
        std::vector<std::uint8_t> Data;
    };

    auto MakeExtension(std::uint16_t Type, const std::vector<std::uint8_t> &Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        AppendU16(Result, Type);
        AppendU16(Result, Payload.size());
        Result.insert(Result.end(), Payload.begin(), Payload.end());
        return Result;
    }

    struct ClientHelloOptions final
    {
        std::string_view ServerName;
        std::vector<std::string> Alpn;
        bool IncludeUnknownExtension{false};
        std::size_t SessionIdLength{0};
        bool IncludeDuplicateSni{false};
        bool IncludeEch{false};
    };

    auto MakeClientHello(ClientHelloOptions Options)
    {
        const auto ServerName = Options.ServerName;
        const auto &Alpn = Options.Alpn;
        const auto IncludeUnknownExtension = Options.IncludeUnknownExtension;
        const auto SessionIdLength = Options.SessionIdLength;
        const auto IncludeDuplicateSni = Options.IncludeDuplicateSni;
        const auto IncludeEch = Options.IncludeEch;
        std::vector<std::uint8_t> Extensions;
        if (!ServerName.empty())
        {
            std::vector<std::uint8_t> Names;
            Names.push_back(0);
            AppendU16(Names, ServerName.size());
            Names.insert(Names.end(), ServerName.begin(), ServerName.end());
            std::vector<std::uint8_t> Sni;
            AppendU16(Sni, Names.size());
            Sni.insert(Sni.end(), Names.begin(), Names.end());
            const auto Extension = MakeExtension(0x0000, Sni);
            Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
            if (IncludeDuplicateSni)
            {
                Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
            }
        }
        if (!Alpn.empty())
        {
            std::vector<std::uint8_t> Protocols;
            for (const auto &Protocol : Alpn)
            {
                Protocols.push_back(static_cast<std::uint8_t>(Protocol.size()));
                Protocols.insert(Protocols.end(), Protocol.begin(), Protocol.end());
            }
            std::vector<std::uint8_t> AlpnPayload;
            AppendU16(AlpnPayload, Protocols.size());
            AlpnPayload.insert(AlpnPayload.end(), Protocols.begin(), Protocols.end());
            const auto Extension = MakeExtension(0x0010, AlpnPayload);
            Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
        }
        const std::vector<std::uint8_t> Versions{2, 0x03, 0x04};
        const auto VersionExtension = MakeExtension(0x002B, Versions);
        Extensions.insert(Extensions.end(), VersionExtension.begin(), VersionExtension.end());
        if (IncludeUnknownExtension)
        {
            const auto Extension = MakeExtension(0xF0AA, {0x01, 0x02, 0x03});
            Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
        }
        if (IncludeEch)
        {
            const auto Extension = MakeExtension(0xFE0D, {0x01});
            Extensions.insert(Extensions.end(), Extension.begin(), Extension.end());
        }

        std::vector<std::uint8_t> Body{0x03, 0x03};
        Body.insert(Body.end(), 32, 0x42);
        Body.push_back(static_cast<std::uint8_t>(SessionIdLength));
        Body.insert(Body.end(), SessionIdLength, 0xA5);
        AppendU16(Body, 2);
        Body.push_back(0x13);
        Body.push_back(0x01);
        Body.push_back(1);
        Body.push_back(0);
        AppendU16(Body, Extensions.size());
        Body.insert(Body.end(), Extensions.begin(), Extensions.end());

        std::vector<std::uint8_t> Handshake{0x01};
        AppendU24(Handshake, Body.size());
        Handshake.insert(Handshake.end(), Body.begin(), Body.end());
        return Handshake;
    }

    auto MakeClientHelloWithKeyShares(std::string_view ServerName,
                                      const std::vector<TestKeyShare> &KeyShares)
        -> std::vector<std::uint8_t>
    {
        auto Handshake = MakeClientHello(ClientHelloOptions{ServerName, {}, false});
        std::vector<std::uint8_t> Entries;
        for (const auto &Share : KeyShares)
        {
            AppendU16(Entries, Share.Group);
            AppendU16(Entries, Share.Data.size());
            Entries.insert(Entries.end(), Share.Data.begin(), Share.Data.end());
        }

        std::vector<std::uint8_t> Payload;
        AppendU16(Payload, Entries.size());
        Payload.insert(Payload.end(), Entries.begin(), Entries.end());
        const auto Extension = MakeExtension(0x0033, Payload);

        std::size_t Offset = 4 + 2 + 32;
        const auto SessionIdLength = Handshake.at(Offset);
        Offset += 1 + SessionIdLength;
        const auto CipherSuitesLength = static_cast<std::size_t>(Handshake.at(Offset)) << 8 |
                                        Handshake.at(Offset + 1);
        Offset += 2 + CipherSuitesLength;
        const auto CompressionMethodsLength = Handshake.at(Offset);
        Offset += 1 + CompressionMethodsLength;
        const auto ExistingExtensionsLength = static_cast<std::size_t>(Handshake.at(Offset)) << 8 |
                                              Handshake.at(Offset + 1);
        const auto NewExtensionsLength = ExistingExtensionsLength + Extension.size();
        Handshake[Offset] = static_cast<std::uint8_t>((NewExtensionsLength >> 8) & 0xFF);
        Handshake[Offset + 1] = static_cast<std::uint8_t>(NewExtensionsLength & 0xFF);
        Handshake.insert(Handshake.end(), Extension.begin(), Extension.end());

        const auto MessageLength = Handshake.size() - 4;
        Handshake[1] = static_cast<std::uint8_t>((MessageLength >> 16) & 0xFF);
        Handshake[2] = static_cast<std::uint8_t>((MessageLength >> 8) & 0xFF);
        Handshake[3] = static_cast<std::uint8_t>(MessageLength & 0xFF);
        return Handshake;
    }

    auto MakeTestX25519Key(std::uint8_t Start) -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> Result{};
        for (std::size_t Index = 0; Index < Result.size(); ++Index)
        {
            Result[Index] = static_cast<std::uint8_t>(Start + Index);
        }
        return Result;
    }

    auto MakeClientHello(
        const std::string_view ServerName,
        const std::vector<std::string> &Alpn,
        const bool IncludeUnknownExtension)
    {
        return MakeClientHello(ClientHelloOptions{
            ServerName, Alpn, IncludeUnknownExtension});
    }

    auto MakeHybridKeyShare(const std::array<std::uint8_t, 32> &X25519Key)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result(1184, 0xA5);
        Result.insert(Result.end(), X25519Key.begin(), X25519Key.end());
        return Result;
    }

    auto MakeHandshake(std::uint8_t Type, const std::vector<std::uint8_t> &Body)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result{Type};
        AppendU24(Result, Body.size());
        Result.insert(Result.end(), Body.begin(), Body.end());
        return Result;
    }

    auto MakeRecord(std::uint8_t Type, const std::vector<std::uint8_t> &Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result{Type, 0x03, 0x03};
        AppendU16(Result, Payload.size());
        Result.insert(Result.end(), Payload.begin(), Payload.end());
        return Result;
    }

    auto MakeRecordSequence(const std::vector<std::uint8_t> &Handshake,
                            const std::vector<std::size_t> &Parts)
        -> std::vector<std::vector<std::uint8_t>>
    {
        std::vector<std::vector<std::uint8_t>> Result;
        std::size_t Offset = 0;
        for (const auto Part : Parts)
        {
            const auto Count = (std::min)(Part, Handshake.size() - Offset);
            Result.push_back(MakeRecord(0x16,
                                        std::vector<std::uint8_t>(Handshake.begin() + Offset,
                                                                  Handshake.begin() + Offset + Count)));
            Offset += Count;
        }
        if (Offset < Handshake.size())
        {
            Result.push_back(MakeRecord(0x16,
                                        std::vector<std::uint8_t>(Handshake.begin() + Offset, Handshake.end())));
        }
        return Result;
    }

    auto Concatenate(const std::vector<std::vector<std::uint8_t>> &Parts) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        for (const auto &Part : Parts)
        {
            Result.insert(Result.end(), Part.begin(), Part.end());
        }
        return Result;
    }

    template <typename Factory>
    auto RunCoro(Net::io_context &Io, Factory FactoryFn) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, FactoryFn(), [&](std::exception_ptr Error)
                      {
                          Failure = Error;
                          Io.stop();
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    struct ReadOutcome
    {
        Preview::Error Error{Preview::Error::None};
        rec::ClientHelloFeatures Features;
    };

    struct ReadHelloRequest
    {
        Net::io_context &Io;
        std::shared_ptr<ScriptedTransport> Transport;
        rec::ProbeBuffer &Buffer;
        ReadOutcome &Outcome;
    };

    auto ReadHello(ReadHelloRequest Request) -> void
    {
        RunCoro(Request.Io, [Transport = std::move(Request.Transport), Buffer = &Request.Buffer,
                             Outcome = &Request.Outcome]() -> Net::awaitable<void>
                {
                    auto [Error, Features] = co_await rec::ReadClientHello(*Transport, *Buffer);
                    Outcome->Error = Error;
                    Outcome->Features = std::move(Features);
                });
    }

    auto ReadAll(Preview::SharedTransmission Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<std::size_t>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer.subspan(Offset), Error);
            if (Error || Count == 0)
            {
                co_return Offset;
            }
            Offset += Count;
        }
        co_return Offset;
    }






























    static_assert(requires(rec::Experiment::SniRouteTable &Routes)
                  { Routes.Add(std::string_view{}, std::string_view{}, Preview::Contract::ProtocolType::Tls); });
















} // namespace


