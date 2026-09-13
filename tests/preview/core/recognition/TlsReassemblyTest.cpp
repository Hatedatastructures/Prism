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

#include <preview/Runtime/Recognition/ProbeBuffer.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Runtime/Recognition/Route.hpp>
#include <preview/Runtime/Recognition/SchemeExecutor.hpp>
#include <preview/Runtime/Recognition/Tls.hpp>
#include <preview/Transport/Transmission.hpp>

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

    auto MakeExtension(std::uint16_t Type, const std::vector<std::uint8_t> &Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Result;
        AppendU16(Result, Type);
        AppendU16(Result, Payload.size());
        Result.insert(Result.end(), Payload.begin(), Payload.end());
        return Result;
    }

    auto MakeClientHello(std::string_view ServerName, const std::vector<std::string> &Alpn,
                         bool IncludeUnknownExtension, std::size_t SessionIdLength = 0,
                         bool IncludeDuplicateSni = false, bool IncludeEch = false)
    {
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

    TEST(TlsReassemblyTest, ReadsFiveByteHeaderAcrossFragments)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("fragment.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        for (const auto Byte : Record)
        {
            Transport->Push({static_cast<std::byte>(Byte)});
        }
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_EQ(Outcome.Features.ServerName, "fragment.example");
        EXPECT_GE(Transport->ReadRequests().size(), 5U);
        EXPECT_EQ(Buffer.Size(), Record.size());
    }

    TEST(TlsReassemblyTest, ReassemblesClientHelloAcrossTwoRecords)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("two.example", {"h2", "http/1.1"}, true);
        const auto Records = MakeRecordSequence(Handshake, {4});
        for (const auto &Record : Records)
        {
            Transport->Push(AsBytes(Record));
        }
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_EQ(Outcome.Features.ServerName, "two.example");
        EXPECT_EQ(Outcome.Features.RawMessage, Handshake);
        EXPECT_EQ(Outcome.Features.RawRecord, Concatenate(Records));
        EXPECT_EQ(Outcome.Features.AlpnProtocols, (std::vector<std::string>{"h2", "http/1.1"}));
    }

    TEST(TlsReassemblyTest, ReassemblesHandshakeHeaderAndBodyAcrossThreeRecords)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("three.example", {"h3"}, false);
        const auto Records = MakeRecordSequence(Handshake, {1, 2});
        for (const auto &Record : Records)
        {
            Transport->Push(AsBytes(Record));
        }
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_EQ(Outcome.Features.ServerName, "three.example");
        EXPECT_EQ(Outcome.Features.RawMessage, Handshake);
        EXPECT_EQ(Outcome.Features.RawRecord, Concatenate(Records));
    }

    TEST(TlsReassemblyTest, StopsAtClientHelloAndPreservesSameRecordHandshakeTail)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("tail.example", {"h2"}, false);
        const auto TailHandshake = MakeHandshake(0x02, {0xAA, 0xBB});
        std::vector<std::uint8_t> Payload = Handshake;
        Payload.insert(Payload.end(), TailHandshake.begin(), TailHandshake.end());
        const auto Record = MakeRecord(0x16, Payload);
        const std::vector<std::uint8_t> Following{0x17, 0x03, 0x03, 0x00, 0x01, 0x7F};
        auto Combined = Record;
        Combined.insert(Combined.end(), Following.begin(), Following.end());
        Transport->Push(AsBytes(Combined));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_EQ(Outcome.Features.RawMessage, Handshake);
        EXPECT_EQ(Buffer.Size(), rec::TlsRecordHeaderSize + Handshake.size());
        EXPECT_EQ(Transport->RemainingBytes(), TailHandshake.size() + Following.size());
        const auto ExpectedTail = AsBytes(TailHandshake);
        const auto ExpectedFollowing = AsBytes(Following);
        std::vector<std::byte> Expected;
        Expected.reserve(TailHandshake.size() + Following.size());
        Expected.insert(Expected.end(), ExpectedTail.begin(), ExpectedTail.end());
        Expected.insert(Expected.end(), ExpectedFollowing.begin(), ExpectedFollowing.end());
        std::vector<std::byte> Remainder(Expected.size());
        std::error_code Error;
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await Transport->AsyncRead(Remainder, Error);
                });
        EXPECT_FALSE(Error);
        EXPECT_EQ(Count, Expected.size());
        EXPECT_EQ(Remainder, Expected);
    }

    TEST(TlsReassemblyTest, ParsesUnknownExtensionWithoutLosingAlpnOrder)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("unknown.example", {"acme", "h2", "http/1.1"}, true);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_TRUE(Outcome.Features.HasAlpn);
        EXPECT_EQ(Outcome.Features.AlpnProtocols,
                  (std::vector<std::string>{"acme", "h2", "http/1.1"}));
    }

    TEST(TlsReassemblyTest, AcceptsClientHelloWithoutSni)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello({}, {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_TRUE(Outcome.Features.ServerName.empty());
        EXPECT_EQ(Outcome.Features.AlpnProtocols, (std::vector<std::string>{"h2"}));
    }

    TEST(TlsReassemblyTest, RejectsClientHelloWithOversizedSessionId)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("oversized.example", {"h2"}, false, 33);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::BadMessage);
    }

    TEST(TlsReassemblyTest, RejectsDuplicateClientHelloExtension)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("duplicate.example", {"h2"}, false, 0, true);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::BadMessage);
    }

    TEST(TlsReassemblyTest, DetectsEncryptedClientHelloExtension)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("outer.example", {"h2"}, false, 0, false, true);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::None);
        EXPECT_TRUE(Outcome.Features.HasEch);
        EXPECT_EQ(Outcome.Features.ServerName, "outer.example");
    }

    TEST(TlsReassemblyTest, RejectsOversizedRecordBeforeReadingPayload)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03, 0x03, 0x40, 0x01}));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::BadLength);
        EXPECT_EQ(Transport->ReadRequests().size(), 1U);
    }

    TEST(TlsReassemblyTest, RejectsClientHelloAbove64KiB)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x01, 0x01, 0x00, 0x00};
        Transport->Push(AsBytes(MakeRecord(0x16, Header)));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::BadLength);
    }

    TEST(TlsReassemblyTest, ReturnsExplicitEofForShortRecordHeader)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03}));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::UnexpectedEof);
    }

    TEST(TlsReassemblyTest, ParseClientHelloKeepsBadMessageForTruncatedInput)
    {
        const std::vector<std::uint8_t> Truncated{0x16, 0x03};
        const auto [Error, Features] = rec::ParseClientHello(Truncated);
        (void)Features;

        EXPECT_EQ(Error, Preview::Error::BadMessage);
    }

    TEST(TlsReassemblyTest, ReturnsIoErrorAfterPartialReadWithError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03}), std::make_error_code(std::errc::connection_reset));
        rec::ProbeBuffer Buffer(64 * 1024);
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Preview::Error::IoError);
    }

    TEST(TlsReassemblyTest, ReadTlsRecordMapsZeroByteEofToUnexpectedEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Eof = Preview::Fault::make_error_code(Preview::Fault::Code::Eof);
        Transport->Push({}, Eof);
        std::pair<Preview::Error, std::vector<std::uint8_t>> Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.first, Preview::Error::UnexpectedEof);
        EXPECT_TRUE(Outcome.second.empty());
    }

    TEST(TlsReassemblyTest, ReadTlsRecordKeepsPartialNonEofAsIoError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03}), std::make_error_code(std::errc::connection_reset));
        std::pair<Preview::Error, std::vector<std::uint8_t>> Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.first, Preview::Error::IoError);
    }

    TEST(TlsReassemblyTest, ReadTlsRecordMapsPayloadEofToUnexpectedEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03, 0x03, 0x00, 0x01}));
        Transport->Push({}, Preview::Fault::make_error_code(Preview::Fault::Code::Eof));
        std::pair<Preview::Error, std::vector<std::uint8_t>> Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.first, Preview::Error::UnexpectedEof);
        EXPECT_TRUE(Outcome.second.empty());
    }

    TEST(TlsReassemblyTest, RouteUsesExactLongestWildcardThenDefault)
    {
        rec::SniRouteTable Routes;
        Routes.Add("*.example.com", "wild");
        Routes.Add("*.deep.example.com", "deep");
        Routes.Add("api.example.com", "exact", rec::RouteOptions{});
        Routes.SetDefault("default", rec::ProtocolType::Tls, true);

        const auto Exact = Routes.LookupValue("API.EXAMPLE.COM.");
        const auto Wildcard = Routes.LookupValue("node.deep.example.com");
        const auto Root = Routes.LookupValue("example.com");
        const auto Nested = Routes.LookupValue("a.b.example.com");
        ASSERT_TRUE(Exact.has_value());
        ASSERT_TRUE(Wildcard.has_value());
        ASSERT_TRUE(Root.has_value());
        ASSERT_TRUE(Nested.has_value());
        EXPECT_EQ(Exact->Scheme, "exact");
        EXPECT_EQ(Wildcard->Scheme, "deep");
        EXPECT_EQ(Root->Scheme, "default");
        EXPECT_EQ(Nested->Scheme, "default");
        EXPECT_EQ(Root->Protocol, rec::ProtocolType::Tls);
        EXPECT_TRUE(Root->AllowFallback);
    }

    TEST(TlsReassemblyTest, RouteValueResultRemainsStableAfterTableMutation)
    {
        rec::SniRouteTable Routes;
        Routes.Add("example.com", "first");
        const auto Stable = Routes.LookupValue("example.com");
        ASSERT_TRUE(Stable.has_value());

        Routes.Add("example.com", "second");

        EXPECT_EQ(Stable->Scheme, "first");
        EXPECT_EQ(Routes.Lookup("example.com"), "second");
    }

    TEST(TlsReassemblyTest, LegacyFourArgumentRouteAddRemainsConstrainedAndFunctional)
    {
        rec::SniRouteTable Routes;
        Routes.Add("legacy.example", "native", rec::ProtocolType::Trojan, true);

        const auto Entry = Routes.LookupValue("legacy.example");
        ASSERT_TRUE(Entry.has_value());
        EXPECT_EQ(Entry->Scheme, "native");
        EXPECT_EQ(Entry->Protocol, rec::ProtocolType::Trojan);
        EXPECT_TRUE(Entry->AllowFallback);
    }

    static_assert(requires(rec::SniRouteTable &Routes)
                  { Routes.Add(std::string_view{}, std::string_view{}, rec::ProtocolType::Tls); });

    TEST(TlsReassemblyTest, EmptyRoutePatternDoesNotBecomeImplicitDefault)
    {
        rec::SniRouteTable Routes;
        Routes.Add("", "native", rec::RouteOptions{rec::ProtocolType::Tls, true});

        EXPECT_FALSE(Routes.LookupValue("").has_value());
    }

    TEST(TlsReassemblyTest, ThreeArgumentProtocolRouteAddDefaultsFallback)
    {
        rec::SniRouteTable Routes;
        Routes.Add("three-arg.example", "native", rec::ProtocolType::Vless);

        const auto Entry = Routes.LookupValue("three-arg.example");
        ASSERT_TRUE(Entry.has_value());
        EXPECT_EQ(Entry->Protocol, rec::ProtocolType::Vless);
        EXPECT_FALSE(Entry->AllowFallback);
    }

    TEST(TlsReassemblyTest, ClearRemovesExplicitDefaultRoute)
    {
        rec::SniRouteTable Routes;
        Routes.SetDefault("fallback");
        ASSERT_TRUE(Routes.LookupValue("unknown.example").has_value());

        Routes.Clear();

        EXPECT_FALSE(Routes.LookupValue("unknown.example").has_value());
    }

    TEST(TlsReassemblyTest, PipelineReassemblesCrossRecordHelloAndReplaysResidualOnce)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("pipeline.example", {"h2"}, false);
        const auto Records = MakeRecordSequence(Handshake, {4});
        const auto Following = MakeRecord(0x17, {0x7F, 0x7E});
        auto Wire = Concatenate(Records);
        Wire.insert(Wire.end(), Following.begin(), Following.end());
        Transport->Push(AsBytes(Wire));

        rec::SniRouteTable Routes;
        Routes.Add("pipeline.example", "native", rec::RouteOptions{rec::ProtocolType::Tls, false});
        rec::SchemeExecutor Executor;
        auto Called = std::make_shared<bool>(false);
        Executor.RegisterScheme("native", [Called](Preview::SharedTransmission Inbound)
                                -> Net::awaitable<Preview::SharedTransmission>
        {
            *Called = true;
            co_return Inbound;
        });
        rec::Pipeline Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_TRUE(*Called);
        ASSERT_FALSE(Result.preread.empty());
        std::vector<std::byte> Expected;
        Expected.insert(Expected.end(), Result.preread.begin(), Result.preread.end());
        const auto FollowingBytes = AsBytes(Following);
        Expected.insert(Expected.end(), FollowingBytes.begin(), FollowingBytes.end());
        std::vector<std::byte> Replayed(Expected.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });

        EXPECT_EQ(Count, Expected.size());
        EXPECT_EQ(Replayed, Expected);
    }

    TEST(TlsReassemblyTest, PipelineKeepsSameRecordResidualAfterClientHello)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("same-record.example", {"h2"}, false);
        const auto Tail = MakeHandshake(0x02, {0xAA, 0xBB});
        auto Payload = Handshake;
        Payload.insert(Payload.end(), Tail.begin(), Tail.end());
        const auto Record = MakeRecord(0x16, Payload);
        Transport->Push(AsBytes(Record));

        rec::SniRouteTable Routes;
        Routes.Add("same-record.example", "native", rec::RouteOptions{});
        rec::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Preview::SharedTransmission Inbound)
                                -> Net::awaitable<Preview::SharedTransmission>
        {
            co_return Inbound;
        });
        rec::Pipeline Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_TRUE(Result.success);
        ASSERT_FALSE(Result.preread.empty());
        EXPECT_EQ(Transport->RemainingBytes(), Tail.size());
        std::vector<std::byte> Expected;
        Expected.insert(Expected.end(), Result.preread.begin(), Result.preread.end());
        const auto TailBytes = AsBytes(Tail);
        Expected.insert(Expected.end(), TailBytes.begin(), TailBytes.end());
        std::vector<std::byte> Replayed(Expected.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });

        EXPECT_EQ(Count, Expected.size());
        EXPECT_EQ(Replayed, Expected);
    }

    TEST(TlsReassemblyTest, LegacyPipelineRejectsTlsWithoutExplicitRoute)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("implicit-route.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto Wire = AsBytes(Record);
        Transport->Push(Wire);

        rec::Pipeline Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Tls);
        ASSERT_NE(Result.transport, nullptr);
        EXPECT_EQ(Result.preread, Wire);
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });
        EXPECT_EQ(Count, Wire.size());
        EXPECT_EQ(Replayed, Wire);
    }

    TEST(TlsReassemblyTest, LegacyPipelineAllowsOnlyExplicitTlsFallback)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("fallback.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto Wire = AsBytes(Record);
        Transport->Push(Wire);

        rec::SniRouteTable Routes;
        Routes.SetDefault("", rec::ProtocolType::Tls, true);
        rec::Pipeline Pipeline(&Routes, nullptr);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Tls);
        EXPECT_TRUE(Result.scheme.empty());
        ASSERT_NE(Result.transport, nullptr);
        EXPECT_EQ(Result.preread, Wire);
    }

    TEST(TlsReassemblyTest, PipelineUsesCallerOwnedProbeBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("caller-buffer.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));

        rec::SniRouteTable Routes;
        Routes.Add("caller-buffer.example", "native", rec::RouteOptions{});
        rec::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Preview::SharedTransmission Inbound)
                                -> Net::awaitable<Preview::SharedTransmission>
        {
            co_return Inbound;
        });
        rec::Pipeline Pipeline(&Routes, &Executor);
        rec::ProbeBuffer Buffer(64 * 1024);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_FALSE(Buffer.Empty());
        EXPECT_EQ(Buffer.Size(), Result.preread.size());
    }

    TEST(TlsReassemblyTest, PipelineContinuesFromExistingProbeBufferWithoutDuplicateSeed)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("existing-buffer.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto PrefixBytes = AsBytes(Record);
        const auto PrefixLength = std::size_t{24};
        rec::ProbeBuffer Buffer(64 * 1024);
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(PrefixBytes.data(), PrefixLength)));
        Transport->Push(std::vector<std::byte>(PrefixBytes.begin() + PrefixLength, PrefixBytes.end()));

        rec::SniRouteTable Routes;
        Routes.Add("existing-buffer.example", "native", rec::RouteOptions{});
        rec::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Preview::SharedTransmission Inbound)
                                -> Net::awaitable<Preview::SharedTransmission>
        {
            co_return Inbound;
        });
        rec::Pipeline Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Buffer.Size(), PrefixBytes.size());
        EXPECT_EQ(Result.preread, PrefixBytes);
        EXPECT_TRUE(std::equal(Buffer.Data().begin(), Buffer.Data().end(), PrefixBytes.begin(), PrefixBytes.end()));
        EXPECT_EQ(Result.detected, rec::ProtocolType::Tls);
    }

    TEST(TlsReassemblyTest, PipelineContinuesFromPartialTlsProbeBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("partial-buffer.example", {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        const auto Wire = AsBytes(Record);
        rec::ProbeBuffer Buffer(64 * 1024);
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 1)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 1, Wire.end()));

        rec::SniRouteTable Routes;
        Routes.Add("partial-buffer.example", "native", rec::RouteOptions{});
        rec::SchemeExecutor Executor;
        Executor.RegisterScheme("native", [](Preview::SharedTransmission Inbound)
                                -> Net::awaitable<Preview::SharedTransmission>
        {
            co_return Inbound;
        });
        rec::Pipeline Pipeline(&Routes, &Executor);
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Tls);
        EXPECT_EQ(Result.preread, Wire);
        EXPECT_EQ(Buffer.Size(), Wire.size());
    }

    TEST(TlsReassemblyTest, PipelineContinuesFromPartialHttpProbeBuffer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{'G', 'E', 'T', ' '});
        rec::ProbeBuffer Buffer(64 * 1024);
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 2)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 2, Wire.end()));
        rec::Pipeline Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Http);
        EXPECT_EQ(Result.preread, Wire);
        EXPECT_EQ(Buffer.Size(), Wire.size());
    }

    TEST(TlsReassemblyTest, PipelineDoesNotTreatTrojanMagicAsProtocol)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{0x0D, 0x0A, 0x0D, 0x0A});
        rec::ProbeBuffer Buffer(64 * 1024);
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 1)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 1, Wire.end()));
        rec::Pipeline Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Unknown);
        ASSERT_EQ(Result.preread.size(), 1U);
        EXPECT_EQ(Result.preread.front(), Wire.front());
        EXPECT_EQ(Buffer.Size(), 1U);
        if (Result.transport)
        {
            Result.transport->Close();
        }
    }

    TEST(TlsReassemblyTest, PipelineRejectsProtocolDetectedAfterNonEofProbeError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{'G', 'E', 'T', ' '});
        rec::ProbeBuffer Buffer(64 * 1024);
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), 2)));
        Transport->Push(std::vector<std::byte>(Wire.begin() + 2, Wire.end()),
                        std::make_error_code(std::errc::connection_reset));
        rec::Pipeline Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.preread, Wire);
        ASSERT_NE(Result.transport, nullptr);
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });
        EXPECT_EQ(Count, Wire.size());
        EXPECT_EQ(Replayed, Wire);
    }

    TEST(TlsReassemblyTest, PipelineReplaysIncompleteVlessPrefixAfterEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Wire = AsBytes(std::vector<std::uint8_t>{0x00});
        rec::ProbeBuffer Buffer(64 * 1024);
        ASSERT_TRUE(Buffer.Seed(std::span<const std::byte>(Wire.data(), Wire.size())));
        Transport->Push({}, Preview::Fault::make_error_code(Preview::Fault::Code::Eof));
        rec::Pipeline Pipeline;
        rec::RecognizeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await Pipeline.Recognize(Transport, Buffer);
                });

        EXPECT_FALSE(Result.success);
        EXPECT_EQ(Result.detected, rec::ProtocolType::Unknown);
        EXPECT_EQ(Result.preread, Wire);
        ASSERT_NE(Result.transport, nullptr);
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t Count = 0;
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Count = co_await ReadAll(Result.transport, Replayed);
                });
        EXPECT_EQ(Count, Wire.size());
        EXPECT_EQ(Replayed, Wire);
    }

    TEST(TlsReassemblyTest, ProbePreservesBytesReturnedWithReadError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Prefix = AsBytes(std::vector<std::uint8_t>{'G'});
        Transport->Push(Prefix, std::make_error_code(std::errc::connection_reset));
        rec::ProbeResult Result;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Result = co_await rec::Probe(*Transport);
                });

        EXPECT_FALSE(Result.success);
        ASSERT_EQ(Result.PreReadSize, Prefix.size());
        EXPECT_EQ(Result.PreRead.front(), Prefix.front());
    }

} // namespace
