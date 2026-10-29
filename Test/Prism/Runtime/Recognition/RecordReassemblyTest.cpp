/**
 * @file RecordReassemblyTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ReassemblySupport.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/RawIngressProbe.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace
{

    /** @brief 保存 TLS 回放用例的输入与读取观察结果。 */
    struct RawIngressReplayScenario final
    {
        std::shared_ptr<ScriptedTransport> Transport;
        std::vector<std::byte> Prefix;
        rec::RawIngressProbeResult Result{};
        Prism::IoResult PrefixResult{};
        Prism::IoResult FollowingResult{};
        std::size_t ReadsAfterProbe{};
        bool HasReplay{};
    };

    /** @brief 执行 RawIngress 探测，并按顺序读取缓存前缀和终态。 */
    auto RunRawIngressReplayScenario(RawIngressReplayScenario &Scenario) -> Net::awaitable<void>
    {
        Scenario.Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
            std::static_pointer_cast<Prism::Transmission>(Scenario.Transport),
            std::chrono::milliseconds::zero(), MakeTlsReassemblyBytePool()});
        Scenario.ReadsAfterProbe = Scenario.Transport->ReadRequests().size();
        Scenario.HasReplay = static_cast<bool>(Scenario.Result.Transport);
        if (Scenario.HasReplay)
        {
            Scenario.PrefixResult = co_await Scenario.Result.Transport->ReadSome(Scenario.Prefix);
            Scenario.FollowingResult = co_await Scenario.Result.Transport->ReadSome(Scenario.Prefix);
        }
    }

} // namespace

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
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
        EXPECT_EQ(Outcome.Features.ServerName, "fragment.example");
        EXPECT_GE(Transport->ReadRequests().size(), 5U);
        EXPECT_EQ(Buffer.Size(), Record.size());
    }

TEST(TlsReassemblyTest, RawIngressProbeClassifiesCleartextAndReplaysFirstByte)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Wire{'G', 'E', 'T', ' '};
        Transport->Push(AsBytes(Wire));
        rec::RawIngressProbeResult Result;
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t ReplayedBytes = 0;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
                    std::static_pointer_cast<Prism::Transmission>(Transport),
                    std::chrono::milliseconds::zero(), MakeTlsReassemblyBytePool()});
                ReplayedBytes = co_await ReadAll(Result.Transport, Replayed);
            });

        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Cleartext);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(ReplayedBytes, Wire.size());
        EXPECT_EQ(Replayed, AsBytes(Wire));
    }

TEST(TlsReassemblyTest, RawIngressProbeReplaysCleartextPrefixBeforeTerminal)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Wire{'G'};
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(AsBytes(Wire), Reset);
        rec::RawIngressProbeResult Result;
        Prism::IoResult PrefixResult;
        Prism::IoResult FollowingResult;
        std::array<std::byte, 1> Prefix{};
        std::array<std::byte, 1> Following{};
        std::size_t ReadCallsAfterProbe = 0;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
                    std::static_pointer_cast<Prism::Transmission>(Transport),
                    std::chrono::milliseconds::zero(), MakeTlsReassemblyBytePool()});
                ReadCallsAfterProbe = Transport->ReadRequests().size();
                PrefixResult = co_await Result.Transport->ReadSome(Prefix);
                FollowingResult = co_await Result.Transport->ReadSome(Following);
            });

        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Cleartext);
        EXPECT_EQ(PrefixResult.Bytes, 1U);
        EXPECT_EQ(Prefix[0], static_cast<std::byte>('G'));
        EXPECT_EQ(PrefixResult.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(PrefixResult.Failure.Native, Reset);
        EXPECT_EQ(FollowingResult.Bytes, 0U);
        EXPECT_EQ(FollowingResult.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(FollowingResult.Failure.Native, Reset);
        EXPECT_EQ(Transport->ReadRequests().size(), ReadCallsAfterProbe);
    }

TEST(TlsReassemblyTest, RawIngressParsesCompleteHelloBeforeEofAndReplaysTerminal)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("probe.example", {"h2"}, false);
        const auto Wire = Concatenate(MakeRecordSequence(Handshake, {Handshake.size()}));
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        Transport->Push(AsBytes(Wire), Eof);
        RawIngressReplayScenario Scenario{Transport, std::vector<std::byte>(Wire.size())};
        RunCoro(Io, [&Scenario] { return RunRawIngressReplayScenario(Scenario); });

        const auto &Result = Scenario.Result;
        const auto &PrefixResult = Scenario.PrefixResult;
        const auto &FollowingResult = Scenario.FollowingResult;
        const auto ReadsAfterProbe = Scenario.ReadsAfterProbe;
        const auto HasReplay = Scenario.HasReplay;
        const auto &Prefix = Scenario.Prefix;

        ASSERT_TRUE(HasReplay);
        const auto Expected = AsBytes(Wire);
        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Tls);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Result.ClientHello.ServerName, "probe.example");
        EXPECT_EQ(PrefixResult.Bytes, Expected.size());
        EXPECT_TRUE(std::equal(Expected.begin(), Expected.end(), Prefix.begin()));
        EXPECT_EQ(PrefixResult.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(PrefixResult.Failure.Native, Eof);
        EXPECT_EQ(FollowingResult.Bytes, 0U);
        EXPECT_EQ(FollowingResult.Failure.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(FollowingResult.Failure.Native, Eof);
        EXPECT_EQ(Transport->ReadRequests().size(), ReadsAfterProbe);
    }

TEST(TlsReassemblyTest, RawIngressReplaysPartialHelloBeforeReset)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("probe.example", {"h2"}, false);
        const auto Wire = Concatenate(MakeRecordSequence(Handshake, {Handshake.size()}));
        const std::vector<std::uint8_t> Partial(Wire.begin(),
            Wire.begin() + static_cast<std::ptrdiff_t>(rec::TlsRecordHeaderSize + 2U));
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(AsBytes(Partial), Reset);
        RawIngressReplayScenario Scenario{Transport, std::vector<std::byte>(Partial.size())};
        RunCoro(Io, [&Scenario] { return RunRawIngressReplayScenario(Scenario); });

        const auto &Result = Scenario.Result;
        const auto &PrefixResult = Scenario.PrefixResult;
        const auto &FollowingResult = Scenario.FollowingResult;
        const auto ReadsAfterProbe = Scenario.ReadsAfterProbe;
        const auto HasReplay = Scenario.HasReplay;
        const auto &Prefix = Scenario.Prefix;

        ASSERT_TRUE(HasReplay);
        const auto Expected = AsBytes(Partial);
        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Rejected);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::IoError);
        EXPECT_EQ(Result.ProtocolError, Prism::Error::IoError);
        EXPECT_EQ(PrefixResult.Bytes, Expected.size());
        EXPECT_TRUE(std::equal(Expected.begin(), Expected.end(), Prefix.begin()));
        EXPECT_EQ(PrefixResult.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(PrefixResult.Failure.Native, Reset);
        EXPECT_EQ(FollowingResult.Bytes, 0U);
        EXPECT_EQ(FollowingResult.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(FollowingResult.Failure.Native, Reset);
        EXPECT_EQ(Transport->ReadRequests().size(), ReadsAfterProbe);
    }

TEST(TlsReassemblyTest, RawIngressProbeReassemblesHelloAndReplaysResidual)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("probe.example", {"h2", "http/1.1"}, false);
        auto Wire = Concatenate(MakeRecordSequence(Handshake, {1, 2, 4, 7}));
        const std::array<std::uint8_t, 4> Residual{0x17, 0x03, 0x03, 0x00};
        Wire.insert(Wire.end(), Residual.begin(), Residual.end());
        for (const auto Byte : Wire)
        {
            Transport->Push({static_cast<std::byte>(Byte)});
        }
        rec::RawIngressProbeResult Result;
        std::vector<std::byte> Replayed(Wire.size());
        std::size_t ReplayedBytes = 0;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
                    std::static_pointer_cast<Prism::Transmission>(Transport),
                    std::chrono::seconds(1), MakeTlsReassemblyBytePool()});
                ReplayedBytes = co_await ReadAll(Result.Transport, Replayed);
            });

        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Tls);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Success);
        EXPECT_EQ(Result.ClientHello.ServerName, "probe.example");
        EXPECT_EQ(Result.ClientHello.AlpnProtocols,
                  (std::vector<std::string>{"h2", "http/1.1"}));
        EXPECT_EQ(ReplayedBytes, Wire.size());
        EXPECT_EQ(Replayed, AsBytes(Wire));
    }

TEST(TlsReassemblyTest, RawIngressProbeRejectsMalformedTlsInsteadOfDowngrading)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Malformed = AsBytes(MakeRecord(0x16, MakeHandshake(0x02, {0x00})));
        Transport->Push(Malformed);
        rec::RawIngressProbeResult Result;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
                    std::static_pointer_cast<Prism::Transmission>(Transport),
                    std::chrono::milliseconds::zero(), MakeTlsReassemblyBytePool()});
            });

        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Rejected);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::BadMessage);
    }

TEST(TlsReassemblyTest, RawIngressProbeTimesOutSilentClientHello)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<Prism::PrismMockTransport>(Io.get_executor());
        rec::RawIngressProbeResult Result;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await rec::RawIngressProbe::Run(rec::RawIngressProbeRequest{
                    std::static_pointer_cast<Prism::Transmission>(Transport),
                    std::chrono::milliseconds(10), MakeTlsReassemblyBytePool()});
            });

        EXPECT_EQ(Result.Kind, rec::RawIngressKind::Rejected);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Timeout);
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
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
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
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
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
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
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
        Prism::IoResult ReadResult{};
        Io.restart();
        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    ReadResult = co_await Transport->ReadSome(Remainder);
                });
        EXPECT_FALSE(ReadResult.Failure.Failed());
        EXPECT_EQ(ReadResult.Bytes, Expected.size());
        EXPECT_EQ(Remainder, Expected);
    }

TEST(TlsReassemblyTest, ParsesUnknownExtensionWithoutLosingAlpnOrder)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello("unknown.example", {"acme", "h2", "http/1.1"}, true);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
        EXPECT_TRUE(Outcome.Features.HasAlpn);
        EXPECT_EQ(Outcome.Features.AlpnProtocols,
                  (std::vector<std::string>{"acme", "h2", "http/1.1"}));
    }

TEST(TlsReassemblyTest, ExtractsX25519FromHybridOnlyKeyShare)
    {
        const auto ExpectedKey = MakeTestX25519Key(0x40);
        const auto HybridShare = MakeHybridKeyShare(ExpectedKey);
        const auto Handshake = MakeClientHelloWithKeyShares("hybrid.example", {{0x11EC, HybridShare}});
        const auto Record = MakeRecord(0x16, Handshake);

        const auto [Error, Features] = rec::ParseClientHello(Record);

        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_TRUE(Features.HasX25519);
        EXPECT_TRUE(Features.HasX25519MLKEM768);
        EXPECT_EQ(Features.X25519Key, ExpectedKey);
        EXPECT_EQ(Features.KeyShareGroups, (std::vector<std::uint16_t>{0x11EC}));
    }

TEST(TlsReassemblyTest, PreservesDirectX25519KeyShare)
    {
        const auto ExpectedKey = MakeTestX25519Key(0x20);
        const std::vector<std::uint8_t> DirectShare(ExpectedKey.begin(), ExpectedKey.end());
        const auto Handshake = MakeClientHelloWithKeyShares("direct.example", {{0x001D, DirectShare}});
        const auto Record = MakeRecord(0x16, Handshake);

        const auto [Error, Features] = rec::ParseClientHello(Record);

        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_TRUE(Features.HasX25519);
        EXPECT_FALSE(Features.HasX25519MLKEM768);
        EXPECT_EQ(Features.X25519Key, ExpectedKey);
        EXPECT_EQ(Features.KeyShareGroups, (std::vector<std::uint16_t>{0x001D}));
    }

TEST(TlsReassemblyTest, PreservesKeyShareOrderAndPrefersDirectX25519)
    {
        const auto DirectKey = MakeTestX25519Key(0x60);
        const auto HybridKey = MakeTestX25519Key(0xA0);
        const std::vector<std::uint8_t> DirectShare(DirectKey.begin(), DirectKey.end());
        const auto HybridShare = MakeHybridKeyShare(HybridKey);
        const std::vector<std::uint16_t> UnknownGroup{0xFEA5};
        const std::vector<std::uint8_t> UnknownShare{0x01, 0x02, 0x03};
        const std::vector<std::vector<TestKeyShare>> ShareOrders{
            {{0xFEA5, UnknownShare}, {0x11EC, HybridShare}, {0x001D, DirectShare}},
            {{0x001D, DirectShare}, {0xFEA5, UnknownShare}, {0x11EC, HybridShare}}};
        const std::vector<std::vector<std::uint16_t>> ExpectedOrders{
            {UnknownGroup[0], 0x11EC, 0x001D},
            {0x001D, UnknownGroup[0], 0x11EC}};

        for (std::size_t Index = 0; Index < ShareOrders.size(); ++Index)
        {
            const auto Handshake = MakeClientHelloWithKeyShares("ordered.example", ShareOrders[Index]);
            const auto Record = MakeRecord(0x16, Handshake);
            const auto [Error, Features] = rec::ParseClientHello(Record);

            EXPECT_EQ(Error, Prism::Error::None);
            EXPECT_EQ(Features.KeyShareGroups, ExpectedOrders[Index]);
            EXPECT_TRUE(Features.HasX25519MLKEM768);
            EXPECT_TRUE(Features.HasX25519);
            EXPECT_EQ(Features.X25519Key, DirectKey);
        }
    }

TEST(TlsReassemblyTest, RejectsMalformedHybridKeyShareLengthForX25519)
    {
        const std::vector<std::uint8_t> MalformedHybridShare(1215, 0xA5);
        const auto Handshake =
            MakeClientHelloWithKeyShares("malformed-hybrid.example", {{0x11EC, MalformedHybridShare}});
        const auto Record = MakeRecord(0x16, Handshake);

        const auto [Error, Features] = rec::ParseClientHello(Record);

        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_TRUE(Features.HasX25519MLKEM768);
        EXPECT_FALSE(Features.HasX25519);
        EXPECT_EQ(Features.KeyShareGroups, (std::vector<std::uint16_t>{0x11EC}));
        EXPECT_EQ(Features.X25519Key, (std::array<std::uint8_t, 32>{}));
    }

TEST(TlsReassemblyTest, KeepsUnknownKeyShareGroupsWithoutX25519Classification)
    {
        const std::vector<TestKeyShare> Shares{{0xFEA5, {0x01, 0x02, 0x03}}};
        const auto Handshake = MakeClientHelloWithKeyShares("unknown-group.example", Shares);
        const auto Record = MakeRecord(0x16, Handshake);

        const auto [Error, Features] = rec::ParseClientHello(Record);

        EXPECT_EQ(Error, Prism::Error::None);
        EXPECT_EQ(Features.KeyShareGroups, (std::vector<std::uint16_t>{0xFEA5}));
        EXPECT_FALSE(Features.HasX25519);
        EXPECT_FALSE(Features.HasX25519MLKEM768);
    }

TEST(TlsReassemblyTest, AcceptsClientHelloWithoutSni)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello({}, {"h2"}, false);
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
        EXPECT_TRUE(Outcome.Features.ServerName.empty());
        EXPECT_EQ(Outcome.Features.AlpnProtocols, (std::vector<std::string>{"h2"}));
    }

TEST(TlsReassemblyTest, RejectsClientHelloWithOversizedSessionId)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello(
            ClientHelloOptions{"oversized.example", {"h2"}, false, 33});
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::BadMessage);
    }

TEST(TlsReassemblyTest, RejectsDuplicateClientHelloExtension)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello(
            ClientHelloOptions{"duplicate.example", {"h2"}, false, 0, true});
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::BadMessage);
    }

TEST(TlsReassemblyTest, DetectsEncryptedClientHelloExtension)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Handshake = MakeClientHello(
            ClientHelloOptions{"outer.example", {"h2"}, false, 0, false, true});
        const auto Record = MakeRecord(0x16, Handshake);
        Transport->Push(AsBytes(Record));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::None);
        EXPECT_TRUE(Outcome.Features.HasEch);
        EXPECT_EQ(Outcome.Features.ServerName, "outer.example");
    }

TEST(TlsReassemblyTest, RejectsOversizedRecordBeforeReadingPayload)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03, 0x03, 0x40, 0x01}));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::BadLength);
        EXPECT_EQ(Transport->ReadRequests().size(), 1U);
    }

TEST(TlsReassemblyTest, RejectsClientHelloAbove64KiB)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x01, 0x01, 0x00, 0x00};
        Transport->Push(AsBytes(MakeRecord(0x16, Header)));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::BadLength);
    }

TEST(TlsReassemblyTest, ReturnsExplicitEofForShortRecordHeader)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03}));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::UnexpectedEof);
    }

TEST(TlsReassemblyTest, ParseClientHelloKeepsBadMessageForTruncatedInput)
    {
        const std::vector<std::uint8_t> Truncated{0x16, 0x03};
        const auto [Error, Features] = rec::ParseClientHello(Truncated);
        (void)Features;

        EXPECT_EQ(Error, Prism::Error::BadMessage);
    }

TEST(TlsReassemblyTest, ReturnsIoErrorAfterPartialReadWithError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        Transport->Push(AsBytes({0x16, 0x03}), std::make_error_code(std::errc::connection_reset));
        rec::ProbeBuffer Buffer(64 * 1024, MakeTlsReassemblyBytePool());
        ReadOutcome Outcome;

        ReadHello(ReadHelloRequest{Io, Transport, Buffer, Outcome});

        EXPECT_EQ(Outcome.Error, Prism::Error::IoError);
    }

