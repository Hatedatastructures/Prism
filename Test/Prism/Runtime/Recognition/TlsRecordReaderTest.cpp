/**
 * @file TlsRecordReaderTest.cpp
 * @brief TLS 记录读取在终态下的字节与错误契约。
 */

#include "ReassemblySupport.hpp"

#include <cstdint>
#include <memory>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/Recognition/TlsRecordReader.hpp>
TEST(TlsReassemblyTest, ReadTlsRecordMapsZeroByteEofToUnexpectedEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        Transport->Push({}, Eof);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.Status, Prism::Error::UnexpectedEof);
        EXPECT_TRUE(Outcome.Record.empty());
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.Terminal.Native, Eof);
    }

TEST(TlsReassemblyTest, ReadTlsRecordKeepsPartialNonEofAsIoError)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> HeaderPrefix{0x16, 0x03};
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(AsBytes(HeaderPrefix), Reset);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.Status, Prism::Error::IoError);
        EXPECT_EQ(Outcome.Record, HeaderPrefix);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.Terminal.Native, Reset);
    }

TEST(TlsReassemblyTest, ReadTlsRecordReturnsHeaderBytesWithTerminal)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> HeaderPrefix{0x16, 0x03};
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        Transport->Push(AsBytes(HeaderPrefix), Eof);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.Status, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Outcome.Record, HeaderPrefix);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.Terminal.Native, Eof);
    }

TEST(TlsReassemblyTest, ReadTlsRecordReturnsPartialPayloadBytesWithTerminal)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x16, 0x03, 0x03, 0x00, 0x04};
        const std::vector<std::uint8_t> PayloadPrefix{0x01, 0x02};
        Transport->Push(AsBytes(Header));
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(AsBytes(PayloadPrefix), Reset);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        auto Expected = Header;
        Expected.insert(Expected.end(), PayloadPrefix.begin(), PayloadPrefix.end());
        EXPECT_EQ(Outcome.Status, Prism::Error::IoError);
        EXPECT_EQ(Outcome.Record, Expected);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.Terminal.Native, Reset);
    }

TEST(TlsReassemblyTest, ReadTlsRecordReturnsPartialPayloadBytesWithEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x16, 0x03, 0x03, 0x00, 0x04};
        const std::vector<std::uint8_t> PayloadPrefix{0x01, 0x02};
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        Transport->Push(AsBytes(Header));
        Transport->Push(AsBytes(PayloadPrefix), Eof);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        auto Expected = Header;
        Expected.insert(Expected.end(), PayloadPrefix.begin(), PayloadPrefix.end());
        EXPECT_EQ(Outcome.Status, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Outcome.Record, Expected);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.Terminal.Native, Eof);
    }

TEST(TlsReassemblyTest, ReadTlsRecordReturnsPreviouslyReadPayloadBeforeEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x16, 0x03, 0x03, 0x00, 0x04};
        const std::vector<std::uint8_t> PayloadPrefix{0x01, 0x02};
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        Transport->Push(AsBytes(Header));
        Transport->Push(AsBytes(PayloadPrefix));
        Transport->Push({}, Eof);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        auto Expected = Header;
        Expected.insert(Expected.end(), PayloadPrefix.begin(), PayloadPrefix.end());
        EXPECT_EQ(Outcome.Status, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Outcome.Record, Expected);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.Terminal.Native, Eof);
    }

TEST(TlsReassemblyTest, ReadTlsRecordReturnsCompleteRecordBytesWithTerminal)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Payload{0x01, 0x02, 0x03};
        const auto Header = std::vector<std::uint8_t>{0x16, 0x03, 0x03, 0x00, 0x03};
        auto Record = Header;
        Record.insert(Record.end(), Payload.begin(), Payload.end());
        Transport->Push(AsBytes(Header));
        const auto Reset = std::make_error_code(std::errc::connection_reset);
        Transport->Push(AsBytes(Payload), Reset);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.Status, Prism::Error::None);
        EXPECT_EQ(Outcome.Record, Record);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Outcome.Terminal.Native, Reset);
    }

TEST(TlsReassemblyTest, ReadTlsRecordReturnsCompleteRecordAndEofSeparately)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x16, 0x03, 0x03, 0x00, 0x03};
        const std::vector<std::uint8_t> Payload{0x01, 0x02, 0x03};
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        auto Expected = Header;
        Expected.insert(Expected.end(), Payload.begin(), Payload.end());
        Transport->Push(AsBytes(Header));
        Transport->Push(AsBytes(Payload), Eof);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.Status, Prism::Error::None);
        EXPECT_EQ(Outcome.Record, Expected);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.Terminal.Native, Eof);
    }

TEST(TlsReassemblyTest, ReadTlsRecordMapsPayloadEofToUnexpectedEof)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransport>(Io.get_executor());
        const std::vector<std::uint8_t> Header{0x16, 0x03, 0x03, 0x00, 0x01};
        const auto Eof = Prism::Fault::make_error_code(Prism::Fault::Code::Eof);
        Transport->Push(AsBytes(Header));
        Transport->Push({}, Eof);
        rec::TlsRecordReadResult Outcome;

        RunCoro(Io, [&]() -> Net::awaitable<void>
                {
                    Outcome = co_await rec::ReadTlsRecord(*Transport);
                });

        EXPECT_EQ(Outcome.Status, Prism::Error::UnexpectedEof);
        EXPECT_EQ(Outcome.Record, Header);
        EXPECT_EQ(Outcome.Terminal.Code, Prism::Fault::Code::Eof);
        EXPECT_EQ(Outcome.Terminal.Native, Eof);
    }
