/**
 * @file AdapterErrorMappingTest.cpp
 * @brief adapter 错误映射与 Session 拒绝路径行为契约。
 */

#include "AdapterTestSupport.hpp"

namespace
{
    auto RunErrorMappingCase(
        Net::io_context &IoContext,
        const Preview::Error ErrorValue,
        const Fault::Code Expected) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto Accept = MakeStubAccept(std::unexpected(ErrorValue));
        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        auto Accepted = co_await Accept->Accept(Transport, {});
        const auto Code = Accepted ? Fault::Code::Success
            : Fault::ToCode(Preview::make_error_code(Accepted.error()));
        if (Accepted)
        {
            Context.SetDataPlane(std::move(*Accepted));
            Transport = Context.Inbound();
        }
        EXPECT_EQ(Code, Expected);
        (void)Client;
    }

    [[nodiscard]] auto ExpectedFaultCode(const Preview::Error ErrorValue) -> Fault::Code
    {
        switch (ErrorValue)
        {
        case Preview::Error::None: return Fault::Code::Success;
        case Preview::Error::NeedMore: return Fault::Code::WouldBlock;
        case Preview::Error::UnexpectedEof: return Fault::Code::Eof;
        case Preview::Error::BadLength:
        case Preview::Error::BadMagic:
        case Preview::Error::BadMessage:
        case Preview::Error::VersionMismatch: return Fault::Code::BadMessage;
        case Preview::Error::BadAuth:
        case Preview::Error::AuthFailed: return Fault::Code::AuthFailed;
        case Preview::Error::NotSupported:
        case Preview::Error::Unsupported: return Fault::Code::NotSupported;
        case Preview::Error::BadAddress: return Fault::Code::UnsupportedAddress;
        case Preview::Error::NotOpen:
        case Preview::Error::BrokenPipe:
        case Preview::Error::IoError: return Fault::Code::IoError;
        case Preview::Error::Canceled: return Fault::Code::Canceled;
        case Preview::Error::Timeout: return Fault::Code::Timeout;
        case Preview::Error::ProtocolError: return Fault::Code::ProtocolError;
        case Preview::Error::KdfError: return Fault::Code::GenericError;
        default: return Fault::Code::GenericError;
        }
    }

    auto RunDgramReject(Net::io_context &IoContext, Fault::Code &Observed) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto [Data, Peer] = MakePairShared(IoContext);
        (void)Peer;
        Runtime::SessionOptions Options;
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::DatagramDataPlane{std::move(Data), {}};
        Options.Services->AcceptProtocol = MakeStubAccept(std::move(Plane));
        Runtime::Session Session(std::move(Options));

        std::error_code ErrorCode;
        const auto Greeting = Socks5Greeting();
        const auto Write = co_await Inbound->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        if (ErrorCode)
        {
            ADD_FAILURE() << ErrorCode.message();
            co_return;
        }
        Observed = (co_await Session.Run(Client)).Code;
    }
}

TEST(AdapterSeam, ErrorMapping)
{
    const std::pair<Preview::Error, Fault::Code> Cases[] = {
        {Preview::Error::BadAuth, Fault::Code::AuthFailed},
        {Preview::Error::AuthFailed, Fault::Code::AuthFailed},
        {Preview::Error::NotSupported, Fault::Code::NotSupported},
        {Preview::Error::IoError, Fault::Code::IoError},
        {Preview::Error::UnexpectedEof, Fault::Code::Eof},
        {static_cast<Preview::Error>(999), Fault::Code::GenericError},
    };
    for (const auto &[ErrorValue, Expected] : Cases)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunErrorMappingCase(IoContext, ErrorValue, Expected));
    }
}

TEST(AdapterSeam, ErrorMappingMirrorsFaultToCode)
{
    for (int Value = 0; Value <= static_cast<int>(Preview::Error::IoError); ++Value)
    {
        const auto ErrorValue = static_cast<Preview::Error>(Value);
        EXPECT_EQ(ExpectedFaultCode(ErrorValue),
                  Preview::Fault::ToCode(Preview::make_error_code(ErrorValue)))
            << "mismatch at Preview::Error value " << Value;
    }
    const auto Bogus = static_cast<Preview::Error>(999);
    EXPECT_EQ(Fault::Code::GenericError,
              Preview::Fault::ToCode(Preview::make_error_code(Bogus)));
}

TEST(AdapterSeam, SessionRejectsDgramWithoutUdpService)
{
    Net::io_context IoContext;
    Fault::Code Observed = Fault::Code::Success;
    RunCoro(IoContext, RunDgramReject(IoContext, Observed));
    EXPECT_EQ(Observed, Fault::Code::NotSupported);
}
