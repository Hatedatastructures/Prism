/**
 * @file AdapterErrorMappingTest.cpp
 * @brief adapter 错误映射与 Session 拒绝路径行为契约。
 */

#include "AdapterTestSupport.hpp"

namespace
{
    auto RunErrorMappingCase(
        Net::io_context &IoContext,
        const Prism::Error ErrorValue,
        const Fault::Code Expected) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto Accept = MakeStubAccept(std::unexpected(ErrorValue));
        Middleware::Context Context;
        SharedTransmission Transport = Inbound;
        auto Accepted = co_await Accept->Accept(Transport, {});
        const auto Code = Accepted ? Fault::Code::Success
            : Fault::ToCode(Prism::make_error_code(Accepted.error()));
        if (Accepted)
        {
            Context.SetDataPlane(std::move(*Accepted));
            Transport = Context.Inbound();
        }
        EXPECT_EQ(Code, Expected);
        (void)Client;
    }

    [[nodiscard]] auto ExpectedFaultCode(const Prism::Error ErrorValue) -> Fault::Code
    {
        switch (ErrorValue)
        {
        case Prism::Error::None: return Fault::Code::Success;
        case Prism::Error::NeedMore: return Fault::Code::WouldBlock;
        case Prism::Error::UnexpectedEof: return Fault::Code::Eof;
        case Prism::Error::BadLength:
        case Prism::Error::BadMagic:
        case Prism::Error::BadMessage:
        case Prism::Error::VersionMismatch: return Fault::Code::BadMessage;
        case Prism::Error::BadAuth:
        case Prism::Error::AuthFailed: return Fault::Code::AuthFailed;
        case Prism::Error::NotSupported:
        case Prism::Error::Unsupported: return Fault::Code::NotSupported;
        case Prism::Error::BadAddress: return Fault::Code::UnsupportedAddress;
        case Prism::Error::NotOpen:
        case Prism::Error::BrokenPipe:
        case Prism::Error::IoError: return Fault::Code::IoError;
        case Prism::Error::Canceled: return Fault::Code::Canceled;
        case Prism::Error::Timeout: return Fault::Code::Timeout;
        case Prism::Error::ProtocolError: return Fault::Code::ProtocolError;
        case Prism::Error::KdfError: return Fault::Code::GenericError;
        default: return Fault::Code::GenericError;
        }
    }

    auto RunDgramReject(Net::io_context &IoContext, Fault::Code &Observed) -> Net::awaitable<void>
    {
        auto [Client, Inbound] = MakePairShared(IoContext);
        auto [Data, Peer] = MakePairShared(IoContext);
        (void)Peer;
        Runtime::SessionOptions Options;
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::DatagramDataPlane{std::move(Data), {}};
        Options.Services->AcceptProtocol = MakeStubAccept(std::move(Plane));
        Runtime::Session Session(std::move(Options));

        std::error_code ErrorCode;
        const auto Greeting = Socks5Greeting();
        const auto Write = co_await Inbound->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Greeting.data()), Greeting.size()));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
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
    const std::pair<Prism::Error, Fault::Code> Cases[] = {
        {Prism::Error::BadAuth, Fault::Code::AuthFailed},
        {Prism::Error::AuthFailed, Fault::Code::AuthFailed},
        {Prism::Error::NotSupported, Fault::Code::NotSupported},
        {Prism::Error::IoError, Fault::Code::IoError},
        {Prism::Error::UnexpectedEof, Fault::Code::Eof},
        {static_cast<Prism::Error>(999), Fault::Code::GenericError},
    };
    for (const auto &[ErrorValue, Expected] : Cases)
    {
        Net::io_context IoContext;
        RunCoro(IoContext, RunErrorMappingCase(IoContext, ErrorValue, Expected));
    }
}

TEST(AdapterSeam, ErrorMappingMirrorsFaultToCode)
{
    for (int Value = 0; Value <= static_cast<int>(Prism::Error::IoError); ++Value)
    {
        const auto ErrorValue = static_cast<Prism::Error>(Value);
        EXPECT_EQ(ExpectedFaultCode(ErrorValue),
                  Prism::Fault::ToCode(Prism::make_error_code(ErrorValue)))
            << "mismatch at Prism::Error value " << Value;
    }
    const auto Bogus = static_cast<Prism::Error>(999);
    EXPECT_EQ(Fault::Code::GenericError,
              Prism::Fault::ToCode(Prism::make_error_code(Bogus)));
}

TEST(AdapterSeam, SessionRejectsDgramWithoutUdpService)
{
    Net::io_context IoContext;
    Fault::Code Observed = Fault::Code::Success;
    RunCoro(IoContext, RunDgramReject(IoContext, Observed));
    EXPECT_EQ(Observed, Fault::Code::NotSupported);
}
