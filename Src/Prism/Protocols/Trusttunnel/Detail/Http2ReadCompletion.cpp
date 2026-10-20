/**
 * @file Http2ReadCompletion.cpp
 * @brief TrustTunnel HTTP/2 输入读取完成处理实现。
 */
#include <Prism/Protocols/Trusttunnel/Detail/Http2ReadCompletion.hpp>

#include <Prism/Foundation/Error.hpp>

#include <system_error>

namespace Prism::Trusttunnel::Detail
{
    auto ProcessHttp2ReadCompletion(
        const Http2ReadCompletion &Completion,
        const std::shared_ptr<H2::Session> &Session,
        const std::shared_ptr<Http2WireWriter> &Wire)
        -> Net::awaitable<Http2ReadStep>
    {
        const auto &Read = Completion.Result;
        if (Read.Bytes > Completion.Buffer.size())
        {
            co_return Http2ReadStep{true, {Prism::Fault::Code::IoError}, false};
        }

        Prism::Fault::Failure ProcessingFailure;
        bool FeedFailed = false;
        if (Read.Bytes != 0U)
        {
            std::error_code FeedError;
            if (!Session->Feed(Completion.Buffer.first(Read.Bytes), FeedError) &&
                FeedError != make_error_code(Prism::Error::NeedMore))
            {
                FeedFailed = true;
                ProcessingFailure = FeedError
                    ? Prism::Fault::FromNative(FeedError)
                    : Prism::Fault::Failure{Prism::Fault::Code::ProtocolError};
            }
            if (ProcessingFailure.Succeeded())
            {
                const auto Flushed = co_await FlushHttp2Frames(Session, Wire);
                if (!Flushed)
                {
                    ProcessingFailure = Flushed.error();
                }
            }
        }

        if (Read.Failure.Failed())
        {
            if (Read.Failure.Code == Prism::Fault::Code::Eof)
            {
                if (FeedFailed)
                {
                    co_return Http2ReadStep{true, ProcessingFailure, false};
                }
                if (ProcessingFailure.Failed())
                {
                    co_return Http2ReadStep{true, ProcessingFailure, true};
                }
                co_return Http2ReadStep{true, Read.Failure, true};
            }
            if (Read.Failure.Code != Prism::Fault::Code::Canceled)
            {
                co_return Http2ReadStep{
                    true, Read.Failure, !FeedFailed};
            }
            if (ProcessingFailure.Failed())
            {
                co_return Http2ReadStep{true, ProcessingFailure, false};
            }
            co_return Http2ReadStep{true, Read.Failure, true};
        }
        if (ProcessingFailure.Failed())
        {
            co_return Http2ReadStep{true, ProcessingFailure, false};
        }
        if (Read.Bytes == 0U)
        {
            co_return Http2ReadStep{
                true, {Prism::Fault::Code::WouldBlock}, true};
        }
        co_return Http2ReadStep{};
    }
}
