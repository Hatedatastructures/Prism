/**
 * @file ReadCompletion.cpp
 * @brief XHTTP HTTP/2 已完成读取的字节消费实现。
 */

#include <Prism/Protocols/Xhttp/Detail/Http2/ReadCompletion.hpp>

#include <Prism/Foundation/Error.hpp>

#include <system_error>

namespace Prism::Xhttp::Detail
{

    [[nodiscard]] auto ProcessHttp2ReadCompletion(
        Prism::Http2::H2Session &Session,
        const std::span<const std::byte> Buffer,
        const Prism::IoResult &Read) -> Http2ReadStep
    {
        if (Read.Bytes > Buffer.size())
        {
            return {{Prism::Fault::Code::InvalidArgument}, false};
        }
        if (Read.Bytes > 0U)
        {
            std::error_code FrameError;
            const auto Data = Buffer.first(Read.Bytes);
            const auto Fed = Session.Feed(Data, FrameError);
            if (!Fed && FrameError != Prism::make_error_code(Prism::Error::NeedMore))
            {
                if (FrameError)
                {
                    return {Prism::Fault::FromNative(FrameError), false};
                }
                return {{Prism::Fault::Code::ProtocolError}, false};
            }
        }
        if (Read.Failure.Failed())
        {
            return {Read.Failure, true};
        }
        if (Read.Bytes == 0U)
        {
            return {{Prism::Fault::Code::WouldBlock}, true};
        }
        return {{}, false};
    }

} // namespace Prism::Xhttp::Detail
