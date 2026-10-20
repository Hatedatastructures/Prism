/**
 * @file Error.cpp
 * @brief 协议错误消息分类实现。
 */
#include <Prism/Foundation/Error.hpp>

namespace Prism::Detail
{
    auto ProtocolCategory::message(const int ErrorValue) const -> std::string
    {
        switch (static_cast<Error>(ErrorValue))
        {
        case Error::None: return "no Error";
        case Error::NeedMore: return "need more Data";
        case Error::UnexpectedEof: return "unexpected end of Stream";
        case Error::BadLength: return "bad Message length";
        case Error::BadMagic: return "bad magic or version";
        case Error::BadAuth: return "authentication Failed";
        case Error::BadMessage: return "malformed Message";
        case Error::BadAddress: return "invalid Target Address";
        case Error::NotOpen: return "Stream not Open";
        case Error::Canceled: return "operation canceled";
        case Error::Timeout: return "operation timed out";
        case Error::BrokenPipe: return "broken pipe";
        case Error::ProtocolError: return "Protocol State Error";
        case Error::KdfError: return "key derivation Failed";
        case Error::Unsupported: return "unsupported feature";
        case Error::IoError: return "io Error";
        case Error::CryptoError: return "cryptographic operation failed";
        }
        return "unknown Protocol Error";
    }
} // namespace Prism::Detail
