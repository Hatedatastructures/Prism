/**
 * @file ForwardResponseFraming.cpp
 * @brief HTTP/1.1 响应 framing 状态机实现 owner。
 */
#include <Prism/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Prism/Foundation/Utility/Http/ForwardResponseFields.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
namespace Prism::Http11
{
    namespace
    {
        [[nodiscard]] auto ToChar(const std::byte Byte) noexcept -> char
        {
            return static_cast<char>(std::to_integer<unsigned char>(Byte));
        }

        [[nodiscard]] auto FramingIsDigit(const char Character) noexcept -> bool
        {
            return Character >= '0' && Character <= '9';
        }

        [[nodiscard]] auto IsHexDigit(const char Character) noexcept -> bool
        {
            return (Character >= '0' && Character <= '9') ||
                   (Character >= 'a' && Character <= 'f') ||
                   (Character >= 'A' && Character <= 'F');
        }

        [[nodiscard]] auto FramingIsTokenChar(const char Character) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Character);
            if ((Byte >= 'A' && Byte <= 'Z') || (Byte >= 'a' && Byte <= 'z') ||
                (Byte >= '0' && Byte <= '9'))
            {
                return true;
            }
            constexpr std::string_view Punctuation{"!#$%&'*+-.^_`|~"};
            return Punctuation.find(Character) != std::string_view::npos;
        }

        [[nodiscard]] auto FramingIsFieldValueChar(const char Character) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Character);
            return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
        }

        [[nodiscard]] auto ParseStatusLine(std::string_view Line, int &StatusCode) noexcept -> bool
        {
            const auto Space = Line.find(' ');
            if (Space != 8U || Line.size() < Space + 4U || !Line.starts_with("HTTP/"))
            {
                return false;
            }
            if (!FramingIsDigit(Line[5]) || Line[6] != '.' || !FramingIsDigit(Line[7]))
            {
                return false;
            }
            if (!FramingIsDigit(Line[Space + 1U]) || !FramingIsDigit(Line[Space + 2U]) ||
                !FramingIsDigit(Line[Space + 3U]))
            {
                return false;
            }
            if (Line.size() > Space + 4U && Line[Space + 4U] != ' ')
            {
                return false;
            }
            StatusCode = (Line[Space + 1U] - '0') * 100 +
                         (Line[Space + 2U] - '0') * 10 + (Line[Space + 3U] - '0');
            return true;
        }

        [[nodiscard]] auto IsCrlf(std::string_view Line) noexcept -> bool
        {
            return Line.size() >= 2U && Line[Line.size() - 2U] == '\r' &&
                   Line.back() == '\n';
        }

        auto FramingTrimTrailingOws(std::string_view &Value) noexcept -> void
        {
            while (!Value.empty() && (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
        }

    } // namespace

    auto ForwardResponseFraming::AppendDecodedBody(std::span<const std::byte> Bytes) -> Error
    {
        if (!CaptureBody_) return Error::None;
        if (DecodedBody_.size() > MaxDecodedBodyBytes_ ||
            Bytes.size() > MaxDecodedBodyBytes_ - DecodedBody_.size())
        {
            return Error::BadLength;
        }
        for (const auto Byte : Bytes)
        {
            DecodedBody_.push_back(std::to_integer<std::uint8_t>(Byte));
        }
        return Error::None;
    }

    auto ForwardResponseFraming::CaptureDecodedBody(std::span<const std::byte> Bytes,
        ForwardResponseConsumeResult &Result) -> bool
    {
        if (!CaptureBody_) return true;
        const auto ErrorCode = AppendDecodedBody(Bytes);
        if (ErrorCode == Error::None) return true;
        Result.ErrorCode = Fail(ErrorCode);
        return false;
    }

    auto ForwardResponseFraming::ConsumeFramingByte() noexcept -> Error
    {
        if (FramingBytes_ >= MaxFramingBytes_) return Fail(Error::BadLength);
        ++FramingBytes_;
        return Error::None;
    }

    ForwardResponseFraming::ForwardResponseFraming(ForwardResponseFramingOptions Options)
        : RequestMethod_(Options.RequestMethod), AllowUpgrade_(Options.AllowUpgrade),
          CaptureBody_(Options.CaptureBody), MaxHeaderBytes_(Options.MaxHeaderBytes),
          MaxDecodedBodyBytes_(Options.MaxDecodedBodyBytes), MaxFramingBytes_(Options.MaxFramingBytes)
    {
        Header_.reserve(1024U);
        Line_.reserve(256U);
        Trailer_.reserve(512U);
    }

    auto ForwardResponseFraming::Consume(std::span<const std::byte> Buffer)
        -> ForwardResponseConsumeResult
    {
        ForwardResponseConsumeResult Result;
        if (State_ == State::Failed)
        {
            Result.ErrorCode = Failure_;
            return Result;
        }
        if (State_ == State::Complete)
        {
            if (!Buffer.empty())
            {
                Result.ErrorCode = Fail(Error::BadMessage);
            }
            Result.Complete = IsComplete();
            return Result;
        }

        while (Result.Accepted < Buffer.size())
        {
            const auto Byte = Buffer[Result.Accepted];
            Error ErrorCode = Error::None;
            switch (State_)
            {
            case State::Header:
                ErrorCode = ConsumeHeaderByte(Byte);
                ++Result.Accepted;
                break;
            case State::ContentLength:
            {
                const auto Available = Buffer.size() - Result.Accepted;
                const auto Count = static_cast<std::size_t>(
                    (std::min)(Remaining_, static_cast<std::uint64_t>(Available)));
                if (!CaptureDecodedBody(Buffer.subspan(Result.Accepted, Count), Result)) return Result;
                Result.Accepted += Count;
                Remaining_ -= Count;
                if (Remaining_ == 0U)
                {
                    State_ = State::Complete;
                }
                continue;
            }
            case State::ChunkSize:
                ErrorCode = ConsumeChunkSizeByte(Byte);
                ++Result.Accepted;
                break;
            case State::ChunkData:
            {
                const auto Available = Buffer.size() - Result.Accepted;
                const auto Count = static_cast<std::size_t>(
                    (std::min)(ChunkRemaining_, static_cast<std::uint64_t>(Available)));
                if (!CaptureDecodedBody(Buffer.subspan(Result.Accepted, Count), Result)) return Result;
                Result.Accepted += Count;
                ChunkRemaining_ -= Count;
                if (ChunkRemaining_ == 0U)
                {
                    State_ = State::ChunkDataCrlf;
                    ChunkCrlfProgress_ = 0;
                }
                continue;
            }
            case State::ChunkDataCrlf:
                ErrorCode = ConsumeChunkDataCrlfByte(Byte);
                ++Result.Accepted;
                break;
            case State::ChunkTrailer:
                ErrorCode = ConsumeTrailerByte(Byte);
                ++Result.Accepted;
                break;
            case State::CloseDelimited:
            case State::Tunnel:
                if (!CaptureDecodedBody(Buffer.subspan(Result.Accepted), Result)) return Result;
                Result.Accepted = Buffer.size();
                Result.Complete = false;
                return Result;
            case State::Complete:
                Result.ErrorCode = Fail(Error::BadMessage);
                Result.Complete = true;
                return Result;
            case State::Failed:
                Result.ErrorCode = Failure_;
                return Result;
            }

            if (ErrorCode != Error::None)
            {
                Result.ErrorCode = ErrorCode;
                return Result;
            }
        }

        Result.Complete = IsComplete();
        return Result;
    }

    auto ForwardResponseFraming::EndOfInput() noexcept -> Error
    {
        if (State_ == State::Failed)
        {
            return Failure_;
        }
        if (State_ == State::Complete)
        {
            return Error::None;
        }
        if (State_ == State::CloseDelimited || State_ == State::Tunnel)
        {
            State_ = State::Complete;
            return Error::None;
        }
        return Fail(Error::UnexpectedEof);
    }

    auto ForwardResponseFraming::ConsumeHeaderByte(const std::byte Byte) -> Error
    {
        if (HeaderBytes_ >= MaxHeaderBytes_) return Fail(Error::BadLength);
        ++HeaderBytes_;
        Header_.push_back(ToChar(Byte));
        if (Header_.size() > MaxResponseHeaderBlockBytes)
        {
            return Fail(Error::BadLength);
        }
        if (Header_.size() >= 2U)
        {
            const auto Last = Header_.back();
            const auto Previous = Header_[Header_.size() - 2U];
            if ((Last == '\n' && Previous != '\r') ||
                (Last != '\n' && Previous == '\r'))
            {
                return Fail(Error::BadMessage);
            }
        }
        if (Header_.size() >= 4U &&
            std::string_view(Header_).substr(Header_.size() - 4U) == "\r\n\r\n")
        {
            return ProcessHeader();
        }
        return Error::None;
    }

    auto ForwardResponseFraming::ConsumeChunkSizeByte(const std::byte Byte) -> Error
    {
        if (const auto ErrorCode = ConsumeFramingByte(); ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Line_.push_back(ToChar(Byte));
        if (Line_.size() > MaxResponseHeaderBlockBytes)
        {
            return Fail(Error::BadLength);
        }
        if (Line_.size() >= 2U)
        {
            const auto Last = Line_.back();
            const auto Previous = Line_[Line_.size() - 2U];
            if ((Last == '\n' && Previous != '\r') ||
                (Last != '\n' && Previous == '\r'))
            {
                return Fail(Error::BadMessage);
            }
            if (Last == '\n')
            {
                return ProcessChunkSizeLine();
            }
        }
        return Error::None;
    }

    auto ForwardResponseFraming::ConsumeChunkDataCrlfByte(const std::byte Byte) -> Error
    {
        if (const auto ErrorCode = ConsumeFramingByte(); ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        const auto Expected = ChunkCrlfProgress_ == 0U ? '\r' : '\n';
        if (ToChar(Byte) != Expected)
        {
            return Fail(Error::BadMessage);
        }
        ++ChunkCrlfProgress_;
        if (ChunkCrlfProgress_ == 2U)
        {
            ChunkCrlfProgress_ = 0;
            State_ = State::ChunkSize;
        }
        return Error::None;
    }

    auto ForwardResponseFraming::ConsumeTrailerByte(const std::byte Byte) -> Error
    {
        if (const auto ErrorCode = ConsumeFramingByte(); ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        Line_.push_back(ToChar(Byte));
        if (Line_.size() > MaxResponseHeaderBlockBytes)
        {
            return Fail(Error::BadLength);
        }
        if (Line_.size() >= 2U)
        {
            const auto Last = Line_.back();
            const auto Previous = Line_[Line_.size() - 2U];
            if ((Last == '\n' && Previous != '\r') ||
                (Last != '\n' && Previous == '\r'))
            {
                return Fail(Error::BadMessage);
            }
            if (Last == '\n')
            {
                return ProcessTrailerLine();
            }
        }
        return Error::None;
    }

    auto ForwardResponseFraming::ProcessHeader() -> Error
    {
        const auto TerminatorStart = Header_.size() - 4U;
        const auto LineEnd = std::string_view(Header_).find("\r\n");
        if (LineEnd == std::string_view::npos || LineEnd > TerminatorStart)
        {
            return Fail(Error::BadMessage);
        }

        int StatusCode = 0;
        if (!ParseStatusLine(std::string_view(Header_).substr(0, LineEnd), StatusCode))
        {
            return Fail(Error::BadMessage);
        }

        std::string_view HeaderBlock;
        const auto HeaderBlockStart = LineEnd + 2U;
        if (LineEnd < TerminatorStart)
        {
            if (HeaderBlockStart > TerminatorStart)
            {
                return Fail(Error::BadMessage);
            }
            HeaderBlock = std::string_view(Header_).substr(
                HeaderBlockStart, TerminatorStart - HeaderBlockStart);
        }
        const auto NoBody = StatusCode == 101 || (StatusCode >= 100 && StatusCode < 200) ||
                            RequestMethod_ == ForwardResponseMethod::Head || StatusCode == 204 ||
                            StatusCode == 304;
        const auto Parsed = ParseResponseHeaders(HeaderBlock, NoBody);
        if (!Parsed)
        {
            return Fail(Error::BadMessage);
        }
        if (StatusCode == 101)
        {
            StatusCode_ = StatusCode;
            ResponseFields_ = *Parsed;
            FinalResponseHeadersReady_ = true;
            if (!AllowUpgrade_)
            {
                return Fail(Error::BadMessage);
            }
            State_ = State::Tunnel;
            return Error::None;
        }
        if (StatusCode >= 100 && StatusCode < 200)
        {
            ResetHeader();
            return Error::None;
        }
        StatusCode_ = StatusCode;
        ResponseFields_ = *Parsed;
        FinalResponseHeadersReady_ = true;
        if (CaptureBody_ && Parsed->HasContentLength &&
            Parsed->ContentLength > MaxDecodedBodyBytes_)
        {
            return Fail(Error::BadLength);
        }
        if (RequestMethod_ == ForwardResponseMethod::Head || StatusCode == 204 || StatusCode == 304)
        {
            State_ = State::Complete;
            return Error::None;
        }
        if (Parsed->HasTransferEncoding)
        {
            if (Parsed->FinalTransferCodingChunked)
            {
                State_ = State::ChunkSize;
                return Error::None;
            }
            State_ = State::CloseDelimited;
            return Error::None;
        }
        if (Parsed->HasContentLength)
        {
            Remaining_ = Parsed->ContentLength;
            State_ = Remaining_ == 0U ? State::Complete : State::ContentLength;
            return Error::None;
        }
        State_ = State::CloseDelimited;
        return Error::None;
    }

    auto ForwardResponseFraming::ProcessChunkSizeLine() -> Error
    {
        std::uint64_t Size = 0;
        if (!ParseChunkSizeLine(Size))
        {
            return Fail(Error::BadMessage);
        }
        if (CaptureBody_ &&
            (DecodedBody_.size() > MaxDecodedBodyBytes_ ||
             Size > MaxDecodedBodyBytes_ - DecodedBody_.size()))
        {
            return Fail(Error::BadLength);
        }
        Line_.clear();
        ChunkRemaining_ = Size;
        if (Size == 0U)
        {
            State_ = State::ChunkTrailer;
        }
        else
        {
            State_ = State::ChunkData;
        }
        return Error::None;
    }

    auto ForwardResponseFraming::ProcessTrailerLine() -> Error
    {
        if (Line_ == "\r\n")
        {
            const auto TrailerError = ValidateResponseTrailers(Trailer_);
            if (TrailerError != Error::None)
            {
                return Fail(TrailerError);
            }
            Line_.clear();
            Trailer_.clear();
            State_ = State::Complete;
            return Error::None;
        }
        Trailer_.append(Line_);
        Line_.clear();
        if (Trailer_.size() > MaxResponseHeaderBlockBytes)
        {
            return Fail(Error::BadLength);
        }
        return Error::None;
    }

    auto ForwardResponseFraming::ParseChunkSizeLine(std::uint64_t &Size) const noexcept -> bool
    {
        if (!IsCrlf(Line_))
        {
            return false;
        }
        std::string_view Text(Line_.data(), Line_.size() - 2U);
        const auto Separator = Text.find(';');
        auto Digits = Text.substr(0, Separator);
        if (Separator != std::string_view::npos)
        {
            FramingTrimTrailingOws(Digits);
        }
        if (Digits.empty())
        {
            return false;
        }
        for (const auto Character : Digits)
        {
            if (!IsHexDigit(Character))
            {
                return false;
            }
        }
        const auto [Next, ErrorCode] = std::from_chars(
            Digits.data(), Digits.data() + Digits.size(), Size, 16);
        if (ErrorCode != std::errc{} || Next != Digits.data() + Digits.size())
        {
            return false;
        }
        return Separator == std::string_view::npos ||
               ParseChunkExtensions(Text.substr(Separator));
    }

    auto ForwardResponseFraming::ParseChunkExtensions(std::string_view Extensions) const noexcept -> bool
    {
        std::size_t Offset = 0;
        const auto SkipOws = [&]()
        {
            while (Offset < Extensions.size() &&
                   (Extensions[Offset] == ' ' || Extensions[Offset] == '\t'))
            {
                ++Offset;
            }
        };
        while (Offset < Extensions.size())
        {
            SkipOws();
            if (Offset == Extensions.size() || Extensions[Offset++] != ';')
            {
                return false;
            }
            SkipOws();
            const auto NameStart = Offset;
            while (Offset < Extensions.size() && FramingIsTokenChar(Extensions[Offset]))
            {
                ++Offset;
            }
            if (NameStart == Offset)
            {
                return false;
            }
            SkipOws();
            if (Offset == Extensions.size())
            {
                continue;
            }
            if (Extensions[Offset++] != '=')
            {
                return false;
            }
            SkipOws();
            if (Offset == Extensions.size())
            {
                return false;
            }
            if (Extensions[Offset] == '"')
            {
                ++Offset;
                bool Closed = false;
                while (Offset < Extensions.size())
                {
                    auto Character = Extensions[Offset++];
                    if (Character == '"')
                    {
                        Closed = true;
                        break;
                    }
                    if (Character == '\\')
                    {
                        if (Offset == Extensions.size() || !FramingIsFieldValueChar(Extensions[Offset++]))
                        {
                            return false;
                        }
                    }
                    else if (!FramingIsFieldValueChar(Character))
                    {
                        return false;
                    }
                }
                if (!Closed)
                {
                    return false;
                }
            }
            else
            {
                const auto ValueStart = Offset;
                while (Offset < Extensions.size() && FramingIsTokenChar(Extensions[Offset]))
                {
                    ++Offset;
                }
                if (ValueStart == Offset)
                {
                    return false;
                }
            }
            SkipOws();
            if (Offset < Extensions.size() && Extensions[Offset] != ';')
            {
                return false;
            }
        }
        return true;
    }

    auto ForwardResponseFraming::Fail(const Error ErrorCode) noexcept -> Error
    {
        Failure_ = ErrorCode == Error::None ? Error::ProtocolError : ErrorCode;
        State_ = State::Failed;
        return Failure_;
    }

    auto ForwardResponseFraming::ResetHeader() -> void
    {
        Header_.clear();
        StatusCode_ = 0;
        FinalResponseHeadersReady_ = false;
        ResponseFields_ = {};
        State_ = State::Header;
    }

} // namespace Prism::Http11
