/**
 * @file ForwardResponseFields.hpp
 * @brief HTTP/1.1 响应头字段与 trailer 语法
 * @details 只提供响应语义所需的字段 framing 元数据。请求侧的认证、Host
 *          和逐跳字段策略不在此接口内。
 */

#pragma once

#include <Preview/Foundation/Error.hpp>

#include <cstddef>
#include <cstdint>
#include <charconv>
#include <cstddef>
#include <system_error>
#include <expected>
#include <string_view>

namespace Preview::Http11
{

    /**
     * @brief 响应字段块、chunk 行和 trailer 单块上限
     */
    inline constexpr std::size_t MaxResponseHeaderBlockBytes = 65536U;

    /**
     * @struct ForwardResponseFields
     * @brief 已验证的响应 framing 元数据
     */
    struct ForwardResponseFields final
    {
        bool HasContentLength{false};
        std::uint64_t ContentLength{0};
        std::size_t ContentLengthFieldCount{0};
        bool HasTransferEncoding{false};
        bool FinalTransferCodingChunked{false};
        std::size_t TransferCodingCount{0};
        std::size_t ContentTypeFieldCount{0};
        std::string_view ContentType; ///< 借用解析输入；由调用方保证字段块生命周期

        /** @brief 按大小写不敏感方式核对 media type，并忽略参数。 */
        [[nodiscard]] auto ContentTypeIs(std::string_view Expected) const noexcept -> bool;
    };

    /**
     * @brief 解析响应头字段
     * @param Block 不含最终空行的响应头字段块
     * @param IgnoreBodyFraming HEAD/1xx/204/304/101 等无实体响应语义
     * @return 已验证的响应 framing 元数据或协议错误
     */
    [[nodiscard]] auto ParseResponseHeaders(std::string_view Block, bool IgnoreBodyFraming)
        -> std::expected<ForwardResponseFields, Error>;

    /**
     * @brief 验证 chunked trailer 字段块
     * @param Block 不含最终空行的 trailer 字段块
     * @return Error::None 或字段/禁用 trailer 错误
     */
    [[nodiscard]] auto ValidateResponseTrailers(std::string_view Block) noexcept -> Error;

    namespace
    {
        [[nodiscard]] auto IsDigit(const char Character) noexcept -> bool
        {
            return Character >= '0' && Character <= '9';
        }

        [[nodiscard]] auto IsTokenChar(const char Character) noexcept -> bool
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

        [[nodiscard]] auto IsFieldValueChar(const char Character) noexcept -> bool
        {
            const auto Byte = static_cast<unsigned char>(Character);
            return Byte == '\t' || (Byte >= 0x20U && Byte != 0x7fU);
        }

        auto TrimTrailingOws(std::string_view &Value) noexcept -> void
        {
            while (!Value.empty() && (Value.back() == ' ' || Value.back() == '\t'))
            {
                Value.remove_suffix(1);
            }
        }

        [[nodiscard]] auto TrimOws(std::string_view Value) noexcept -> std::string_view
        {
            while (!Value.empty() && (Value.front() == ' ' || Value.front() == '\t'))
            {
                Value.remove_prefix(1);
            }
            TrimTrailingOws(Value);
            return Value;
        }

        [[nodiscard]] auto ResponseIequals(std::string_view Left, std::string_view Right) noexcept -> bool
        {
            if (Left.size() != Right.size())
            {
                return false;
            }
            for (std::size_t Index = 0; Index < Left.size(); ++Index)
            {
                auto A = static_cast<unsigned char>(Left[Index]);
                auto B = static_cast<unsigned char>(Right[Index]);
                if (A >= 'A' && A <= 'Z')
                {
                    A = static_cast<unsigned char>(A + ('a' - 'A'));
                }
                if (B >= 'A' && B <= 'Z')
                {
                    B = static_cast<unsigned char>(B + ('a' - 'A'));
                }
                if (A != B)
                {
                    return false;
                }
            }
            return true;
        }

        struct TransferCodingState final
        {
            bool ChunkedSeen{false};
            bool FinalChunked{false};
            std::size_t Count{0};
        };

        struct ResponseField final
        {
            std::string_view Name;
            std::string_view Value;
        };

        struct ResponseFieldParseOptions final
        {
            bool IgnoreBodyFraming{false};
            bool Trailer{false};
        };

        struct ResponseFieldParseState final
        {
            ResponseFieldParseOptions Options;
            TransferCodingState TransferCodings;
            ForwardResponseFields Metadata;
        };

        [[nodiscard]] auto ParseDecimal(std::string_view Value,
                                        std::uint64_t &Output) noexcept -> bool
        {
            if (Value.empty())
            {
                return false;
            }
            for (const auto Character : Value)
            {
                if (!IsDigit(Character))
                {
                    return false;
                }
            }
            const auto [Next, ErrorCode] = std::from_chars(
                Value.data(), Value.data() + Value.size(), Output);
            return ErrorCode == std::errc{} && Next == Value.data() + Value.size();
        }

        auto SkipOws(std::string_view Value, std::size_t &Offset) noexcept -> void
        {
            while (Offset < Value.size() && (Value[Offset] == ' ' || Value[Offset] == '\t'))
            {
                ++Offset;
            }
        }

        [[nodiscard]] auto ReadToken(std::string_view Value, std::size_t &Offset) noexcept
            -> std::string_view
        {
            const auto Start = Offset;
            while (Offset < Value.size() && IsTokenChar(Value[Offset]))
            {
                ++Offset;
            }
            return Value.substr(Start, Offset - Start);
        }

        [[nodiscard]] auto ParseQuotedValue(std::string_view Value, std::size_t &Offset) noexcept
            -> bool
        {
            if (Offset == Value.size() || Value[Offset++] != '"')
            {
                return false;
            }
            while (Offset < Value.size())
            {
                const auto Character = Value[Offset++];
                if (Character == '"')
                {
                    return true;
                }
                if (Character == '\\')
                {
                    if (Offset == Value.size() || !IsFieldValueChar(Value[Offset++]))
                    {
                        return false;
                    }
                }
                else if (!IsFieldValueChar(Character))
                {
                    return false;
                }
            }
            return false;
        }

        [[nodiscard]] auto ParseTransferCodingValue(std::string_view Value,
                                                    TransferCodingState &State) noexcept -> bool
        {
            Value = TrimOws(Value);
            if (Value.empty())
            {
                return false;
            }
            std::size_t Offset = 0;
            while (Offset < Value.size())
            {
                SkipOws(Value, Offset);
                const auto Coding = ReadToken(Value, Offset);
                if (Coding.empty() || State.ChunkedSeen)
                {
                    return false;
                }
                bool HasParameters = false;
                while (true)
                {
                    SkipOws(Value, Offset);
                    if (Offset == Value.size() || Value[Offset] != ';')
                    {
                        break;
                    }
                    HasParameters = true;
                    ++Offset;
                    SkipOws(Value, Offset);
                    if (ReadToken(Value, Offset).empty())
                    {
                        return false;
                    }
                    SkipOws(Value, Offset);
                    if (Offset == Value.size() || Value[Offset++] != '=')
                    {
                        return false;
                    }
                    SkipOws(Value, Offset);
                    if (Offset == Value.size())
                    {
                        return false;
                    }
                    if (Value[Offset] == '"')
                    {
                        if (!ParseQuotedValue(Value, Offset))
                        {
                            return false;
                        }
                    }
                    else if (ReadToken(Value, Offset).empty())
                    {
                        return false;
                    }
                }
                const auto IsChunked = ResponseIequals(Coding, "chunked");
                if (IsChunked && HasParameters)
                {
                    return false;
                }
                State.ChunkedSeen = State.ChunkedSeen || IsChunked;
                State.FinalChunked = IsChunked;
                ++State.Count;
                SkipOws(Value, Offset);
                if (Offset == Value.size())
                {
                    return true;
                }
                if (Value[Offset++] != ',')
                {
                    return false;
                }
            }
            return false;
        }

        [[nodiscard]] auto ParseFieldLine(std::string_view Line, ResponseField &Output) noexcept -> bool
        {
            if (Line.empty() || Line.front() == ' ' || Line.front() == '\t')
            {
                return false;
            }
            const auto Colon = Line.find(':');
            if (Colon == std::string_view::npos || Colon == 0U)
            {
                return false;
            }
            Output.Name = Line.substr(0, Colon);
            Output.Value = Line.substr(Colon + 1U);
            for (const auto Character : Output.Name)
            {
                if (!IsTokenChar(Character))
                {
                    return false;
                }
            }
            for (const auto Character : Output.Value)
            {
                if (!IsFieldValueChar(Character))
                {
                    return false;
                }
            }
            return true;
        }

        [[nodiscard]] auto IsForbiddenTrailer(std::string_view Name) noexcept -> bool
        {
            return ResponseIequals(Name, "content-length") || ResponseIequals(Name, "transfer-encoding") ||
                   ResponseIequals(Name, "trailer") || ResponseIequals(Name, "connection") ||
                   ResponseIequals(Name, "host") || ResponseIequals(Name, "upgrade");
        }

        [[nodiscard]] auto ApplyResponseField(const ResponseField &Field,
                                              ResponseFieldParseState &State) noexcept -> bool
        {
            if (State.Options.Trailer && IsForbiddenTrailer(Field.Name))
            {
                return false;
            }
            const auto Value = TrimOws(Field.Value);
            if (ResponseIequals(Field.Name, "content-length"))
            {
                std::uint64_t Length = 0;
                if (!ParseDecimal(Value, Length))
                {
                    return false;
                }
                if (State.Metadata.HasContentLength &&
                    State.Metadata.ContentLength != Length && !State.Options.IgnoreBodyFraming)
                {
                    return false;
                }
                State.Metadata.HasContentLength = true;
                State.Metadata.ContentLength = Length;
                ++State.Metadata.ContentLengthFieldCount;
                return true;
            }
            if (ResponseIequals(Field.Name, "transfer-encoding"))
            {
                if (!ParseTransferCodingValue(Value, State.TransferCodings))
                {
                    return false;
                }
                State.Metadata.HasTransferEncoding = true;
                State.Metadata.FinalTransferCodingChunked = State.TransferCodings.FinalChunked;
                return true;
            }
            if (ResponseIequals(Field.Name, "content-type"))
            {
                if (State.Metadata.ContentTypeFieldCount == 0U)
                {
                    State.Metadata.ContentType = Value;
                }
                ++State.Metadata.ContentTypeFieldCount;
            }
            return true;
        }

        [[nodiscard]] auto ParseFields(std::string_view Block,
                                       ResponseFieldParseOptions Options)
            -> std::expected<ForwardResponseFields, Error>
        {
            if (Block.size() > MaxResponseHeaderBlockBytes)
            {
                return std::unexpected(Error::BadLength);
            }

            ResponseFieldParseState State{.Options = Options};
            while (!Block.empty())
            {
                const auto Next = Block.find("\r\n");
                const auto Line = Next == std::string_view::npos ? Block : Block.substr(0, Next);
                Block = Next == std::string_view::npos ? std::string_view{} : Block.substr(Next + 2U);
                ResponseField Field;
                if (!ParseFieldLine(Line, Field) || !ApplyResponseField(Field, State))
                {
                    return std::unexpected(Error::BadMessage);
                }
            }
            if (!Options.IgnoreBodyFraming && State.Metadata.HasContentLength &&
                State.Metadata.HasTransferEncoding)
            {
                return std::unexpected(Error::BadMessage);
            }
            State.Metadata.FinalTransferCodingChunked = State.TransferCodings.FinalChunked;
            State.Metadata.TransferCodingCount = State.TransferCodings.Count;
            return State.Metadata;
        }
    } // namespace

    inline auto ForwardResponseFields::ContentTypeIs(const std::string_view Expected) const noexcept
        -> bool
    {
        if (ContentTypeFieldCount == 0U || ContentType.empty())
        {
            return false;
        }
        const auto Separator = ContentType.find(';');
        const auto MediaType = Separator == std::string_view::npos
                                   ? ContentType
                                   : ContentType.substr(0, Separator);
        return ResponseIequals(TrimOws(MediaType), Expected);
    }

    inline auto ParseResponseHeaders(std::string_view Block, const bool IgnoreBodyFraming)
        -> std::expected<ForwardResponseFields, Error>
    {
        return ParseFields(Block, {.IgnoreBodyFraming = IgnoreBodyFraming, .Trailer = false});
    }

    inline auto ValidateResponseTrailers(const std::string_view Block) noexcept -> Error
    {
        const auto Result = ParseFields(Block, {.IgnoreBodyFraming = false, .Trailer = true});
        return Result ? Error::None : Result.error();
    }
} // namespace Preview::Http11
