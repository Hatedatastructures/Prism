/**
 * @file ForwardResponseFraming.hpp
 * @brief HTTP/1.1 源站响应消息定界状态机
 * @details 只处理响应状态行、头字段和消息正文边界。原始 wire 字节由
 *          ForwardResponseTransport 按 Consume() 返回的前缀直接转发。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Http/ForwardResponseFields.hpp>

namespace Prism::Http11
{

    /**
     * @enum ForwardResponseMethod
     * @brief 请求方法对响应正文规则的影响
     */
    enum class ForwardResponseMethod : std::uint8_t
    {
        Other,
        Head,
    };

    /**
     * @struct ForwardResponseFramingOptions
     * @brief 响应定界策略
     */
    struct ForwardResponseFramingOptions final
    {
        ForwardResponseMethod RequestMethod{ForwardResponseMethod::Other};
        bool AllowUpgrade{false};
        bool CaptureBody{false}; ///< 转发器默认只计边界，不复制正文
        std::size_t MaxHeaderBytes{std::numeric_limits<std::size_t>::max()}; ///< 累计状态行与字段上限
        std::size_t MaxDecodedBodyBytes{65536U}; ///< 解码正文累计上限
        std::size_t MaxFramingBytes{std::numeric_limits<std::size_t>::max()}; ///< chunk/trailer 累计开销
    };

    /**
     * @struct ForwardResponseConsumeResult
     * @brief 一次增量输入的消费结果
     * @details Accepted 以前缀字节数表示已属于当前响应并可原样转发。
     *          ErrorCode 非 None 时，调用方应先转发 Accepted 字节，再结束传输。
     */
    struct ForwardResponseConsumeResult final
    {
        std::size_t Accepted{0};
        Error ErrorCode{Error::None};
        bool Complete{false};
    };

    /**
     * @class ForwardResponseFraming
     * @brief HTTP/1.1 响应消息边界状态机
     * @details 响应字段语法和请求字段安全策略分开处理。本类维护响应特有的
     *          状态行、正文长度、chunked 和 Upgrade 状态。
     */
    class ForwardResponseFraming final
    {
    public:
        explicit ForwardResponseFraming(ForwardResponseFramingOptions Options);

        ForwardResponseFraming(const ForwardResponseFraming &) = delete;
        auto operator=(const ForwardResponseFraming &) -> ForwardResponseFraming & = delete;

        /**
         * @brief 增量消费源站响应 wire 字节
         * @param Buffer 源站输入
         * @return 已接受的前缀、消息错误和完成状态
         */
        [[nodiscard]] auto Consume(std::span<const std::byte> Buffer)
            -> ForwardResponseConsumeResult;

        /**
         * @brief 通知源站 clean EOF
         * @return None 表示 close-delimited 或 tunnel 正常结束，其余为截断错误
         */
        [[nodiscard]] auto EndOfInput() noexcept -> Error;

        [[nodiscard]] auto IsComplete() const noexcept -> bool
        {
            return State_ == State::Complete;
        }
        [[nodiscard]] auto IsTunnel() const noexcept -> bool
        {
            return State_ == State::Tunnel;
        }
        [[nodiscard]] auto IsFailed() const noexcept -> bool
        {
            return State_ == State::Failed;
        }
        /** @brief 最终（非 1xx）响应头已解析；字段视图在本对象销毁前有效。 */
        [[nodiscard]] auto HasFinalResponseHeaders() const noexcept -> bool
        {
            return FinalResponseHeadersReady_;
        }
        /** @brief 已严格解析的最终状态码；仅在 HasFinalResponseHeaders() 后有效。 */
        [[nodiscard]] auto StatusCode() const noexcept -> int
        {
            return StatusCode_;
        }
        /** @brief 最终响应字段视图；仅在 HasFinalResponseHeaders() 后读取。 */
        [[nodiscard]] auto ResponseFields() const noexcept -> const ForwardResponseFields &
        {
            return ResponseFields_;
        }
        /** @brief 转移已解码正文所有权；返回值与本状态机解耦。 */
        [[nodiscard]] auto TakeDecodedBody() noexcept -> std::vector<std::uint8_t>
        {
            return std::move(DecodedBody_);
        }

    private:
        enum class State : std::uint8_t
        {
            Header,
            ContentLength,
            ChunkSize,
            ChunkData,
            ChunkDataCrlf,
            ChunkTrailer,
            CloseDelimited,
            Tunnel,
            Complete,
            Failed,
        };

        [[nodiscard]] auto ConsumeHeaderByte(std::byte Byte) -> Error;
        [[nodiscard]] auto ConsumeChunkSizeByte(std::byte Byte) -> Error;
        [[nodiscard]] auto ConsumeChunkDataCrlfByte(std::byte Byte) -> Error;
        [[nodiscard]] auto ConsumeTrailerByte(std::byte Byte) -> Error;
        [[nodiscard]] auto ProcessHeader() -> Error;
        [[nodiscard]] auto ProcessChunkSizeLine() -> Error;
        [[nodiscard]] auto ProcessTrailerLine() -> Error;
        [[nodiscard]] auto ParseChunkSizeLine(std::uint64_t &Size) const noexcept -> bool;
        [[nodiscard]] auto ParseChunkExtensions(std::string_view Extensions) const noexcept -> bool;
        [[nodiscard]] auto AppendDecodedBody(std::span<const std::byte> Bytes) -> Error
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

        [[nodiscard]] auto CaptureDecodedBody(std::span<const std::byte> Bytes,
                                              ForwardResponseConsumeResult &Result) -> bool
        {
            if (!CaptureBody_) return true;
            const auto ErrorCode = AppendDecodedBody(Bytes);
            if (ErrorCode == Error::None) return true;
            Result.ErrorCode = Fail(ErrorCode);
            return false;
        }

        [[nodiscard]] auto ConsumeFramingByte() noexcept -> Error
        {
            if (FramingBytes_ >= MaxFramingBytes_) return Fail(Error::BadLength);
            ++FramingBytes_;
            return Error::None;
        }
        [[nodiscard]] auto Fail(Error ErrorCode) noexcept -> Error;
        auto ResetHeader() -> void;

        ForwardResponseMethod RequestMethod_;
        bool AllowUpgrade_;
        bool CaptureBody_;
        std::size_t MaxHeaderBytes_;
        std::size_t MaxDecodedBodyBytes_;
        std::size_t MaxFramingBytes_;
        State State_{State::Header};
        std::size_t HeaderBytes_{0};
        std::uint64_t Remaining_{0};
        std::uint64_t ChunkRemaining_{0};
        std::uint8_t ChunkCrlfProgress_{0};
        std::size_t FramingBytes_{0};
        std::string Header_;
        std::string Line_;
        std::string Trailer_;
        int StatusCode_{0};
        bool FinalResponseHeadersReady_{false};
        ForwardResponseFields ResponseFields_{};
        std::vector<std::uint8_t> DecodedBody_;
        Error Failure_{Error::None};
    };

} // namespace Prism::Http11

#include <Prism/Foundation/Utility/Http/ForwardResponseFramingDetail.hpp>
