/**
 * @file CodecTraits.hpp
 * @brief 帧编解码器 trait（FrameCodec concept）
 * @details 定义跨协议帧编解码器的统一契约：
 *          - Parse：增量解析字节流 → ParseResult（错误码 + 消费字节数 + 事件）
 *          - Build：由 FrameEvent 事件 → 编码字节流
 *          借鉴 tests/common/Core/Parser.hpp 的 concept 约束模式，
 *          热路径编解码零异常，失败通过 CodecError 枚举表达。
 *          所有协议实现（http2/http3/quic/自定义帧）只需满足
 *          FrameCodec 概念即可接入统一的帧管线。
 * @note 本文件纯 Header-only，仅声明契约，不包含任何具体编解码器。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace Preview::Codec
{

    /**
     * @enum CodecError
     * @brief 编解码错误码
     * @details 与 Fault::Code 解耦的轻量错误码，专用于帧
     * 编解码热路径，避免异常开销。
     */
    enum class CodecError : std::uint8_t
    {
        None = 0,     ///< 无错误
        NeedMore,    ///< 数据不足，需继续投喂（增量解析）
        Malformed,    ///< 帧格式非法（长度/魔数/字段越界）
        Unsupported,  ///< 不支持的帧类型 / 版本 / 特性
    };

    /**
     * @struct FrameEvent
     * @brief 帧事件（编解码器的领域对象）
     * @details Parse 的输出事件与 Build 的输入事件为同一类型，
     * 描述一条已解码的帧：所属流 + 帧类型 + 载荷视图。
     * @note payload 为视图语义，生命周期由调用方持有的输入缓冲保证；
     *       需要跨调用存活时须自行拷贝。
     */
    struct FrameEvent
    {
        std::int64_t StreamId{0};                  ///< 所属流 ID（无流语义的协议填 0）
        std::uint64_t Type{0};                      ///< 帧类型（协议自定编码）
        std::span<const std::uint8_t> payload{};    ///< 帧载荷视图（不含帧头）
        bool fin{false};                            ///< 是否伴随流结束（END_STREAM 语义）
    };

    /**
     * @struct ParseResult
     * @brief 帧解析结果
     * @details 三要素：错误码 + 消费字节数 + 解码事件。
     * - consumed：本次调用实际消费的输入字节数（need_more 时可能为 0）
     * - event：仅 Error == none 时有效，为 optional 以表达
     *   "成功但无完整事件"（如仅消费了帧头）的中间状态
     */
    struct ParseResult
    {
        CodecError Error{CodecError::None};       ///< 解析错误码
        std::size_t consumed{0};                    ///< 已消费字节数
        std::optional<FrameEvent> event;           ///< 解码事件（Error == none 时有效）

        /**
         * @brief 快速构造成功结果
         * @param ev 解码事件
         * @param n 消费字节数
         * @return 成功解析结果
         */
        [[nodiscard]] static auto Ok(FrameEvent ev, std::size_t N) noexcept -> ParseResult
        {
            return ParseResult{CodecError::None, N, std::move(ev)};
        }

        /**
         * @brief 快速构造失败结果
         * @param ec 错误码
         * @param n 消费字节数（解析失败时通常为 0）
         * @return 失败解析结果
         */
        [[nodiscard]] static auto Fail(CodecError ec, std::size_t N = 0) noexcept -> ParseResult
        {
            return ParseResult{ec, N, std::nullopt};
        }

        /**
         * @brief 是否成功且产出完整事件
         * @return 成功且含事件返回 true
         */
        [[nodiscard]] auto HasEvent() const noexcept -> bool
        {
            return Error == CodecError::None && event.has_value();
        }
    };

    /// 编码输出字节容器（帧字节流）
    using Bytes = std::vector<std::byte>;

    /**
     * @brief 帧编解码器 concept
     * @details 要求实现两个对称操作：
     * - Parse(std::span<const uint8_t>) → ParseResult：增量解析
     * - Build(const FrameEvent&) → Bytes：事件编码为帧字节流
     * 满足该概念的类型即可接入统一的帧管线（测试注入 / 生产替换）。
     * @tparam T 编解码器类型
     */
    template <typename T>
    concept FrameCodec = requires(T &c, std::span<const std::uint8_t> input, const FrameEvent &event) {
        { c.Parse(input) } -> std::same_as<ParseResult>;
        { c.Build(event) } -> std::convertible_to<Bytes>;
    };

    /**
     * @brief 校验输入是否完整可解析（便捷辅助）
     * @param c 编解码器
     * @param input 输入字节流
     * @return Error == none 返回 true
     * @details 供上层循环在投喂前快速判断，等价于
     * c.Parse(input).Error == CodecError::None。
     */
    template <FrameCodec C>
    [[nodiscard]] inline auto CanParse(C &c, std::span<const std::uint8_t> input) -> bool
    {
        return c.Parse(input).Error == CodecError::None;
    }

} // namespace Preview::Codec
