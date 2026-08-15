/**
 * @file codec_traits.hpp
 * @brief 帧编解码器 trait（frame_codec concept）
 * @details 定义跨协议帧编解码器的统一契约：
 *          - parse：增量解析字节流 → parse_result（错误码 + 消费字节数 + 事件）
 *          - build：由 frame_event 事件 → 编码字节流
 *          借鉴 tests/common/core/parser.hpp 的 concept 约束模式，
 *          热路径编解码零异常，失败通过 codec_error 枚举表达。
 *          所有协议实现（http2/http3/quic/自定义帧）只需满足
 *          frame_codec 概念即可接入统一的帧管线。
 * @note 本文件纯 header-only，仅声明契约，不包含任何具体编解码器。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace psmtest::codec
{

    /**
     * @enum codec_error
     * @brief 编解码错误码
     * @details 与 fault::code 解耦的轻量错误码，专用于帧
     * 编解码热路径，避免异常开销。
     */
    enum class codec_error : std::uint8_t
    {
        none = 0,     ///< 无错误
        need_more,    ///< 数据不足，需继续投喂（增量解析）
        malformed,    ///< 帧格式非法（长度/魔数/字段越界）
        unsupported,  ///< 不支持的帧类型 / 版本 / 特性
    };

    /**
     * @struct frame_event
     * @brief 帧事件（编解码器的领域对象）
     * @details parse 的输出事件与 build 的输入事件为同一类型，
     * 描述一条已解码的帧：所属流 + 帧类型 + 载荷视图。
     * @note payload 为视图语义，生命周期由调用方持有的输入缓冲保证；
     *       需要跨调用存活时须自行拷贝。
     */
    struct frame_event
    {
        std::int64_t stream_id{0};                  ///< 所属流 ID（无流语义的协议填 0）
        std::uint64_t type{0};                      ///< 帧类型（协议自定编码）
        std::span<const std::uint8_t> payload{};    ///< 帧载荷视图（不含帧头）
        bool fin{false};                            ///< 是否伴随流结束（END_STREAM 语义）
    };

    /**
     * @struct parse_result
     * @brief 帧解析结果
     * @details 三要素：错误码 + 消费字节数 + 解码事件。
     * - consumed：本次调用实际消费的输入字节数（need_more 时可能为 0）
     * - event：仅 error == none 时有效，为 optional 以表达
     *   "成功但无完整事件"（如仅消费了帧头）的中间状态
     */
    struct parse_result
    {
        codec_error error{codec_error::none};       ///< 解析错误码
        std::size_t consumed{0};                    ///< 已消费字节数
        std::optional<frame_event> event;           ///< 解码事件（error == none 时有效）

        /**
         * @brief 快速构造成功结果
         * @param ev 解码事件
         * @param n 消费字节数
         * @return 成功解析结果
         */
        [[nodiscard]] static auto ok(frame_event ev, std::size_t n) noexcept -> parse_result
        {
            return parse_result{codec_error::none, n, std::move(ev)};
        }

        /**
         * @brief 快速构造失败结果
         * @param ec 错误码
         * @param n 消费字节数（解析失败时通常为 0）
         * @return 失败解析结果
         */
        [[nodiscard]] static auto fail(codec_error ec, std::size_t n = 0) noexcept -> parse_result
        {
            return parse_result{ec, n, std::nullopt};
        }

        /**
         * @brief 是否成功且产出完整事件
         * @return 成功且含事件返回 true
         */
        [[nodiscard]] auto has_event() const noexcept -> bool
        {
            return error == codec_error::none && event.has_value();
        }
    };

    /// 编码输出字节容器（帧字节流）
    using bytes = std::vector<std::byte>;

    /**
     * @brief 帧编解码器 concept
     * @details 要求实现两个对称操作：
     * - parse(std::span<const uint8_t>) → parse_result：增量解析
     * - build(const frame_event&) → bytes：事件编码为帧字节流
     * 满足该概念的类型即可接入统一的帧管线（测试注入 / 生产替换）。
     * @tparam T 编解码器类型
     */
    template <typename T>
    concept frame_codec = requires(T &c, std::span<const std::uint8_t> input, const frame_event &event) {
        { c.parse(input) } -> std::same_as<parse_result>;
        { c.build(event) } -> std::convertible_to<bytes>;
    };

    /**
     * @brief 校验输入是否完整可解析（便捷辅助）
     * @param c 编解码器
     * @param input 输入字节流
     * @return error == none 返回 true
     * @details 供上层循环在投喂前快速判断，等价于
     * c.parse(input).error == codec_error::none。
     */
    template <frame_codec C>
    [[nodiscard]] inline auto can_parse(C &c, std::span<const std::uint8_t> input) -> bool
    {
        return c.parse(input).error == codec_error::none;
    }

} // namespace psmtest::codec
