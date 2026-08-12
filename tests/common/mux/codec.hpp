/**
 * @file codec.hpp
 * @brief 多路复用帧编解码策略（concept 约束，模板传参）
 * @details 借鉴 Boost.Beast 策略模式：会话逻辑只实现一次，
 *          smux / yamux / h2mux 各自提供满足 frame_codec concept 的
 *          编解码策略，通过模板参数注入共享会话框架。
 * @note 全部纯函数，零状态零分配。
 * @note concept 约束帧构造（build_open / build_data / build_fin /
 *          build_rst）与帧事件判定（frame_event），其余（会话级控制
 *          帧识别等）由会话框架经 if constexpr 检测按需调用。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/mux/types.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace psmtest::mux
{

    /**
     * @struct frame_codec
     * @brief 帧编解码策略 concept
     * @tparam C 策略类型
     * @details 要求策略提供帧类型、帧头长度/负载上限、帧解析与
     *          事件判定，以及四类帧构造（开流/数据/FIN 半关/RST 重置）。
     */
    template <typename C>
    concept frame_codec = requires
    {
        typename C::frame_type;
        requires std::default_initializable<typename C::frame_type>;
        { C::header_len } -> std::convertible_to<const std::size_t>;
        { C::max_payload_len } -> std::convertible_to<const std::size_t>;
        { C::payload_len(std::declval<const typename C::frame_type &>()) } -> std::convertible_to<std::size_t>;
        { C::parse_header(std::span<const std::uint8_t>{}, std::declval<typename C::frame_type &>()) } -> std::same_as<error>;
        { C::parse_payload(std::declval<typename C::frame_type &>(), std::span<const std::uint8_t>{}) } -> std::same_as<error>;
        { C::frame_event(std::declval<const typename C::frame_type &>()) } -> std::same_as<stream_event>;
        { C::is_control(std::declval<const typename C::frame_type &>()) } -> std::same_as<bool>;
        { C::frame_stream_id(std::declval<const typename C::frame_type &>()) } -> std::convertible_to<std::uint32_t>;
        { C::build_open(std::uint32_t{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
        { C::build_data(std::uint32_t{}, std::span<const std::uint8_t>{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
        { C::build_fin(std::uint32_t{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
        { C::build_rst(std::uint32_t{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
    };

} // namespace psmtest::mux
