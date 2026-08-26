/**
 * @file Codec.hpp
 * @brief 多路复用帧编解码策略（concept 约束，模板传参）
 * @details 借鉴 Boost.Beast 策略模式：会话逻辑只实现一次，
 *          smux / yamux / h2mux 各自提供满足 FrameCodec concept 的
 *          编解码策略，通过模板参数注入共享会话框架。
 * @note 全部纯函数，零状态零分配。
 * @note concept 约束帧构造（BuildOpen / BuildData / BuildFin /
 *          BuildRst）与帧事件判定（FrameEvent），其余（会话级控制
 *          帧识别等）由会话框架经 if constexpr 检测按需调用。
 */

#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Mux/Types.hpp>

namespace Preview::Mux
{

    /**
     * @struct FrameCodec
     * @brief 帧编解码策略 concept
     * @tparam C 策略类型
     * @details 要求策略提供帧类型、帧头长度/负载上限、帧解析与
     *          事件判定，以及四类帧构造（开流/数据/FIN 半关/RST 重置）。
     */
    template <typename C>
    concept FrameCodec = requires {
        typename C::FrameType;
        requires std::default_initializable<typename C::FrameType>;
        { C::HeaderLen } -> std::convertible_to<const std::size_t>;
        { C::MaxPayloadLen } -> std::convertible_to<const std::size_t>;
        {
            C::PayloadLen(std::declval<const typename C::FrameType &>())
        } -> std::convertible_to<std::size_t>;
        {
            C::ParseHeader(std::span<const std::uint8_t>{}, std::declval<typename C::FrameType &>())
        } -> std::same_as<Error>;
        {
            C::ParsePayload(std::declval<typename C::FrameType &>(), std::span<const std::uint8_t>{})
        } -> std::same_as<Error>;
        { C::FrameEvent(std::declval<const typename C::FrameType &>()) } -> std::same_as<StreamEvent>;
        { C::IsControl(std::declval<const typename C::FrameType &>()) } -> std::same_as<bool>;
        {
            C::FrameStreamId(std::declval<const typename C::FrameType &>())
        } -> std::convertible_to<std::uint32_t>;
        { C::BuildOpen(std::uint32_t{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
        {
            C::BuildData(std::uint32_t{}, std::span<const std::uint8_t>{})
        } -> std::convertible_to<std::vector<std::uint8_t>>;
        { C::BuildFin(std::uint32_t{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
        { C::BuildRst(std::uint32_t{}) } -> std::convertible_to<std::vector<std::uint8_t>>;
    };

} // namespace Preview::Mux
