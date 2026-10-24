/**
 * @file Io.hpp
 * @brief Hysteria2 连接的精确读写辅助。
 * @details 该 owner 只负责 Transmission 的完整字节读写和地址体消费；
 *          Conn 保留握手、帧状态、账户租约与关闭职责。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Hysteria2::Detail
{

    namespace Net = boost::asio;

    /**
     * @brief 将底层读取终态映射为协议错误。
     * @param Failure 原始传输终态；调用方仍保留 Native 信息。
     * @return Hysteria2 读取接口公开的错误分类。
     */
    [[nodiscard]] auto ReadFailureToError(
        const Prism::Fault::Failure &Failure) noexcept -> Prism::Error;

    /** @brief 映射可选读取终态；缺少 typed failure 时保留调用方原有错误。 */
    [[nodiscard]] auto ReadFailureToError(
        const std::optional<Prism::Fault::Failure> &Failure,
        const Prism::Error Fallback) noexcept -> Prism::Error;

    /**
     * @brief 精确读取一个字段，并保留同次读取附带的终态。
     * @param Transport 借用底层传输。
     * @param Destination 当前字段缓冲区，借用至协程完成。
     * @param PendingTerminal Conn 持有的 sticky 终态状态。
     * @return true 表示字段不完整或已有终态；完整字段先返回成功。
     */
    [[nodiscard]] auto ReadExact(
        const Prism::SharedTransmission &Transport,
        std::span<std::uint8_t> Destination,
        std::optional<Prism::Fault::Failure> &PendingTerminal)
        -> Net::awaitable<bool>;

    [[nodiscard]] auto SendBytes(
        const Prism::SharedTransmission &Transport,
        std::span<const std::uint8_t> Data) -> Net::awaitable<bool>;

    [[nodiscard]] auto ReadAddressBody(
        const Prism::SharedTransmission &Transport,
        Prism::Hysteria2::Address &AddressValue,
        std::optional<Prism::Fault::Failure> &PendingTerminal)
        -> Net::awaitable<Prism::Error>;

    /**
     * @brief 读取一个完整 Hysteria2 帧。
     * @param Transport 借用底层传输；所有权由调用方保留，借用期限到本次 completion。
     * @param MessageValue 输出帧；完整载荷与底层终态同次到达时仍保留载荷。
     * @param PendingTerminal Conn 持有的 sticky 终态状态。
     * @return 协议错误；完整字段后终态留给下次读取，超出接收窗口返回 BadLength。
     * @note 帧无长度字段：精确分段读取头部（Kind/Id/地址），剩余一次读为载荷。
     *       本函数不执行关闭、取消或半关闭。
     */
    [[nodiscard]] auto ReadFrame(
        const Prism::SharedTransmission &Transport,
        Prism::Hysteria2::Message &MessageValue,
        std::optional<Prism::Fault::Failure> &PendingTerminal)
        -> Net::awaitable<Prism::Error>;

} // namespace Prism::Hysteria2::Detail
