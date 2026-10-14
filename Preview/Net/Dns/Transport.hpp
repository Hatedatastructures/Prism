/**
 * @file Transport.hpp
 * @brief DNS 上游传输层契约：收发概念、可池化概念与共享字节上限
 * @details 传输实现按连接 owner 拆分：
 *          - Detail/UdpTransport.hpp：数据报单发单收（不入池）
 *          - Detail/TcpTransport.hpp：2 字节长度前缀帧（可入池复用）
 *          - Detail/TlsTransport.hpp：DoT（TLS 承载帧，可入池复用）
 *          每次操作消费调用者传入的绝对 AttemptDeadline：解析、建连、收发
 *          与 DoH 分块读写共享同一预算，不逐段重置；socket/stream 与
 *          deadline 定时器由各传输的共享状态拥有，handler 不借用裸 this。
 * @note DoH（HTTP 承载）见 Doh.hpp；连接池见 ConnPool.hpp；
 *       deadline 机制见 Detail/Deadline.hpp
 */

#pragma once

#include "Config.hpp"
#include "Detail/Deadline.hpp"
#include "Format.hpp"

#include <boost/asio.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;

    /// 以 error_code 表达成败的结果类型（传输层不抛异常）
    template <typename T>
    using EcResult = std::expected<T, boost::system::error_code>;

    /**
     * @concept TransportLink
     * @brief 一次 DNS 字节帧的收发单元
     * @details Send 写入一段 DNS 报文字节（帧封装由实现内部完成），
     *          Receive 返回剥离封装后的应答字节，Close 释放底层套接字；
     *          接口只借用 wire/应答缓冲到本次操作完成，不保存引用。
     */
    template <typename T>
    concept TransportLink = requires(T LinkObject, std::span<const std::uint8_t> Wire,
                                     Detail::AttemptDeadline Deadline) {
        LinkObject.Send(Wire, Deadline);
        LinkObject.Receive(Deadline);
        LinkObject.Close();
        LinkObject.IsOpen();
    };

    /**
     * @concept PoolableTransport
     * @brief 可入池的传输：在收发之上追加建连能力
     * @details Connect 建立底层连接（endpoint 由上层解析缓存提供），
     *          上层据此判定能否复用
     */
    template <typename T>
    concept PoolableTransport =
        TransportLink<T> && requires(T LinkObject, const Net::ip::tcp::endpoint &Endpoint,
                                     const Server &ServerConfig, Detail::AttemptDeadline Deadline) {
            LinkObject.Connect(Endpoint, ServerConfig, Deadline);
        };

    namespace Detail
    {
        /// 帧体长度上限（DNS over TCP 单帧 65535 字节上限）
        constexpr std::size_t MaxFrameBytes = 65535;

        /// UDP 单次应答接收上限（EDNS0 1232 字节预算下的常见上限）
        constexpr std::size_t MaxUdpResponseBytes = 4096;

        /// TCP/DoT 共享的 2 字节大端长度前缀封装
        [[nodiscard]] inline auto MakeTcpFrame(std::span<const std::uint8_t> Wire)
            -> EcResult<std::vector<std::uint8_t>>
        {
            if (Wire.size() > MaxFrameBytes)
            {
                return std::unexpected(
                    boost::system::errc::make_error_code(boost::system::errc::message_size));
            }
            std::vector<std::uint8_t> Frame;
            Frame.reserve(Wire.size() + 2);
            Frame.push_back(static_cast<std::uint8_t>(Wire.size() >> 8));
            Frame.push_back(static_cast<std::uint8_t>(Wire.size() & 0xFF));
            Frame.insert(Frame.end(), Wire.begin(), Wire.end());
            return Frame;
        }

    } // namespace Detail

} // namespace Preview::Network::Dns
