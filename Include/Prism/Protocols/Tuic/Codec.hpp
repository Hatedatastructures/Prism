/**
 * @file Codec.hpp
 * @brief TUIC 帧编解码（纯函数，零状态 + Serializer/Parser 类）
 * @details 帧格式（TUIC v5）：
 *          Authenticate：[Ver 1B][Cmd 1B][UUID 16B][TOKEN 32B]
 *          Connect：[Ver 1B][Cmd 1B][ATYP][ADDR][PORT 2B BE]
 *          Packet：[Ver 1B][Cmd 1B][AssocID 2B BE][PktID 2B BE]
 *                  [FragTotal 1B][FragID 1B][Size 2B BE][ATYP][ADDR][PORT][Data]
 *          Dissociate：[Ver 1B][Cmd 1B][AssocID 2B BE]
 *          Heartbeat：[Ver 1B][Cmd 1B]
 * @note 提供 Serializer/Parser 类（Beast 风格）与纯函数。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Tuic/Types.hpp>

namespace Prism::Tuic
{

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param Addr 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （原内联实现 ipv4 无校验存在越界写，统一实现修复为非法输入输出 0.0.0.0）
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &Addr,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        return Prism::Protocol::Common::EncodeAddress(Addr, Output);
    }

    /**
     * @brief 编码地址（ATYP + ADDR + PORT 2B BE）
     */
    [[nodiscard]] auto EncodeAddress(const Address &Addr) -> std::vector<std::uint8_t>;

    /**
     * @brief 解析地址（增量）
     * @param Data 输入
     * @param Output 输出地址
     * @param Consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Consumed) -> Error;

    /**
     * @brief 构造消息帧（写入复用缓冲）
     * @param MessageValue 消息
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto Build(
        const Message &MessageValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(
            2 + 8 + 1 + MessageValue.dst.Host.size() + 2 + MessageValue.payload.size());
        Output.push_back(ProtocolVersion);
        Output.push_back(MessageValue.Cmd);
        if (MessageValue.Cmd == CmdAuthenticate)
        {
            Output.clear();
            return;
        }
        if (MessageValue.Cmd == CmdConnect)
        {
            if (!EncodeAddress(MessageValue.dst, Output))
            {
                Output.clear();
                return;
            }
        }
        else if (MessageValue.Cmd == CmdPacket)
        {
            if (MessageValue.FragTotal == 0 ||
                MessageValue.FragId >= MessageValue.FragTotal ||
                MessageValue.payload.size() > 0xFFFF)
            {
                Output.clear();
                return;
            }
            Output.push_back(static_cast<std::uint8_t>((MessageValue.AssocId >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.AssocId & 0xFF));
            Output.push_back(static_cast<std::uint8_t>((MessageValue.PktId >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.PktId & 0xFF));
            Output.push_back(MessageValue.FragTotal);
            Output.push_back(MessageValue.FragId);
            Output.push_back(static_cast<std::uint8_t>((MessageValue.payload.size() >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.payload.size() & 0xFF));
            if (MessageValue.FragId == 0)
            {
                if (!EncodeAddress(MessageValue.dst, Output))
                {
                    Output.clear();
                    return;
                }
            }
            else
            {
                Output.push_back(static_cast<std::uint8_t>(AddressType::None));
            }
            Output.insert(Output.end(), MessageValue.payload.begin(), MessageValue.payload.end());
        }
        else if (MessageValue.Cmd == CmdDissociate)
        {
            Output.push_back(static_cast<std::uint8_t>((MessageValue.AssocId >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(MessageValue.AssocId & 0xFF));
        }
        else if (MessageValue.Cmd != CmdHeartbeat)
        {
            Output.clear();
        }
    }

    /**
     * @brief 构造消息帧
     * @param MessageValue 消息
     * @return wire 字节
     */
    [[nodiscard]] auto Build(const Message &MessageValue) -> std::vector<std::uint8_t>;

    /**
     * @brief 解析消息帧（增量）
     * @param Data 输入
     * @param Output 输出消息
     * @param Consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] auto Parse(
        std::span<const std::uint8_t> Data,
        Message &Output,
        std::size_t &Consumed) -> Error;

    /**
     * @brief Tuic 帧序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         */
        auto Reset(const Message &MessageValue) -> void;

        /**
         * @brief 增量输出
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &Ec) -> std::size_t;

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

    private:
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief 构造 TUIC v5 独立 uni stream 认证帧
     */
    [[nodiscard]] auto BuildAuthenticate(
        const std::array<std::uint8_t, UuidLen> &Uuid,
        const std::array<std::uint8_t, TokenLen> &Token)
        -> std::array<std::uint8_t, AuthenticateFrameLen>;

    /**
     * @brief 解析 TUIC v5 独立 uni stream 认证帧
     */
    [[nodiscard]] auto ParseAuthenticate(
        std::span<const std::uint8_t> Data,
        AuthenticateFrame &Out,
        std::size_t &Consumed) -> Error;

    /**
     * @brief Tuic 帧解析器（wire → 对象，Beast 风格）
     */
    class Parser
    {
    public:
        /**
         * @brief 增量喂入
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &Ec) -> std::size_t;

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置
         */
        auto Reset() -> void;

    private:
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

} // namespace Prism::Tuic
