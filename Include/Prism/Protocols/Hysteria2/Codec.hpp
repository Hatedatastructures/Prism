/**
 * @file Codec.hpp
 * @brief Hysteria2 帧编解码（纯函数 + Serializer/Parser 类）
 * @details 帧格式（简化对齐 hysteria2 测试协议）：
 *          TCP：[Kind 1B][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          UDP：[Kind 1B][SessionID 4B LE][PacketID 4B LE][ATYP 1B][ADDR][PORT 2B BE][Payload]
 *          另含认证请求构造（MakeAuthRequest，HTTP/3 HEADERS 风格）
 *          与 Beast 风格 Serializer/Parser 类。
 * @note 参考 hysteria2 协议规范。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Common/Address.hpp>
#include <Prism/Protocols/Hysteria2/Types.hpp>

namespace Prism::Hysteria2
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
     * @brief 构造 TCP 帧
     */
    [[nodiscard]] auto BuildTcp(
        const Address &Destination,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>;

    /**
     * @brief UDP 帧构造输入（SessionId + PacketId + dst + payload）
     */
    struct UdpFrameInput
    {
        std::uint32_t SessionId{0};           ///< 会话 ID
        std::uint32_t PacketId{0};            ///< 包 ID
        const Address *dst{nullptr};           ///< 目标地址
        std::span<const std::uint8_t> payload; ///< 载荷
    };

    /**
     * @brief 构造 UDP 帧（写入复用缓冲）
     * @param Input 输入
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdp(
        const UdpFrameInput &Input,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (!Input.dst)
        {
            return;
        }
        Output.push_back(static_cast<std::uint8_t>(Message::Kind::Udp));
        Output.push_back(static_cast<std::uint8_t>(Input.SessionId & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.SessionId >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.SessionId >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.SessionId >> 24) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(Input.PacketId & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.PacketId >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.PacketId >> 16) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>((Input.PacketId >> 24) & 0xFF));
        if (!EncodeAddress(*Input.dst, Output))
        {
            Output.clear();
            return;
        }
        Output.insert(Output.end(), Input.payload.begin(), Input.payload.end());
    }

    /**
     * @brief 构造 UDP 帧
     */
    [[nodiscard]] auto BuildUdp(const UdpFrameInput &Input) -> std::vector<std::uint8_t>;

    /**
     * @brief 解析帧（增量）
     * @param Data 输入
     * @param Output 输出消息
     * @param Consumed 输出消耗字节数
     * @return 错误码
     */
    [[nodiscard]] auto Parse(
        std::span<const std::uint8_t> Data,
        Message &Output,
        std::size_t &Consumed) -> Error;

    // ==================== Auth（认证请求）合并 ====================

    /**
     * @brief 认证请求（HTTP/3 HEADERS 帧，首字节 0x01）
     * @param Password 认证密码
     * @return 认证请求字节；QPACK 或帧长度不足时返回空字符串
     */
    [[nodiscard]] auto MakeAuthRequest(std::string_view Password) -> std::string;
    // ==================== Session.hpp（Serializer/Parser）合并 ====================

    /**
     * @brief Hysteria2 帧序列化器（对象 → wire）
     */
    class Serializer
    {
    public:
        /**
         * @brief 重置并绑定消息
         * @param MessageValue 待序列化消息
         */
        auto Reset(const Message &MessageValue) -> void;

        /**
         * @brief 增量输出 wire 字节
         * @param Buffer 输出缓冲
         * @param Ec 输出错误码
         * @return 本次写入字节数
         */
        auto Get(
            boost::asio::mutable_buffer Buffer,
            std::error_code &Ec) -> std::size_t;

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

        /**
         * @brief 剩余未输出字节数
         * @return 剩余未输出字节数
         */
        [[nodiscard]] auto Remaining() const -> std::size_t
        {
            if (Offset_ >= Wire_.size())
            {
                return 0;
            }
            return Wire_.size() - Offset_;
        }

    private:
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief Hysteria2 帧解析器（wire → 对象）
     */
    class Parser
    {
    public:
        /**
         * @brief 增量喂入 wire 字节
         * @param Buffer 输入缓冲
         * @param Ec 输出错误码
         * @return 本次消耗字节数
         */
        auto Put(
            boost::asio::const_buffer Buffer,
            std::error_code &Ec) -> std::size_t;

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 解析结果（Done 后有效）
         * @return 消息引用（Done 后有效）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return Msg_;
        }

        /**
         * @brief 重置解析器
         */
        auto Reset() -> void;

    private:
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool Done_{false};
    };

} // namespace Prism::Hysteria2
