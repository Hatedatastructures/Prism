/**
 * @file Codec.hpp
 * @brief VLESS 请求头编解码（纯函数 + Serializer/Parser 类，零状态）
 * @details 请求头格式：
 *          [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]
 *          [Port 2B BE][Atyp 1B][Addr var]
 *          响应固定 2 字节：[Version 0x00][Addons Length 0x00]
 *          Serializer/Parser 类（Beast 风格）：对象 ↔ wire 字节。
 * @note 客户端必须发送 2 字节响应（1 字节会导致 mux 解析错位）。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Core/Protocol/Address.hpp>
#include <common/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param addr 目标地址
     * @param out 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note 转发层：统一实现见 Protocol/common::EncodeAddress
     *       （原内联实现 ipv4 无校验存在越界写，统一实现修复为非法输入输出 0.0.0.0）
     */
    template <typename Alloc>
    [[nodiscard]] inline auto EncodeAddress(const Address &addr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        Preview::Protocol::Common::EncodeAddress(addr, out);
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @return 字节序列
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &addr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        EncodeAddress(addr, out);
        return out;
    }

    /**
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE，增量）
     * @param Data 输入数据
     * @param out 输出地址
     * @param off 输入起始偏移，输出结束偏移
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseAddress(std::span<const std::uint8_t> Data, Address &out,
                                            std::size_t &off) -> Error
    {
        if (off >= Data.size())
        {
            return Error::need_more;
        }
        out.Type = static_cast<AddressType>(Data[off++]);
        switch (out.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < off + 4)
            {
                return Error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[off], Data[off + 1], Data[off + 2],
                          Data[off + 3]);
            out.Host = buf.data();
            off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < off + 16)
            {
                return Error::need_more;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + off), 16);
            off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (off >= Data.size())
            {
                return Error::need_more;
            }
            const auto len = Data[off++];
            if (Data.size() < off + len)
            {
                return Error::need_more;
            }
            out.Host.assign(reinterpret_cast<const char *>(Data.data() + off), len);
            off += len;
            break;
        }
        }
        if (Data.size() < off + 2)
        {
            return Error::need_more;
        }
        out.Port = static_cast<std::uint16_t>(Data[off]) << 8 | Data[off + 1];
        off += 2;
        return Error::none;
    }

    /**
     * @brief 构造 VLESS 请求头字节（写入复用缓冲）
     * @param hdr 请求头
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildRequest(const RequestHeader &hdr, std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(22 + hdr.Addons.size() + hdr.Target.Host.size());
        out.push_back(hdr.Version);
        out.insert(out.end(), hdr.Uuid.begin(), hdr.Uuid.end());
        out.push_back(static_cast<std::uint8_t>(hdr.Addons.size()));
        out.insert(out.end(), hdr.Addons.begin(), hdr.Addons.end());
        out.push_back(static_cast<std::uint8_t>(hdr.Cmd));
        out.push_back(static_cast<std::uint8_t>((hdr.Target.Port >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.Target.Port & 0xFF));
        out.push_back(static_cast<std::uint8_t>(hdr.Target.Type));
        switch (hdr.Target.Type)
        {
        case AddressType::Ipv4: {
            std::array<std::uint8_t, 4> ip{};
            static_cast<void>(Preview::Protocol::Common::ParseIpv4Text(hdr.Target.Host, ip));
            out.insert(out.end(), ip.begin(), ip.end());
            break;
        }
        case AddressType::Ipv6: {
            out.insert(out.end(), hdr.Target.Host.begin(), hdr.Target.Host.end());
            break;
        }
        case AddressType::Domain:
        default: {
            if (hdr.Target.Host.size() > 0xFF)
            {
                // 超长域名无法用单字节长度表达：编码为空域名（接收方解析失败），
                // 禁止静默回绕——回绕会把后续载荷当长度字节，整帧错位静默损坏
                out.push_back(0x00);
                break;
            }
            out.push_back(static_cast<std::uint8_t>(hdr.Target.Host.size()));
            out.insert(out.end(), hdr.Target.Host.begin(), hdr.Target.Host.end());
            break;
        }
        }
    }

    /**
     * @brief 构造 VLESS 请求头字节
     * @param hdr 请求头
     * @return 字节序列
     * @details 格式 [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]
     * [Port 2B BE][Atyp 1B][Addr var]（Port 在 ATYP 之前，与 UDP 帧相反）。
     */
    [[nodiscard]] inline auto BuildRequest(const RequestHeader &hdr) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildRequest(hdr, out);
        return out;
    }

    /**
     * @brief 解析 VLESS 请求头（增量）
     * @param Data 输入数据
     * @param out 输出请求头
     * @param consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseRequest(std::span<const std::uint8_t> Data, RequestHeader &out,
                                            std::size_t &consumed) -> Error
    {
        if (Data.size() < 22) // 1 + 16 + 1 + 1 + 2 + 1
        {
            return Error::need_more;
        }
        out.Version = Data[0];
        if (out.Version != ProtocolVersion)
        {
            return Error::bad_magic;
        }
        std::memcpy(out.Uuid.data(), Data.data() + 1, UuidLen);
        const auto AddnlLen = Data[17];
        if (Data.size() < 18 + AddnlLen + 1 + 2 + 1)
        {
            return Error::need_more;
        }
        out.Addons.assign(Data.begin() + 18, Data.begin() + 18 + AddnlLen);
        std::size_t off = 18 + AddnlLen;
        out.Cmd = static_cast<Command>(Data[off++]);
        out.Target.Port = static_cast<std::uint16_t>(Data[off]) << 8 | Data[off + 1];
        off += 2;
        out.Target.Type = static_cast<AddressType>(Data[off++]);
        switch (out.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() < off + 4)
            {
                return Error::need_more;
            }
            std::array<char, 16> buf{};
            std::snprintf(buf.data(), buf.size(), "%u.%u.%u.%u", Data[off], Data[off + 1], Data[off + 2],
                          Data[off + 3]);
            out.Target.Host = buf.data();
            off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() < off + 16)
            {
                return Error::need_more;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + off), 16);
            off += 16;
            break;
        }
        case AddressType::Domain:
        default: {
            if (off >= Data.size())
            {
                return Error::need_more;
            }
            const auto len = Data[off++];
            if (Data.size() < off + len)
            {
                return Error::need_more;
            }
            out.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + off), len);
            off += len;
            break;
        }
        }
        consumed = off;
        return Error::none;
    }

    /**
     * @brief 构造 VLESS UDP 帧（写入复用缓冲）
     * @param Target 目标地址
     * @param payload UDP 载荷
     * @param out 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdpPkt(const Address &Target, std::span<const std::uint8_t> payload,
                              std::vector<std::uint8_t, Alloc> &out) -> void
    {
        out.clear();
        out.reserve(1 + Target.Host.size() + 2 + payload.size());
        EncodeAddress(Target, out);
        out.insert(out.end(), payload.begin(), payload.end());
    }

    /**
     * @brief 构造 VLESS UDP 帧
     * @param Target 目标地址
     * @param payload UDP 载荷
     * @return 帧字节：[ATYP 1B][ADDR var][PORT 2B BE][payload]
     * @details 帧内无长度字段、无 CRLF：地址头之后剩余全部字节即为
     * 载荷，边界由调用方（一次底层读）约定。
     * @note 地址类型为 VLESS 值体系（IPv4 0x01 / Domain 0x02 / IPv6 0x03）
     */
    [[nodiscard]] inline auto BuildUdpPkt(const Address &Target, std::span<const std::uint8_t> payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> out;
        BuildUdpPkt(Target, payload, out);
        return out;
    }

    /**
     * @brief 解析 VLESS UDP 帧
     * @param Data 输入数据
     * @param Target 输出目标地址
     * @param payload 输出载荷（视图指向 Data）
     * @return 错误码；need_more = 地址不完整
     * @details 地址解析后剩余全部字节即为载荷（帧无长度字段）。
     */
    [[nodiscard]] inline auto ParseUdpPkt(std::span<const std::uint8_t> Data, Address &Target,
                                            std::span<const std::uint8_t> &payload) -> Error
    {
        std::size_t off = 0;
        auto err = ParseAddress(Data, Target, off);
        if (err != Error::none)
        {
            return err;
        }
        payload = Data.subspan(off);
        return Error::none;
    }

    /**
     * @brief 构造响应字节（固定 2 字节）
     * @return [Version 0x00][Addons Length 0x00]
     */
    [[nodiscard]] inline constexpr auto MakeResponse() -> std::array<std::uint8_t, 2>
    {
        return {ProtocolVersion, 0x00};
    }

    /**
     * @brief VLESS 帧消息（Beast 风格，供 Serializer/Parser 使用）
     */
    struct Message
    {
        /// 用户 UUID（16 字节）
        std::array<std::uint8_t, UuidLen> uuid{};
        /// 命令（CmdTcp / cmd_udp / cmd_mux）
        std::uint8_t cmd{CmdTcp};
        /// 目标地址
        Address dst;
        /// 解析有效
        bool valid{false};
    };

    /**
     * @brief VLESS 帧序列化器（对象 → wire，Beast 风格）
     */
    class Serializer
    {
    public:
        /**
         * @brief 构造
         * @param uuid 用户 UUID
         */
        explicit Serializer(const std::array<std::uint8_t, UuidLen> &uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param msg 消息
         * @details 按消息编为请求头 wire 字节，随后可通过 Get() 增量输出。
         */
        auto Reset(const Message &msg) -> void
        {
            RequestHeader hdr;
            hdr.Version = ProtocolVersion;
            hdr.Uuid = uuid_;
            hdr.Cmd = static_cast<Command>(msg.cmd);
            hdr.Target = msg.dst;
            wire_ = BuildRequest(hdr);
            offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ec 错误码输出参数
         * @return 写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto n = std::min(Buffer.size(), wire_.size() - offset_);
            std::memcpy(Buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return offset_ >= wire_.size();
        }

    private:
        std::array<std::uint8_t, UuidLen> uuid_;
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /**
     * @brief VLESS 帧解析器（wire → 对象，Beast 风格）
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param uuid 期望的用户 UUID（校验用）
         */
        explicit Parser(const std::array<std::uint8_t, UuidLen> &uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入数据
         * @param ec 错误码输出参数
         * @return 本次消耗的字节数（0 = 半帧等待）
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            buf_.insert(buf_.end(), Data.begin(), Data.end());
            std::size_t consumed = 0;
            RequestHeader req;
            const auto err = ParseRequest(buf_, req, consumed);
            if (err == Error::need_more)
            {
                ec = make_error_code(Error::need_more);
                return 0;
            }
            if (err != Error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            // UUID 校验
            if (req.Uuid != uuid_)
            {
                ec = make_error_code(Error::auth_failed);
                return 0;
            }
            msg_.uuid = req.Uuid;
            msg_.cmd = static_cast<std::uint8_t>(req.Cmd);
            msg_.dst = req.Target;
            msg_.valid = true;
            done_ = true;
            return consumed;
        }

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用（解析完成后调用）
         */
        [[nodiscard]] auto Get() const -> const Message &
        {
            return msg_;
        }

        /**
         * @brief 重置
         * @details 清空内部缓冲与解析状态，可复用同一解析器。
         */
        auto Reset() -> void
        {
            buf_.clear();
            msg_ = Message{};
            done_ = false;
        }

    private:
        std::array<std::uint8_t, UuidLen> uuid_;
        std::vector<std::uint8_t> buf_;
        Message msg_{};
        bool done_{false};
    };

} // namespace Preview::Vless
