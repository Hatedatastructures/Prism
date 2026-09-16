/**
 * @file Codec.hpp
 * @brief VLESS 请求头编解码（纯函数 + Serializer/Parser 类，零状态）
 * @details 请求头格式：
 *          [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]
 *          TCP/UDP 命令后接 [Port 2B BE][Atyp 1B][Addr var]；Mux 命令在 Cmd 后结束
 *          响应固定 2 字节：[Version 0x00][Addons Length 0x00]
 *          Serializer/Parser 类（Beast 风格）：对象 ↔ wire 字节。
 * @note 客户端必须发送 2 字节响应（1 字节会导致 mux 解析错位）。
 */

#pragma once

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
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

#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    namespace Net = boost::asio;

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE，追加到缓冲）
     * @param AddressValue 目标地址
     * @param Output 输出缓冲（追加到末尾；调用方持有复用，热路径零分配）
     * @note VLESS 对地址字段执行严格校验；非法输入不会生成可发送的部分帧。
     */
    template <typename Alloc>
    inline auto EncodeAddress(
        const Address &AddressValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        const auto Begin = Output.size();
        const auto Reject = [&Output, Begin]
        {
            Output.resize(Begin);
        };
        Output.push_back(static_cast<std::uint8_t>(AddressValue.Type));
        switch (AddressValue.Type)
        {
        case AddressType::Ipv4: {
            std::array<std::uint8_t, 4> Bytes{};
            if (!Preview::Protocol::Common::ParseIpv4Text(AddressValue.Host, Bytes))
            {
                Reject();
                return;
            }
            Output.insert(Output.end(), Bytes.begin(), Bytes.end());
            break;
        }
        case AddressType::Ipv6: {
            boost::system::error_code ErrorCode;
            const auto Parsed = Net::ip::make_address_v6(AddressValue.Host, ErrorCode);
            if (!ErrorCode)
            {
                const auto Bytes = Parsed.to_bytes();
                Output.insert(Output.end(), Bytes.begin(), Bytes.end());
            }
            else if (AddressValue.Host.size() == 16)
            {
                Output.insert(Output.end(), AddressValue.Host.begin(), AddressValue.Host.end());
            }
            else
            {
                Reject();
                return;
            }
            break;
        }
        case AddressType::Domain:
            if (AddressValue.Host.empty() || AddressValue.Host.size() > 0xFF)
            {
                Reject();
                return;
            }
            Output.push_back(static_cast<std::uint8_t>(AddressValue.Host.size()));
            Output.insert(Output.end(), AddressValue.Host.begin(), AddressValue.Host.end());
            break;
        default:
            Reject();
            return;
        }
        Output.push_back(static_cast<std::uint8_t>((AddressValue.Port >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(AddressValue.Port & 0xFF));
    }

    /**
     * @brief 编码地址为字节（ATYP + ADDR + PORT 2B BE）
     * @param AddressValue 目标地址
     * @return 字节序列
     */
    [[nodiscard]] inline auto EncodeAddress(const Address &AddressValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        EncodeAddress(AddressValue, Output);
        return Output;
    }

    /**
     * @brief 解析地址字节（ATYP + ADDR + PORT 2B BE，增量）
     * @param Data 输入数据
     * @param Output 输出地址
     * @param Offset 输入起始偏移，输出结束偏移
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseAddress(
        std::span<const std::uint8_t> Data,
        Address &Output,
        std::size_t &Offset) -> Error
    {
        if (Offset >= Data.size())
        {
            return Error::NeedMore;
        }
        Output.Type = static_cast<AddressType>(Data[Offset++]);
        switch (Output.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Offset < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Offset]),
                static_cast<unsigned int>(Data[Offset + 1]),
                static_cast<unsigned int>(Data[Offset + 2]),
                static_cast<unsigned int>(Data[Offset + 3]));
            Output.Host = Buffer.data();
            Offset += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Offset < 16)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), 16);
            Offset += 16;
            break;
        }
        case AddressType::Domain: {
            if (Offset >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Offset++];
            if (Data.size() - Offset < Length)
            {
                return Error::NeedMore;
            }
            Output.Host.assign(reinterpret_cast<const char *>(Data.data() + Offset), Length);
            Offset += Length;
            break;
        }
        default:
            return Error::BadMessage;
        }
        if (Data.size() - Offset < 2)
        {
            return Error::NeedMore;
        }
        Output.Port = static_cast<std::uint16_t>(Data[Offset]) << 8 | Data[Offset + 1];
        Offset += 2;
        return Error::None;
    }

    /**
     * @brief 构造 VLESS 请求头字节（写入复用缓冲）
     * @param RequestValue 请求头
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildRequest(
        const RequestHeader &RequestValue,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        if (RequestValue.Version != ProtocolVersion || RequestValue.Addons.size() > 0xFF ||
            (RequestValue.Cmd != Command::Tcp && RequestValue.Cmd != Command::Udp &&
             RequestValue.Cmd != Command::Mux))
        {
            return;
        }
        const auto IsMux = RequestValue.Cmd == Command::Mux;
        Output.reserve((IsMux ? 19U : 22U) + RequestValue.Addons.size() +
                       (IsMux ? 0U : RequestValue.Target.Host.size()));
        Output.push_back(RequestValue.Version);
        Output.insert(Output.end(), RequestValue.Uuid.begin(), RequestValue.Uuid.end());
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Addons.size()));
        Output.insert(Output.end(), RequestValue.Addons.begin(), RequestValue.Addons.end());
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Cmd));
        if (IsMux)
        {
            return;
        }
        Output.push_back(static_cast<std::uint8_t>((RequestValue.Target.Port >> 8) & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Target.Port & 0xFF));
        Output.push_back(static_cast<std::uint8_t>(RequestValue.Target.Type));
        switch (RequestValue.Target.Type)
        {
        case AddressType::Ipv4: {
            std::array<std::uint8_t, 4> Ipv4Bytes{};
            if (!Preview::Protocol::Common::ParseIpv4Text(RequestValue.Target.Host, Ipv4Bytes))
            {
                Output.clear();
                return;
            }
            Output.insert(Output.end(), Ipv4Bytes.begin(), Ipv4Bytes.end());
            break;
        }
        case AddressType::Ipv6: {
            // 文本形式（如 "::1"）解析为 16 字节二进制（线缆约定，对齐
            // Protocol/common::EncodeAddress）；解析失败时只接受完整的
            // 16 字节原始地址，避免把任意长度文本写入固定格式字段。
            boost::system::error_code ErrorCode;
            const auto Ipv6 = Net::ip::make_address_v6(RequestValue.Target.Host, ErrorCode);
            if (!ErrorCode)
            {
                const auto Bytes = Ipv6.to_bytes();
                Output.insert(Output.end(), Bytes.begin(), Bytes.end());
            }
            else if (RequestValue.Target.Host.size() == 16)
            {
                Output.insert(
                    Output.end(),
                    RequestValue.Target.Host.begin(),
                    RequestValue.Target.Host.end());
            }
            else
            {
                Output.clear();
                return;
            }
            break;
        }
        case AddressType::Domain: {
            if (RequestValue.Target.Host.empty() || RequestValue.Target.Host.size() > 0xFF)
            {
                Output.clear();
                return;
            }
            Output.push_back(static_cast<std::uint8_t>(RequestValue.Target.Host.size()));
            Output.insert(
                Output.end(),
                RequestValue.Target.Host.begin(),
                RequestValue.Target.Host.end());
            break;
        }
        default:
            Output.clear();
            return;
        }
    }

    /**
     * @brief 构造 VLESS 请求头字节
     * @param RequestValue 请求头
     * @return 字节序列
     * @details 通用头为 [Version 1B][UUID 16B][AddnlLen 1B][Addnl var][Cmd 1B]；
     *          TCP/UDP 命令再附加 [Port 2B BE][Atyp 1B][Addr var]，Mux 命令则结束于 Cmd。
     */
    [[nodiscard]] inline auto BuildRequest(const RequestHeader &RequestValue)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildRequest(RequestValue, Output);
        return Output;
    }

    /**
     * @brief 解析 VLESS 请求头（增量）
     * @param Data 输入数据
     * @param Output 输出请求头
     * @param Consumed 输出消耗字节数
     * @return 错误码；need_more = 数据不足
     */
    [[nodiscard]] inline auto ParseRequest(
        std::span<const std::uint8_t> Data,
        RequestHeader &Output,
        std::size_t &Consumed) -> Error
    {
        if (Data.size() < 18)
        {
            return Error::NeedMore;
        }
        Output.Version = Data[0];
        if (Output.Version != ProtocolVersion)
        {
            return Error::BadMagic;
        }
        std::memcpy(Output.Uuid.data(), Data.data() + 1, UuidLen);
        const auto AddnlLen = Data[17];
        const auto CommandOffset = 18U + static_cast<std::size_t>(AddnlLen);
        if (Data.size() <= CommandOffset)
        {
            return Error::NeedMore;
        }
        Output.Addons.assign(Data.begin() + 18, Data.begin() + 18 + AddnlLen);
        std::size_t Off = CommandOffset;
        Output.Cmd = static_cast<Command>(Data[Off++]);
        if (Output.Cmd != Command::Tcp && Output.Cmd != Command::Udp && Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }
        if (Output.Cmd == Command::Mux)
        {
            Output.Target.Type = AddressType::Domain;
            Output.Target.Host = "v1.mux.cool";
            Output.Target.Port = 0;
            Consumed = Off;
            return Error::None;
        }
        if (Data.size() - Off < 3U)
        {
            return Error::NeedMore;
        }
        Output.Target.Port = static_cast<std::uint16_t>(Data[Off]) << 8 | Data[Off + 1];
        Off += 2;
        Output.Target.Type = static_cast<AddressType>(Data[Off++]);
        switch (Output.Target.Type)
        {
        case AddressType::Ipv4: {
            if (Data.size() - Off < 4)
            {
                return Error::NeedMore;
            }
            std::array<char, 16> Buffer{};
            std::snprintf(
                Buffer.data(),
                Buffer.size(),
                "%u.%u.%u.%u",
                static_cast<unsigned int>(Data[Off]),
                static_cast<unsigned int>(Data[Off + 1]),
                static_cast<unsigned int>(Data[Off + 2]),
                static_cast<unsigned int>(Data[Off + 3]));
            Output.Target.Host = Buffer.data();
            Off += 4;
            break;
        }
        case AddressType::Ipv6: {
            if (Data.size() - Off < 16)
            {
                return Error::NeedMore;
            }
            Output.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), 16);
            Off += 16;
            break;
        }
        case AddressType::Domain: {
            if (Off >= Data.size())
            {
                return Error::NeedMore;
            }
            const auto Length = Data[Off++];
            if (Data.size() - Off < Length)
            {
                return Error::NeedMore;
            }
            Output.Target.Host.assign(reinterpret_cast<const char *>(Data.data() + Off), Length);
            Off += Length;
            break;
        }
        default:
            return Error::BadMessage;
        }
        if (Output.Target.Type == AddressType::Domain && Output.Target.Host.empty() &&
            Output.Cmd != Command::Mux)
        {
            return Error::BadMessage;
        }
        Consumed = Off;
        return Error::None;
    }

    /**
     * @brief 构造 VLESS UDP 帧（写入复用缓冲）
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @param Output 输出缓冲（调用方持有复用，热路径零分配）
     */
    template <typename Alloc>
    inline auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload,
        std::vector<std::uint8_t, Alloc> &Output) -> void
    {
        Output.clear();
        Output.reserve(1 + Target.Host.size() + 2 + Payload.size());
        const auto BeforeAddress = Output.size();
        EncodeAddress(Target, Output);
        if (Output.size() == BeforeAddress)
        {
            return;
        }
        Output.insert(Output.end(), Payload.begin(), Payload.end());
    }

    /**
     * @brief 构造 VLESS UDP 帧
     * @param Target 目标地址
     * @param Payload UDP 载荷
     * @return 帧字节：[ATYP 1B][ADDR var][PORT 2B BE][payload]
     * @details 帧内无长度字段、无 CRLF：地址头之后剩余全部字节即为
     * 载荷，边界由调用方（一次底层读）约定。
     * @note 地址类型为 VLESS 值体系（IPv4 0x01 / Domain 0x02 / IPv6 0x03）
     */
    [[nodiscard]] inline auto BuildUdpPkt(
        const Address &Target,
        std::span<const std::uint8_t> Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        BuildUdpPkt(Target, Payload, Output);
        return Output;
    }

    /**
     * @brief 解析 VLESS UDP 帧
     * @param Data 输入数据
     * @param Target 输出目标地址
     * @param Payload 输出载荷（视图指向 Data）
     * @return 错误码；need_more = 地址不完整
     * @details 地址解析后剩余全部字节即为载荷（帧无长度字段）。
     */
    [[nodiscard]] inline auto ParseUdpPkt(
        std::span<const std::uint8_t> Data,
        Address &Target,
        std::span<const std::uint8_t> &Payload) -> Error
    {
        std::size_t Offset = 0;
        const auto ErrorCode = ParseAddress(Data, Target, Offset);
        if (ErrorCode != Error::None)
        {
            return ErrorCode;
        }
        if (Target.Type == AddressType::Domain && Target.Host.empty())
        {
            return Error::BadMessage;
        }
        Payload = Data.subspan(Offset);
        return Error::None;
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
        /// 命令（CmdTcp / CmdUdp / cmd_mux）
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
         * @param Uuid 用户 UUID
         */
        explicit Serializer(const std::array<std::uint8_t, UuidLen> &Uuid) : Uuid_(Uuid)
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         * @details 按消息编为请求头 wire 字节，随后可通过 Get() 增量输出。
         */
        auto Reset(const Message &MessageValue) -> void
        {
            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Uuid = Uuid_;
            RequestValue.Cmd = static_cast<Command>(MessageValue.cmd);
            RequestValue.Target = MessageValue.dst;
            Wire_ = BuildRequest(RequestValue);
            Offset_ = 0;
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码输出参数
         * @return 写入字节数
         */
        auto Get(
            boost::asio::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
            Offset_ += N;
            return N;
        }

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Offset_ >= Wire_.size();
        }

    private:
        std::array<std::uint8_t, UuidLen> Uuid_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
    };

    /**
     * @brief VLESS 帧解析器（wire → 对象，Beast 风格）
     */
    class Parser
    {
    public:
        /**
         * @brief 构造
         * @param Uuid 期望的用户 UUID（校验用）
         */
        explicit Parser(
            const std::array<std::uint8_t, UuidLen> &Uuid,
            const bool ValidateUuid = true)
            : Uuid_(Uuid), ValidateUuid_(ValidateUuid)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入数据
         * @param ErrorCode 错误码输出参数
         * @return 本次消耗的字节数（0 = 半帧等待）
         */
        auto Put(
            boost::asio::const_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            if (Done_)
            {
                return 0;
            }
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            const auto PreviousBufferSize = Buf_.size();
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            std::size_t Consumed = 0;
            RequestHeader RequestValue;
            const auto ParseError = ParseRequest(Buf_, RequestValue, Consumed);
            if (ParseError == Error::NeedMore)
            {
                ErrorCode = make_error_code(Error::NeedMore);
                return 0;
            }
            if (ParseError != Error::None)
            {
                ErrorCode = make_error_code(ParseError);
                return 0;
            }
            // UUID 校验
            const std::string_view GotUuid(
                reinterpret_cast<const char *>(RequestValue.Uuid.data()),
                RequestValue.Uuid.size());
            const std::string_view ExpectedUuid(reinterpret_cast<const char *>(Uuid_.data()), Uuid_.size());
            if (ValidateUuid_ && !Preview::ConstantTimeEqual(GotUuid, ExpectedUuid))
            {
                ErrorCode = make_error_code(Error::AuthFailed);
                return 0;
            }
            Msg_.uuid = RequestValue.Uuid;
            Msg_.cmd = static_cast<std::uint8_t>(RequestValue.Cmd);
            Msg_.dst = RequestValue.Target;
            Msg_.valid = true;
            Done_ = true;
            return std::min(Consumed, Buf_.size()) - PreviousBufferSize;
        }

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
         * @details 清空内部缓冲与解析状态，可复用同一解析器。
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            Done_ = false;
        }

    private:
        std::array<std::uint8_t, UuidLen> Uuid_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        bool ValidateUuid_{true};
        bool Done_{false};
    };

} // namespace Preview::Vless
