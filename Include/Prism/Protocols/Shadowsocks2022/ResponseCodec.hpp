/**
 * @file ResponseCodec.hpp
 * @brief Shadowsocks 2022 响应/数据报编解码
 * @details 负责无状态 UDP 数据报的 SeparateHeader、目标地址和
 *          AEAD 载荷组装/解析。会话密钥、分块数据面和请求握手分别
 *          位于 KeyDerivation.hpp、ChunkCodec.hpp、RequestWire.hpp 与
 *          RequestState.hpp。
 */

#pragma once

#include <openssl/rand.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>
#include <utility>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace Prism::Shadowsocks2022
{

    /// UDP 数据报填充类型（客户端/服务端）
    inline constexpr std::uint8_t UdpType = HeaderTypeClient;
    /// UDP 数据报 AEAD 使用 AES-128-GCM，密钥固定 16 字节
    inline constexpr std::size_t AeadKeyLen = 16;
    /// SeparateHeader 总长度
    inline constexpr std::size_t SeparateHdrLen = SessionIdLen + PacketIdLen;
    /// 时间戳长度
    inline constexpr std::size_t UdpTsLen = 8;
    /// 单个 UDP 数据报载荷上限
    inline constexpr std::size_t MaxUdpPayload = 65535;
    /// 最小 UDP 地址大小：域名类型、1 字节长度、1 字节域名和 2 字节端口。
    inline constexpr std::size_t MinUdpAddressSize = 1U + 1U + 1U + 2U;
    /// 最大 UDP 地址大小：域名类型、1 字节长度、255 字节域名和 2 字节端口。
    inline constexpr std::size_t MaxUdpAddressSize = 1U + 1U + 0xFFU + 2U;
    /// 单包 padding 长度字段可表示的最大填充。
    inline constexpr std::size_t MaxUdpPaddingSize =
        (std::numeric_limits<std::uint16_t>::max)();
    /// SIP022 原始 UDP packet 的完整长度上限，包含 server 字段与最大 padding。
    inline constexpr std::size_t MaxUdpPacketSize =
        SeparateHdrLen + AeadTagLen + 1U + UdpTsLen + SessionIdLen + 2U +
        MaxUdpPaddingSize + MaxUdpAddressSize + MaxUdpPayload;
    /// SIP022 最短合法 UDP packet 的完整长度下限。
    inline constexpr std::size_t MinUdpPacketSize =
        SeparateHdrLen + AeadTagLen + 1U + UdpTsLen + 2U + MinUdpAddressSize;

    namespace detail
    {

        /**
         * @brief UDP 数据报 AEAD 加密输入
         */
        struct UdpSealInput
        {
            std::span<const std::uint8_t> key;
            std::span<const std::uint8_t> Nonce;
            std::span<const std::uint8_t> plain;
            std::span<const std::uint8_t> aad;
        };

        /**
         * @brief UDP 数据报 AEAD 解密输入
         */
        struct UdpOpenInput
        {
            std::span<const std::uint8_t> key;
            std::span<const std::uint8_t> Nonce;
            std::span<const std::uint8_t> cipher;
            std::span<const std::uint8_t> aad;
        };

        /**
         * @brief 对 UDP SeparateHeader 执行无填充 AES-128-ECB
         * @param Key 预共享密钥
         * @param Input 16 字节明文或密文
         * @param Encrypt true = 加密，false = 解密
         * @return 转换后的 16 字节；参数或 OpenSSL 失败返回空值
         */
        [[nodiscard]] auto CryptSeparate(
            std::span<const std::uint8_t> Key,
            std::span<const std::uint8_t, SeparateHdrLen> Input,
            bool Encrypt)
            -> std::optional<std::array<std::uint8_t, SeparateHdrLen>>;

        /**
         * @brief UDP 数据报单次 AES-128-GCM 加密
         * @param Input 加密输入
         * @return 密文 + 16B tag；失败返回空
         */
        [[nodiscard]] auto UdpSeal(const UdpSealInput &Input)
            -> std::vector<std::uint8_t>;

        /**
         * @brief UDP 数据报单次 AES-128-GCM 解密
         * @param Input 解密输入
         * @return 明文；nullopt = 校验失败或参数非法，空 vector = 合法空载荷
         */
        [[nodiscard]] auto UdpOpen(const UdpOpenInput &Input)
            -> std::optional<std::vector<std::uint8_t>>;

    } // namespace detail

    /**
     * @brief UDP 数据报构造输入
     */
    struct UdpBuildInput
    {
        std::span<const std::uint8_t> SessionKey;
        std::uint64_t PacketId{0};
        const Address *Target{nullptr};
        std::span<const std::uint8_t> payload;
        std::span<const std::uint8_t> SessionId{};
        std::uint64_t Timestamp{0};
        std::span<const std::uint8_t> RemoteSessionId{};
        std::uint8_t HeaderType{HeaderTypeClient};
    };

    /**
     * @brief UDP 数据报解析输入
     */
    struct UdpParseInput
    {
        std::span<const std::uint8_t> SessionKey;
        std::span<const std::uint8_t> packet;
        Address *Target{nullptr};
        std::vector<std::uint8_t> *payload{nullptr};
        std::array<std::uint8_t, SessionIdLen> *SessionId{nullptr};
        std::uint64_t *PacketId{nullptr};
        std::uint64_t *Timestamp{nullptr};
        std::uint8_t *HeaderType{nullptr};
        std::array<std::uint8_t, SessionIdLen> *RemoteSessionId{nullptr};
        std::uint64_t Now{0}; ///< 校验时间基准（0 = 当前系统时间）
        std::uint64_t TimeWindow{30}; ///< 时间戳容忍窗口（秒）
    };

    /**
     * @brief 构造 UDP 数据报（写入复用缓冲）
     * @param Input 构造输入
     * @param Output 输出缓冲
     * @return false = 参数非法
     */
    template <typename Alloc>
    [[nodiscard]] inline auto BuildUdpPacket(
        const UdpBuildInput &Input,
        std::vector<std::uint8_t, Alloc> &Output) -> bool
    {
        Output.clear();
        if (!Input.Target || Input.SessionKey.size() != AeadKeyLen ||
            Input.payload.size() > MaxUdpPayload ||
            (Input.HeaderType != HeaderTypeClient && Input.HeaderType != HeaderTypeServer))
        {
            return false;
        }

        std::array<std::uint8_t, SessionIdLen> SessionId{};
        if (Input.SessionId.empty())
        {
            if (RAND_bytes(SessionId.data(), static_cast<int>(SessionId.size())) != 1)
            {
                return false;
            }
        }
        else if (Input.SessionId.size() != SessionIdLen)
        {
            return false;
        }
        else
        {
            std::memcpy(SessionId.data(), Input.SessionId.data(), SessionIdLen);
        }
        if (Input.HeaderType == HeaderTypeServer && Input.RemoteSessionId.size() != SessionIdLen)
        {
            return false;
        }

        std::array<std::uint8_t, SeparateHdrLen> SeparatePlain{};
        std::memcpy(SeparatePlain.data(), SessionId.data(), SessionIdLen);
        for (std::size_t I = 0; I < PacketIdLen; ++I)
        {
            SeparatePlain[SessionIdLen + I] =
                static_cast<std::uint8_t>((Input.PacketId >> (56 - I * 8)) & 0xFF);
        }
        const auto Separate = detail::CryptSeparate(
            Input.SessionKey,
            std::span<const std::uint8_t, SeparateHdrLen>(SeparatePlain),
            true);
        if (!Separate)
        {
            return false;
        }

        const auto Subkey = Prism::Shadowsocks2022::SessionKey(
            Input.SessionKey,
            std::span<const std::uint8_t>(SessionId),
            AeadKeyLen);
        std::vector<std::uint8_t> Plain;
        Plain.reserve(1 + UdpTsLen + 32 + 2 + Input.payload.size());
        Plain.push_back(Input.HeaderType);
        std::uint64_t Timestamp;
        if (Input.Timestamp != 0)
        {
            Timestamp = Input.Timestamp;
        }
        else
        {
            Timestamp = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
        }
        for (std::size_t I = 0; I < UdpTsLen; ++I)
        {
            Plain.push_back(static_cast<std::uint8_t>((Timestamp >> (56 - I * 8)) & 0xFF));
        }
        // SIP022 / sing-shadowsocks 权威顺序：
        //   Client 帧：[type][epoch][paddingLen 2B][padding][addrport][payload]
        //   Server 帧：[type][epoch][remoteSessionId 8B][paddingLen 2B][padding]
        //              [addrport][payload]
        if (Input.HeaderType == HeaderTypeServer)
        {
            Plain.insert(Plain.end(), Input.RemoteSessionId.begin(), Input.RemoteSessionId.end());
        }
        Plain.push_back(0);
        Plain.push_back(0);
        if (!EncodeAddress(*Input.Target, Plain))
        {
            return false;
        }
        Plain.insert(Plain.end(), Input.payload.begin(), Input.payload.end());

        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), SeparatePlain.data() + SessionIdLen / 2, SessionIdLen / 2);
        std::memcpy(Nonce.data() + SessionIdLen / 2,
                    SeparatePlain.data() + SessionIdLen, PacketIdLen);

        const auto BodyEnc = detail::UdpSeal(detail::UdpSealInput{Subkey, Nonce, Plain, {}});
        if (BodyEnc.empty())
        {
            return false;
        }
        Output.reserve(Separate->size() + BodyEnc.size());
        Output.insert(Output.end(), Separate->begin(), Separate->end());
        Output.insert(Output.end(), BodyEnc.begin(), BodyEnc.end());
        return true;
    }

    /**
     * @brief 构造 UDP 数据报（逐包 AEAD 无状态加密）
     * @param Input 构造输入
     * @return 完整数据报字节；参数非法返回空
     */
    [[nodiscard]] auto BuildUdpPacket(const UdpBuildInput &Input)
        -> std::vector<std::uint8_t>;

    namespace detail
    {

        struct UdpParseState final
        {
            std::array<std::uint8_t, SessionIdLen> SessionId{};
            std::array<std::uint8_t, 12> Nonce{};
            std::vector<std::uint8_t> Body;
            std::uint64_t PacketId{0}, Timestamp{0};
            std::size_t Offset{0};
            std::uint8_t Type{0};
        };

        [[nodiscard]] auto DecodeSeparateHeader(std::span<const std::uint8_t> SessionKey,
                                                       std::span<const std::uint8_t> Packet,
                                                       UdpParseState &State) -> Error;

        [[nodiscard]] auto OpenUdpBody(std::span<const std::uint8_t> SessionKey,
                                              std::span<const std::uint8_t> Packet,
                                              UdpParseState &State) -> Error;

        [[nodiscard]] auto ValidateUdpBody(const UdpParseInput &Input,
                                                  UdpParseState &State) -> Error;

        [[nodiscard]] auto ParseUdpAddressPayload(const UdpParseInput &Input,
                                                         UdpParseState &State) -> Error;

    } // namespace detail

    /** @brief 解析 UDP 数据报（逐包 AEAD 无状态解密）。 */
    [[nodiscard]] auto ParseUdpPacket(const UdpParseInput &Input) -> Error;

} // namespace Prism::Shadowsocks2022
