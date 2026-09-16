/**
 * @file Reality.hpp
 * @brief Reality 协议入口（聚合头 + 工厂函数）
 * @details 协议族统一入口：
 * - 工厂函数（本文件）：Connect / Accept ——认证握手在工厂内部完成
 * - 配置：ClientConfig / ServerConfig（本文件，字段分开定义）
 * - 连接：Conn（流，Conn.hpp，X25519 + HKDF + AEAD 认证）
 * - 编解码/密钥：Codec.hpp（X25519 + AuthKey 派生 + SessionId Seal/Open）
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Reality/Codec.hpp>
#include <Preview/Protocols/Reality/Conn.hpp>
#include <Preview/Protocols/Reality/Carrier.hpp>
#include <Preview/Protocols/Reality/Types.hpp>

namespace Preview::Reality
{

    // =========================================================================
    // 配置（客户端与服务端字段分开定义）
    // =========================================================================

    /**
     * @struct ClientConfig
     * @brief Reality 客户端配置
     * @details 控制客户端的行为：X25519 密钥与短 ID。构造后只读。
     */
    struct ClientConfig
    {
        /// 客户端 X25519 私钥（32 字节，字段名称保持配置兼容）
        std::array<std::uint8_t, KeyLen> private_key{};
        /// 短 ID（8 字节，内嵌 SessionId）
        std::array<std::uint8_t, MaxShortIdLen> ShortId{};
    };

    /**
     * @struct ServerConfig
     * @brief Reality 服务端配置
     * @details 控制服务端的行为：X25519 私钥与短 ID 校验。构造后只读。
     */
    struct ServerConfig
    {
        /// 服务端 X25519 私钥（32 字节，字段名称保持配置兼容）
        std::array<std::uint8_t, KeyLen> private_key{};
        /// 服务端允许的短 ID（空列表拒绝所有连接）
        std::vector<std::array<std::uint8_t, MaxShortIdLen>> ShortIds;
    };

    /**
     * @struct ConnectParameters
     * @brief Reality 客户端连接装配参数
     * @details Upstream 的所有权转移；其余字段在函数调用期间借用并立即复制。
     */
    struct ConnectParameters
    {
        SharedTransmission Upstream;
        const ClientConfig &Config;
        std::span<const std::uint8_t> PeerPublicKey;
        const HandshakeParams &Params;
    };

    /**
     * @struct AcceptParameters
     * @brief Reality 服务端连接装配参数
     * @details Upstream 的所有权转移；其余字段在函数调用期间借用并立即复制。
     */
    struct AcceptParameters
    {
        SharedTransmission Upstream;
        const ServerConfig &Config;
        std::span<const std::uint8_t> PeerPublicKey;
        const HandshakeParams &Params;
    };

    namespace Detail
    {
        struct OwnedHandshakeData
        {
            std::vector<std::uint8_t> ClientRandom;
            std::vector<std::uint8_t> Hello;
            std::array<std::uint8_t, MaxShortIdLen> ShortId{};
        };

        struct OwnedConnectRequest
        {
            SharedTransmission Upstream;
            ClientConfig Config;
            std::vector<std::uint8_t> PeerPublicKey;
            OwnedHandshakeData Handshake;
        };

        struct OwnedAcceptRequest
        {
            SharedTransmission Upstream;
            ServerConfig Config;
            std::vector<std::uint8_t> PeerPublicKey;
            OwnedHandshakeData Handshake;
        };

        [[nodiscard]] inline auto CopyBytes(std::span<const std::uint8_t> Bytes)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Result;
            Result.reserve(Bytes.size());
            for (const auto Byte : Bytes)
            {
                Result.push_back(Byte);
            }
            return Result;
        }

        [[nodiscard]] inline auto SnapshotHandshake(const HandshakeParams &Params)
            -> OwnedHandshakeData
        {
            return {CopyBytes(Params.ClientRandom), CopyBytes(Params.hello), Params.ShortId};
        }

        [[nodiscard]] inline auto ConnectOwned(OwnedConnectRequest Params)
            -> Net::awaitable<std::pair<Error, SharedConn>>
        {
            auto Connection = std::make_shared<Conn<>>(
                std::move(Params.Upstream), Params.Config.private_key);
            const HandshakeParams Handshake{
                Params.Handshake.ClientRandom, Params.Handshake.Hello, Params.Handshake.ShortId};
            const auto ErrorCode = co_await Connection->WriteHandshake(
                Params.PeerPublicKey, Handshake);
            SharedConn Result;
            if (ErrorCode == Error::None)
            {
                Result = SharedConn(std::move(Connection));
            }
            else
            {
                Connection->Close();
            }
            co_return std::pair{ErrorCode, std::move(Result)};
        }

        [[nodiscard]] inline auto AcceptOwned(OwnedAcceptRequest Params)
            -> Net::awaitable<
                std::tuple<Error, std::array<std::uint8_t, MaxShortIdLen>, SharedConn>>
        {
            auto Connection = std::make_shared<Conn<>>(
                std::move(Params.Upstream), Params.Config.private_key);
            std::array<std::uint8_t, MaxShortIdLen> ShortId{};
            if (Params.Config.ShortIds.empty())
            {
                Connection->Close();
                co_return std::tuple{Error::BadAuth, ShortId, SharedConn{}};
            }

            const HandshakeParams Handshake{
                Params.Handshake.ClientRandom, Params.Handshake.Hello, Params.Handshake.ShortId};
            auto ErrorCode = co_await Connection->ReadHandshake(
                Params.PeerPublicKey, Handshake, ShortId);
            SharedConn Result;
            if (ErrorCode == Error::None &&
                std::find(Params.Config.ShortIds.begin(), Params.Config.ShortIds.end(), ShortId) !=
                    Params.Config.ShortIds.end())
            {
                Result = SharedConn(std::move(Connection));
            }
            else
            {
                if (ErrorCode == Error::None)
                {
                    ErrorCode = Error::BadAuth;
                }
                Connection->Close();
            }
            co_return std::tuple{ErrorCode, ShortId, std::move(Result)};
        }
    } // namespace Detail

    // =========================================================================
    // 工厂（自由函数，握手在内部完成）
    // =========================================================================

    /**
     * @brief 创建客户端流连接并完成认证握手
     * @param Params 客户端连接装配参数
     * @return 错误码与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::pair<Error, SharedConn>>
    {
        Detail::OwnedConnectRequest Request{
            std::move(Params.Upstream),
            Params.Config,
            Detail::CopyBytes(Params.PeerPublicKey),
            Detail::SnapshotHandshake(Params.Params)};
        return Detail::ConnectOwned(std::move(Request));
    }

    /**
     * @brief 接收服务端流连接并完成认证校验
     * @param Params 服务端连接装配参数
     * @return 错误码、解析的短 ID 与协议连接（失败时连接为空）
     */
    [[nodiscard]] inline auto Accept(AcceptParameters Params)
        -> Net::awaitable<
            std::tuple<Error, std::array<std::uint8_t, MaxShortIdLen>, SharedConn>>
    {
        Detail::OwnedAcceptRequest Request{
            std::move(Params.Upstream),
            Params.Config,
            Detail::CopyBytes(Params.PeerPublicKey),
            Detail::SnapshotHandshake(Params.Params)};
        return Detail::AcceptOwned(std::move(Request));
    }

} // namespace Preview::Reality
