/**
 * @file ResponseCodec.hpp
 * @brief VMess 响应头编解码
 * @details 响应头使用请求消息中的 key/nonce 派生密钥，并以 AuthID
 *          作为 AEAD 附加认证数据。请求消息和认证原语分别来自
 *          RequestCodec.hpp 与 Auth.hpp。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <span>
#include <string>
#include <vector>

#include <preview/Protocols/Vmess/Auth.hpp>
#include <preview/Protocols/Vmess/RequestCodec.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    /**
     * @brief 响应头密封输入（IV + V + AuthID）
     */
    struct RespHeaderInput
    {
        std::span<const std::uint8_t, 12> iv;
        std::span<const std::uint8_t, 4> v;
        std::span<const std::uint8_t, 16> AuthId;
    };

    /**
     * @brief 响应头解析输入（IV + 密文 + AuthID）
     */
    struct RespHeaderParseInput
    {
        std::span<const std::uint8_t, 12> iv;
        std::span<const std::uint8_t> Data;
        std::span<const std::uint8_t, 16> AuthId;
    };

    /**
     * @brief 密封响应头
     * @param RespKey 16 字节响应密钥
     * @param in 输入（iv + v + AuthId）
     * @return 响应头密文（4 + 16 tag）
     */
    [[nodiscard]] inline auto SealResponseHeader(std::span<const std::uint8_t, 16> RespKey,
                                                   const RespHeaderInput &in) -> std::vector<std::uint8_t>
    {
        return detail::AesGcmSeal(detail::SealInput{RespKey, in.iv, in.v, in.AuthId});
    }

    /**
     * @brief 打开响应头
     * @param RespKey 16 字节响应密钥
     * @param in 输入（iv + Data + AuthId）
     * @param out 输出响应头
     * @return 错误码
     */
    [[nodiscard]] inline auto OpenResponseHeader(std::span<const std::uint8_t, 16> RespKey,
                                                   const RespHeaderParseInput &in, ResponseHeader &out)
        -> Error
    {
        const auto Plain = detail::AesGcmOpen(detail::OpenInput{RespKey, in.iv, in.Data, in.AuthId});
        if (Plain.size() < 4)
        {
            return Error::BadAuth;
        }
        out.Version = Plain[0];
        std::memcpy(out.v.data(), Plain.data(), 4);
        return Error::None;
    }

    /**
     * @brief 构造 VMess AEAD 响应头
     * @param msg 请求消息（RequestKey / RequestNonce / RespHeader）
     * @param resp 输出响应字节
     * @return false = 成功（保留历史 API 语义）
     */
    [[nodiscard]] inline auto MakeResponse(const Message &msg, std::string &resp) -> bool
    {
        const auto RespBodyKey = detail::Sha256(msg.RequestKey);
        const auto RespBodyIv = detail::Sha256(msg.RequestNonce);
        std::array<std::uint8_t, 16> RespKey16{};
        std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
        std::array<std::uint8_t, 16> RespIv16{};
        std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);

        const auto AuthId = std::span<const std::uint8_t, AuthHeaderLen>(msg.AuthId);

        const std::array<std::uint8_t, 4> v_plain{msg.RespHeader, 0, 0, 0};
        const auto RespKey = Kdf(RespKey16, KdfRespKey);
        const auto RespIv = Kdf(RespIv16, KdfRespIv);
        std::array<std::uint8_t, 16> rk{};
        std::memcpy(rk.data(), RespKey.data(), 16);
        std::array<std::uint8_t, 12> riv{};
        std::memcpy(riv.data(), RespIv.data(), 12);
        const auto RespEnc = SealResponseHeader(rk, RespHeaderInput{riv, v_plain, AuthId});

        const auto RespLenKey = Kdf(RespKey16, KdfRespLenKey);
        const auto RespLenIv = Kdf(RespIv16, KdfRespLenIv);
        std::array<std::uint8_t, 16> rlk{};
        std::memcpy(rlk.data(), RespLenKey.data(), 16);
        std::array<std::uint8_t, 12> rliv{};
        std::memcpy(rliv.data(), RespLenIv.data(), 12);
        const std::array<std::uint8_t, 2> resp_LenPlain{static_cast<std::uint8_t>(RespEnc.size() >> 8),
                                                         static_cast<std::uint8_t>(RespEnc.size() & 0xFF)};
        const auto LenEnc = detail::AesGcmSeal(detail::SealInput{rlk, rliv, resp_LenPlain, AuthId});

        resp.clear();
        resp.reserve(LenEnc.size() + RespEnc.size());
        resp.insert(resp.end(), LenEnc.begin(), LenEnc.end());
        resp.insert(resp.end(), RespEnc.begin(), RespEnc.end());
        return false;
    }

} // namespace Preview::Vmess
