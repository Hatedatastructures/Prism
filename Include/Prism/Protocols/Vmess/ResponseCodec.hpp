/**
 * @file ResponseCodec.hpp
 * @brief VMess 响应头编解码
 * @details 响应头使用请求消息中的 key/nonce 派生密钥；标准 VMess
 *          response AEAD 不把 AuthID 作为附加认证数据。请求消息和认证原语分别来自
 *          RequestCodec.hpp 与 AuthCrypto.hpp、AuthKdf.hpp、AuthId.hpp、AuthHeader.hpp。
 */

#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace Prism::Vmess
{

    /**
     * @brief 响应头密封输入（IV + V）
     */
    struct RespHeaderInput
    {
        std::span<const std::uint8_t, 12> iv;
        std::span<const std::uint8_t, 4> v;
    };

    /**
     * @brief 响应头解析输入（IV + 密文）
     */
    struct RespHeaderParseInput
    {
        std::span<const std::uint8_t, 12> iv;
        std::span<const std::uint8_t> Data;
    };

    /**
     * @brief 密封响应头
     * @param RespKey 16 字节响应密钥
     * @param Input 输入（iv + v）
     * @return 响应头密文（4 + 16 tag）
     */
    [[nodiscard]] auto SealResponseHeader(std::span<const std::uint8_t, 16> RespKey,
        const RespHeaderInput& Input) -> std::vector<std::uint8_t>;

    /**
     * @brief 打开响应头
     * @param RespKey 16 字节响应密钥
     * @param Input 输入（iv + Data）
     * @param Output 输出响应头
     * @return 错误码
     */
    [[nodiscard]] auto OpenResponseHeader(std::span<const std::uint8_t, 16> RespKey,
        const RespHeaderParseInput& Input, ResponseHeader& Output) -> Error;

    /**
     * @brief 构造 VMess AEAD 响应头
     * @param MessageValue 请求消息（RequestKey / RequestNonce / RespHeader）
     * @param Response 输出响应字节
     * @return false = 成功（保留历史 API 语义）
     */
    [[nodiscard]] auto MakeResponse(const Message& MessageValue, std::string& Response) -> bool;

} // namespace Prism::Vmess
