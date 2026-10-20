/**
 * @file CryptoExceptionTestSupport.hpp
 * @brief CryptoExceptionCoverage.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file CryptoExceptionCoverage.cpp
 * @brief tests/Prism/Crypto 与异常覆盖率补充测试
 * @details 纯函数单元测试（无协程），目标提升两个模块的路径覆盖：
 * - crypto：aead 错误路径补充（空密钥/空输入/短密文）、base64（非法字符/填充
 *   错误/往返）、blake3（空输入/大输入/已知向量）、block（AES-128/256 往返、
 *   密钥长度错误）、hkdf（RFC 4231/5869 已知向量、expand 非法长度边界）、
 *   Sha224（空/边界/已知向量、Credential 规范化）、X25519（RFC 7748 向量、
 *   密钥派生往返、非法长度、低阶点）
 * - exception：Deviant/Network/Protocol/Security 的构造（错误码+描述）、
 *   What() 内容、TypeName()、ErrorCode()、Location()/Filename()、
 *   Dump() 完整格式、安全异常的敏感信息保护（错误码消息不携带描述、
 *   Dump 不泄露完整路径）
 * @note 已知向量来源：FIPS-197、RFC 4231、RFC 5869、RFC 7748、NIST、
 *       BLAKE3 官方测试向量
 */

#include <boost/asio.hpp>

#include <Prism/Foundation/Utility/Crypto/Crypto.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Foundation/Utility/Crypto/X25519.hpp>
#include <Prism/Foundation/Exception/Network.hpp>
#include <Prism/Foundation/Exception/Protocol.hpp>
#include <Prism/Foundation/Exception/Security.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace crypto = Prism::Crypto;
    namespace fault = Prism::Fault;
    namespace exc = Prism::Exception;

    /**
     * @brief 将一个十六进制字符转换为四位数值。
     * @param Character 输入字符。
     * @return 字符对应的半字节。
     */
    [[nodiscard]] auto HexNibble(const char Character) -> std::uint8_t
    {
        if (Character >= '0' && Character <= '9')
        {
            return static_cast<std::uint8_t>(Character - '0');
        }
        if (Character >= 'a' && Character <= 'f')
        {
            return static_cast<std::uint8_t>(Character - 'a' + 10);
        }
        return static_cast<std::uint8_t>(Character - 'A' + 10);
    }

    /**
     * @brief 十六进制字符串转字节数组
     * @param hex 十六进制字符串（无 0x 前缀，成对字符）
     * @return 解码后的字节序列
     */
    auto HexToBytes(const std::string_view Hex) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        Output.reserve(Hex.size() / 2);
        for (std::size_t Index = 0; Index + 1 < Hex.size(); Index += 2)
        {
            Output.push_back(static_cast<std::uint8_t>((HexNibble(Hex[Index]) << 4) |
                                                        HexNibble(Hex[Index + 1])));
        }
        return Output;
    }

    /**
     * @brief 字节序列转十六进制字符串
     * @param Data 字节序列
     * @return 小写十六进制字符串
     */
    auto ToHex(const std::span<const std::uint8_t> Data) -> std::string
    {
        constexpr char HexChars[] = "0123456789abcdef";
        std::string out;
        out.reserve(Data.size() * 2);
        for (const auto byte : Data)
        {
            out.push_back(HexChars[(byte >> 4) & 0x0F]);
            out.push_back(HexChars[byte & 0x0F]);
        }
        return out;
    }

    /**
     * @brief 检查字符串是否包含子串
     * @param haystack 被搜索的字符串
     * @param needle 目标子串
     * @return 找到返回 true
     */
    auto Contains(const std::string &haystack, const std::string_view needle) -> bool
    {
        return haystack.find(needle) != std::string::npos;
    }

    // ──────────────────────── crypto: aead 错误路径补充 ────────────────────────






    // ──────────────────────── crypto: base64 ────────────────────────












    // ──────────────────────── crypto: blake3 ────────────────────────








    // ──────────────────────── crypto: block ────────────────────────





    // ──────────────────────── crypto: hkdf ────────────────────────













    // ──────────────────────── crypto: Sha224 ────────────────────────






    // ──────────────────────── crypto: X25519 ────────────────────────







    // ──────────────────────── exception: Deviant ────────────────────────

    /**
     * @class exposed_deviant
     * @brief 暴露 TypeName() 的 Deviant 测试子类
     * @details Deviant 是抽象基类，此类用于实例化测试并公开类型名称。
     */
    class exposed_deviant : public exc::Deviant
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_deviant(std::error_code ec, std::string_view desc = {},
                                 const std::source_location &loc = std::source_location::current())
            : exc::Deviant(ec, desc, loc)
        {
        }

        /** @brief 转发字符串构造 */
        explicit exposed_deviant(const std::string &msg,
                                 const std::source_location &loc = std::source_location::current())
            : exc::Deviant(msg, loc)
        {
        }

        /** @brief 转发格式化构造 */
        template <typename... Args>
        explicit exposed_deviant(const std::source_location &loc, std::format_string<Args...> fmt,
                                 Args &&...args)
            : exc::Deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return "EXPOSED";
        }
    };











    // ──────────────────────── exception: Network ────────────────────────

    /**
     * @class exposed_network
     * @brief 暴露 protected TypeName() 的 Network 测试子类
     */
    class exposed_network : public exc::Network
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_network(fault::Code err, std::string_view desc = {},
                                 const std::source_location &loc = std::source_location::current())
            : exc::Network(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return exc::Network::TypeName();
        }
    };




    // ──────────────────────── exception: Protocol ────────────────────────

    /**
     * @class exposed_protocol
     * @brief 暴露 protected TypeName() 的 Protocol 测试子类
     */
    class exposed_protocol : public exc::Protocol
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_protocol(fault::Code err, std::string_view desc = {},
                                  const std::source_location &loc = std::source_location::current())
            : exc::Protocol(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return exc::Protocol::TypeName();
        }
    };




    // ──────────────────────── exception: Security（敏感信息保护） ────────────────────────

    /**
     * @class exposed_security
     * @brief 暴露 protected TypeName() 的 Security 测试子类
     */
    class exposed_security : public exc::Security
    {
    public:
        /** @brief 转发错误码构造 */
        explicit exposed_security(fault::Code err, std::string_view desc = {},
                                  const std::source_location &loc = std::source_location::current())
            : exc::Security(err, desc, loc)
        {
        }

        /** @brief 公开类型名称 */
        [[nodiscard]] auto TypeName() const noexcept -> std::string_view override
        {
            return exc::Security::TypeName();
        }
    };





} // namespace


