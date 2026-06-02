/**
 * @file RestlsHandshakePure.cpp
 * @brief Restls 握手纯函数单元测试
 * @details 通过 #include 源文件直接测试 anonymous namespace 中的
 *          extract_server_random、is_tls13_server_hello 和 parse_host_port
 *          纯函数。这三个函数负责从 TLS ServerHello 中提取 ServerRandom、
 *          检测是否为 TLS 1.3 握手以及解析 host:port 地址。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>
#include <prism/stealth/facade/restls/crypto.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

// 拉入源文件中 anonymous namespace 的函数定义
// 注意：必须在所有头文件之后 include
// anonymous namespace 函数在 psm::stealth::restls 命名空间中可见
#include "../../src/prism/stealth/facade/restls/handshake.cpp"

using namespace psm::stealth::restls;

namespace
{

    /**
     * @brief 构建测试用 ServerHello 字节缓冲区
     * @details 按照 TLS 1.3 ServerHello 格式构造字节数组：
     *          TLS 记录头(5) + 握手头(4) + 版本(2) + 随机数(32) +
     *          SessionID 长度(1) + 密码套件(2) + 压缩方法(1) + 可选扩展。
     * @param with_tls13_ext 是否包含 supported_versions 扩展（TLS 1.3 标志）
     * @return 完整的 ServerHello 字节缓冲区
     */
    auto make_server_hello(bool with_tls13_ext = false) -> std::vector<std::byte>
    {
        std::vector<std::byte> buf;

        // TLS 记录头: content_type(1) + version(2) + length(2)
        buf.push_back(std::byte{0x16}); // Handshake
        buf.push_back(std::byte{0x03});
        buf.push_back(std::byte{0x03}); // legacy version

        // 构建握手体
        std::vector<std::byte> body;

        // 握手类型
        body.push_back(std::byte{0x02}); // ServerHello

        // 握手长度占位符（3 字节）
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});

        // 版本（legacy）
        body.push_back(std::byte{0x03});
        body.push_back(std::byte{0x03});

        // 随机数（32 字节，全部填充 0x42）
        for (int i = 0; i < 32; ++i)
        {
            body.push_back(std::byte{0x42});
        }

        // SessionID 长度 = 0（无 SessionID）
        body.push_back(std::byte{0x00});

        // 密码套件（2 字节）
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x01});

        // 压缩方法（1 字节）
        body.push_back(std::byte{0x00});

        if (with_tls13_ext)
        {
            // 扩展列表
            std::vector<std::byte> ext;

            // supported_versions 扩展: type=0x002B, length=2, value=0x0304
            ext.push_back(std::byte{0x00});
            ext.push_back(std::byte{0x2B});
            ext.push_back(std::byte{0x00});
            ext.push_back(std::byte{0x02});
            ext.push_back(std::byte{0x03});
            ext.push_back(std::byte{0x04}); // TLS 1.3

            // 扩展列表长度（2 字节）
            auto ext_size = static_cast<std::uint16_t>(ext.size());
            body.push_back(std::byte(static_cast<std::uint8_t>((ext_size >> 8) & 0xFF)));
            body.push_back(std::byte(static_cast<std::uint8_t>(ext_size & 0xFF)));
            body.insert(body.end(), ext.begin(), ext.end());
        }

        // 填充握手长度（body 中去掉 4 字节握手头之后的长度）
        auto hs_len = body.size() - 4;
        body[1] = std::byte(static_cast<std::uint8_t>((hs_len >> 16) & 0xFF));
        body[2] = std::byte(static_cast<std::uint8_t>((hs_len >> 8) & 0xFF));
        body[3] = std::byte(static_cast<std::uint8_t>(hs_len & 0xFF));

        // 记录长度（2 字节）
        auto rec_len = static_cast<std::uint16_t>(body.size());
        buf.push_back(std::byte(static_cast<std::uint8_t>((rec_len >> 8) & 0xFF)));
        buf.push_back(std::byte(static_cast<std::uint8_t>(rec_len & 0xFF)));

        // 拼接握手体
        buf.insert(buf.end(), body.begin(), body.end());

        return buf;
    }

    // ─── extract_server_random 测试 ──────────────────

    /**
     * @brief 测试 extract_server_random 从合法 ServerHello 中提取 32 字节随机数
     * @details 构造完整的 ServerHello，验证返回值非空且随机数字节正确（全部为 0x42）。
     */
    TEST(RestlsHandshakePure, ExtractServerRandomValid)
    {
        auto hello = make_server_hello(false);
        auto result = extract_server_random(hello);

        EXPECT_TRUE(result.has_value()) << "extract_server_random: 合法 ServerHello 返回非空";

        if (result)
        {
            // 随机数应为 32 字节 0x42
            bool all_42 = true;
            for (std::size_t i = 0; i < 32; ++i)
            {
                if ((*result)[i] != 0x42)
                {
                    all_42 = false;
                    break;
                }
            }
            EXPECT_TRUE(all_42) << "extract_server_random: 随机数字节全部为 0x42";
        }
    }

    /**
     * @brief 测试 extract_server_random 对过短缓冲区返回 nullopt
     * @details 缓冲区长度不足 43 字节（最小合法长度），应返回空值。
     */
    TEST(RestlsHandshakePure, ExtractServerRandomTooShort)
    {
        // 构造 42 字节缓冲区（最小需要 43 字节）
        std::vector<std::byte> short_buf(42, std::byte{0x00});

        auto result = extract_server_random(short_buf);
        EXPECT_TRUE(!result.has_value()) << "extract_server_random: 过短缓冲区返回 nullopt";
    }

    /**
     * @brief 测试 extract_server_random 对空缓冲区返回 nullopt
     */
    TEST(RestlsHandshakePure, ExtractServerRandomEmpty)
    {
        std::vector<std::byte> empty_buf;
        auto result = extract_server_random(empty_buf);
        EXPECT_TRUE(!result.has_value()) << "extract_server_random: 空缓冲区返回 nullopt";
    }

    // ─── is_tls13_server_hello 测试 ──────────────────

    /**
     * @brief 测试 is_tls13_server_hello 识别包含 supported_versions 扩展的 TLS 1.3 ServerHello
     * @details 构造包含 type=0x002B、value=0x0304 扩展的 ServerHello，应返回 true。
     */
    TEST(RestlsHandshakePure, IsTls13ServerHelloTrue)
    {
        auto hello = make_server_hello(true);
        auto result = is_tls13_server_hello(hello);

        EXPECT_TRUE(result) << "is_tls13_server_hello: TLS 1.3 ServerHello 返回 true";
    }

    /**
     * @brief 测试 is_tls13_server_hello 对无扩展的 TLS 1.2 ServerHello 返回 false
     * @details 构造不含扩展的 ServerHello，应返回 false。
     */
    TEST(RestlsHandshakePure, IsTls13ServerHelloFalse)
    {
        auto hello = make_server_hello(false);
        auto result = is_tls13_server_hello(hello);

        EXPECT_TRUE(!result) << "is_tls13_server_hello: 无扩展 ServerHello 返回 false";
    }

    /**
     * @brief 测试 is_tls13_server_hello 对截断的 ServerHello 返回 false
     * @details 缓冲区过短无法解析到 session_id_len 字段，应返回 false。
     */
    TEST(RestlsHandshakePure, IsTls13ServerHelloShort)
    {
        // 缓冲区短于所需的最小长度
        std::vector<std::byte> short_buf(20, std::byte{0x00});
        auto result = is_tls13_server_hello(short_buf);

        EXPECT_TRUE(!result) << "is_tls13_server_hello: 截断缓冲区返回 false";
    }

    // ─── parse_host_port 测试 ────────────────────────

    /**
     * @brief 测试 parse_host_port 解析无端口的地址字符串
     * @details 输入 "example.com"，应返回 host="example.com"、port=443（默认端口）。
     */
    TEST(RestlsHandshakePure, ParseHostPortDefault)
    {
        auto [host, port] = parse_host_port("example.com");

        EXPECT_TRUE(host == "example.com") << "parse_host_port: 无端口时 host 正确";
        EXPECT_TRUE(port == 443) << "parse_host_port: 无端口时默认 port=443";
    }

    /**
     * @brief 测试 parse_host_port 解析带显式端口的地址字符串
     * @details 输入 "example.com:8443"，应返回 host="example.com"、port=8443。
     */
    TEST(RestlsHandshakePure, ParseHostPortExplicit)
    {
        auto [host, port] = parse_host_port("example.com:8443");

        EXPECT_TRUE(host == "example.com") << "parse_host_port: 显式端口时 host 正确";
        EXPECT_TRUE(port == 8443) << "parse_host_port: 显式端口时 port=8443";
    }

} // namespace
