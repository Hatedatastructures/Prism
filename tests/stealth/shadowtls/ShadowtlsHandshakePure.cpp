/**
 * @file ShadowtlsHandshakePure.cpp
 * @brief ShadowTLS 握手纯函数单元测试
 * @details 通过 #include 源文件直接测试 anonymous namespace 中的
 *          extract_random 和 is_tls13_hello 纯函数。
 *          这两个函数负责从 TLS ServerHello 中提取 ServerRandom
 *          和检测是否为 TLS 1.3 握手。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/stealth/facade/shadowtls/util/constants.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

// 拉入源文件中 anonymous namespace 的函数定义
// 注意：必须在所有头文件之后 include
// anonymous namespace 函数在 psm::stealth::shadowtls 命名空间中可见
#include "../../src/prism/stealth/facade/shadowtls/handshake.cpp"

using namespace psm::stealth::shadowtls;

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
        buf.push_back(std::byte{content_handshake});  // 0x16
        buf.push_back(std::byte{0x03});
        buf.push_back(std::byte{0x03}); // legacy version

        // 构建握手体
        std::vector<std::byte> body;

        // 握手类型
        body.push_back(std::byte{hs_type_serverhello}); // 0x02

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
            ext.push_back(std::byte{0x04});

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

    // ─── extract_random 测试 ──────────────────────────

    /**
     * @brief 测试 extract_random 从合法 ServerHello 中提取 32 字节随机数
     * @details 构造完整的 ServerHello，验证返回值非空且随机数字节正确。
     */
    TEST(ShadowtlsHandshakePure, ExtractRandomValid)
    {
        auto hello = make_server_hello(false);
        auto result = extract_random(hello);

        EXPECT_TRUE(result.has_value()) << "extract_random: 合法 ServerHello 返回非空";

        if (result)
        {
            // 随机数应为 32 字节 0x42
            bool all_42 = true;
            for (std::size_t i = 0; i < tls_rndsize; ++i)
            {
                if (result->at(i) != std::byte{0x42})
                {
                    all_42 = false;
                    break;
                }
            }
            EXPECT_TRUE(all_42) << "extract_random: 随机数字节全部为 0x42";
        }
    }

    /**
     * @brief 测试 extract_random 对过短缓冲区返回 nullopt
     * @details 缓冲区长度不足 43 字节（最小合法长度），应返回空值。
     */
    TEST(ShadowtlsHandshakePure, ExtractRandomTooShort)
    {
        // 构造 42 字节缓冲区（最小需要 43 字节）
        std::vector<std::byte> short_buf(42, std::byte{0x00});
        short_buf[0] = std::byte{content_handshake};
        short_buf[5] = std::byte{hs_type_serverhello};

        auto result = extract_random(short_buf);
        EXPECT_TRUE(!result.has_value()) << "extract_random: 过短缓冲区返回 nullopt";
    }

    /**
     * @brief 测试 extract_random 对错误内容类型返回 nullopt
     * @details TLS 记录头的 content_type 不是 0x16（Handshake），应返回空值。
     */
    TEST(ShadowtlsHandshakePure, ExtractRandomWrongType)
    {
        auto hello = make_server_hello(false);

        // 篡改 content_type
        hello[0] = std::byte{0x17}; // Application Data

        auto result = extract_random(hello);
        EXPECT_TRUE(!result.has_value()) << "extract_random: 错误 content_type 返回 nullopt";
    }

    /**
     * @brief 测试 extract_random 对非 ServerHello 握手类型返回 nullopt
     * @details 握手类型不是 0x02（ServerHello），应返回空值。
     */
    TEST(ShadowtlsHandshakePure, ExtractRandomNotServerHello)
    {
        auto hello = make_server_hello(false);

        // 篡改握手类型
        hello[5] = std::byte{0x01}; // ClientHello

        auto result = extract_random(hello);
        EXPECT_TRUE(!result.has_value()) << "extract_random: 非 ServerHello 类型返回 nullopt";
    }

    /**
     * @brief 测试 extract_random 对空缓冲区返回 nullopt
     */
    TEST(ShadowtlsHandshakePure, ExtractRandomEmpty)
    {
        std::vector<std::byte> empty_buf;
        auto result = extract_random(empty_buf);
        EXPECT_TRUE(!result.has_value()) << "extract_random: 空缓冲区返回 nullopt";
    }

    /**
     * @brief 测试 extract_random 对恰好等于最小长度的缓冲区成功提取
     * @details 缓冲区大小恰好为 tls_hdrsize + 1 + 3 + 2 + tls_rndsize = 43 字节。
     */
    TEST(ShadowtlsHandshakePure, ExtractRandomExactMinSize)
    {
        std::vector<std::byte> buf(43, std::byte{0x00});
        buf[0] = std::byte{content_handshake}; // 0x16
        buf[5] = std::byte{hs_type_serverhello}; // 0x02
        // 偏移 11-42 填充 0x55
        for (std::size_t i = 11; i < 43; ++i)
        {
            buf[i] = std::byte{0x55};
        }

        auto result = extract_random(buf);
        EXPECT_TRUE(result.has_value()) << "extract_random: 恰好最小长度返回非空";

        if (result)
        {
            bool all_55 = true;
            for (std::size_t i = 0; i < tls_rndsize; ++i)
            {
                if (result->at(i) != std::byte{0x55})
                {
                    all_55 = false;
                    break;
                }
            }
            EXPECT_TRUE(all_55) << "extract_random: 恰好最小长度时随机数字节正确";
        }
    }

    // ─── is_tls13_hello 测试 ──────────────────────────

    /**
     * @brief 测试 is_tls13_hello 识别包含 supported_versions 扩展的 TLS 1.3 ServerHello
     * @details 构造包含 type=0x002B、value=0x0304 扩展的 ServerHello，应返回 true。
     */
    TEST(ShadowtlsHandshakePure, IsTls13HelloWithSupportedVersions)
    {
        auto hello = make_server_hello(true);
        auto result = is_tls13_hello(hello);

        EXPECT_TRUE(result) << "is_tls13_hello: TLS 1.3 ServerHello 返回 true";
    }

    /**
     * @brief 测试 is_tls13_hello 对无 supported_versions 扩展的 TLS 1.2 ServerHello 返回 false
     * @details 构造不含扩展的 ServerHello，应返回 false。
     */
    TEST(ShadowtlsHandshakePure, IsTls13HelloTls12)
    {
        auto hello = make_server_hello(false);
        auto result = is_tls13_hello(hello);

        EXPECT_TRUE(!result) << "is_tls13_hello: 无扩展 ServerHello 返回 false";
    }

    /**
     * @brief 测试 is_tls13_hello 对截断的 ServerHello 返回 false
     * @details 缓冲区过短无法解析到 session_id_len 字段，应返回 false。
     */
    TEST(ShadowtlsHandshakePure, IsTls13HelloTooShort)
    {
        // 缓冲区短于 session_id_len_idx (43)
        std::vector<std::byte> short_buf(20, std::byte{0x00});
        auto result = is_tls13_hello(short_buf);

        EXPECT_TRUE(!result) << "is_tls13_hello: 截断缓冲区返回 false";
    }

    /**
     * @brief 测试 is_tls13_hello 对错误的扩展版本号返回 false
     * @details 构造含 supported_versions 扩展但值为 0x0303（TLS 1.2）的 ServerHello。
     */
    TEST(ShadowtlsHandshakePure, IsTls13HelloWrongVersion)
    {
        // 手动构建含 supported_versions 扩展但版本号为 TLS 1.2 的 ServerHello
        std::vector<std::byte> buf;

        // TLS 记录头
        buf.push_back(std::byte{content_handshake});
        buf.push_back(std::byte{0x03});
        buf.push_back(std::byte{0x03});

        // 握手体
        std::vector<std::byte> body;
        body.push_back(std::byte{hs_type_serverhello});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00}); // 长度占位

        body.push_back(std::byte{0x03});
        body.push_back(std::byte{0x03}); // 版本

        // 随机数
        for (int i = 0; i < 32; ++i)
        {
            body.push_back(std::byte{0x42});
        }

        // SessionID 长度 = 0
        body.push_back(std::byte{0x00});
        // 密码套件
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x01});
        // 压缩方法
        body.push_back(std::byte{0x00});

        // supported_versions 扩展: type=0x002B, length=2, value=0x0303 (TLS 1.2)
        std::vector<std::byte> ext;
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x2B});
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x02});
        ext.push_back(std::byte{0x03});
        ext.push_back(std::byte{0x03}); // TLS 1.2 而非 TLS 1.3

        auto ext_size = static_cast<std::uint16_t>(ext.size());
        body.push_back(std::byte(static_cast<std::uint8_t>((ext_size >> 8) & 0xFF)));
        body.push_back(std::byte(static_cast<std::uint8_t>(ext_size & 0xFF)));
        body.insert(body.end(), ext.begin(), ext.end());

        // 填充握手长度
        auto hs_len = body.size() - 4;
        body[1] = std::byte(static_cast<std::uint8_t>((hs_len >> 16) & 0xFF));
        body[2] = std::byte(static_cast<std::uint8_t>((hs_len >> 8) & 0xFF));
        body[3] = std::byte(static_cast<std::uint8_t>(hs_len & 0xFF));

        // 记录长度
        auto rec_len = static_cast<std::uint16_t>(body.size());
        buf.push_back(std::byte(static_cast<std::uint8_t>((rec_len >> 8) & 0xFF)));
        buf.push_back(std::byte(static_cast<std::uint8_t>(rec_len & 0xFF)));
        buf.insert(buf.end(), body.begin(), body.end());

        auto result = is_tls13_hello(buf);
        EXPECT_TRUE(!result) << "is_tls13_hello: supported_versions 值为 TLS 1.2 返回 false";
    }

    /**
     * @brief 测试 is_tls13_hello 跳过无关扩展后找到 supported_versions
     * @details 构造含一个无关扩展后再接 supported_versions 扩展的 ServerHello，
     *          验证函数能正确遍历扩展列表。
     */
    TEST(ShadowtlsHandshakePure, IsTls13HelloSkipOtherExt)
    {
        std::vector<std::byte> buf;

        // TLS 记录头
        buf.push_back(std::byte{content_handshake});
        buf.push_back(std::byte{0x03});
        buf.push_back(std::byte{0x03});

        // 握手体
        std::vector<std::byte> body;
        body.push_back(std::byte{hs_type_serverhello});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});

        body.push_back(std::byte{0x03});
        body.push_back(std::byte{0x03});

        for (int i = 0; i < 32; ++i)
        {
            body.push_back(std::byte{0x42});
        }

        body.push_back(std::byte{0x00}); // SessionID 长度
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x01}); // 密码套件
        body.push_back(std::byte{0x00}); // 压缩方法

        // 构建扩展列表
        std::vector<std::byte> ext;

        // 无关扩展: type=0x0000 (server_name), length=4, value=随意
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x04});
        ext.push_back(std::byte{0x01});
        ext.push_back(std::byte{0x02});
        ext.push_back(std::byte{0x03});
        ext.push_back(std::byte{0x04});

        // supported_versions 扩展
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x2B});
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x02});
        ext.push_back(std::byte{0x03});
        ext.push_back(std::byte{0x04});

        auto ext_size = static_cast<std::uint16_t>(ext.size());
        body.push_back(std::byte(static_cast<std::uint8_t>((ext_size >> 8) & 0xFF)));
        body.push_back(std::byte(static_cast<std::uint8_t>(ext_size & 0xFF)));
        body.insert(body.end(), ext.begin(), ext.end());

        // 填充握手长度
        auto hs_len = body.size() - 4;
        body[1] = std::byte(static_cast<std::uint8_t>((hs_len >> 16) & 0xFF));
        body[2] = std::byte(static_cast<std::uint8_t>((hs_len >> 8) & 0xFF));
        body[3] = std::byte(static_cast<std::uint8_t>(hs_len & 0xFF));

        // 记录长度
        auto rec_len = static_cast<std::uint16_t>(body.size());
        buf.push_back(std::byte(static_cast<std::uint8_t>((rec_len >> 8) & 0xFF)));
        buf.push_back(std::byte(static_cast<std::uint8_t>(rec_len & 0xFF)));
        buf.insert(buf.end(), body.begin(), body.end());

        auto result = is_tls13_hello(buf);
        EXPECT_TRUE(result) << "is_tls13_hello: 跳过无关扩展后找到 TLS 1.3";
    }

    /**
     * @brief 测试 is_tls13_hello 处理带 SessionID 的 ServerHello
     * @details 构造含 4 字节 SessionID 的 ServerHello，验证偏移量计算正确。
     */
    TEST(ShadowtlsHandshakePure, IsTls13HelloWithSessionId)
    {
        std::vector<std::byte> buf;

        buf.push_back(std::byte{content_handshake});
        buf.push_back(std::byte{0x03});
        buf.push_back(std::byte{0x03});

        std::vector<std::byte> body;
        body.push_back(std::byte{hs_type_serverhello});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x00});

        body.push_back(std::byte{0x03});
        body.push_back(std::byte{0x03});

        for (int i = 0; i < 32; ++i)
        {
            body.push_back(std::byte{0x42});
        }

        // SessionID 长度 = 4，后接 4 字节 SessionID
        body.push_back(std::byte{0x04});
        body.push_back(std::byte{0xAA});
        body.push_back(std::byte{0xBB});
        body.push_back(std::byte{0xCC});
        body.push_back(std::byte{0xDD});

        body.push_back(std::byte{0x00});
        body.push_back(std::byte{0x01}); // 密码套件
        body.push_back(std::byte{0x00}); // 压缩方法

        // supported_versions 扩展
        std::vector<std::byte> ext;
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x2B});
        ext.push_back(std::byte{0x00});
        ext.push_back(std::byte{0x02});
        ext.push_back(std::byte{0x03});
        ext.push_back(std::byte{0x04});

        auto ext_size = static_cast<std::uint16_t>(ext.size());
        body.push_back(std::byte(static_cast<std::uint8_t>((ext_size >> 8) & 0xFF)));
        body.push_back(std::byte(static_cast<std::uint8_t>(ext_size & 0xFF)));
        body.insert(body.end(), ext.begin(), ext.end());

        // 填充握手长度
        auto hs_len = body.size() - 4;
        body[1] = std::byte(static_cast<std::uint8_t>((hs_len >> 16) & 0xFF));
        body[2] = std::byte(static_cast<std::uint8_t>((hs_len >> 8) & 0xFF));
        body[3] = std::byte(static_cast<std::uint8_t>(hs_len & 0xFF));

        // 记录长度
        auto rec_len = static_cast<std::uint16_t>(body.size());
        buf.push_back(std::byte(static_cast<std::uint8_t>((rec_len >> 8) & 0xFF)));
        buf.push_back(std::byte(static_cast<std::uint8_t>(rec_len & 0xFF)));
        buf.insert(buf.end(), body.begin(), body.end());

        auto result = is_tls13_hello(buf);
        EXPECT_TRUE(result) << "is_tls13_hello: 带 SessionID 的 TLS 1.3 ServerHello 返回 true";
    }

} // namespace
