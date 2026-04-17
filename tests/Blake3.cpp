/**
 * @file Blake3.cpp
 * @brief BLAKE3 密钥派生单元测试
 * @details 测试 psm::crypto::derive_key 命名空间下的 BLAKE3 密钥派生功能，
 * 覆盖确定性、不同上下文/材料、span 与 vector 重载一致性、输出长度、空输入等场景。
 */

#include <prism/crypto/blake3.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace
{
    int passed = 0;
    int failed = 0;

    /**
     * @brief 输出信息级别日志
     * @param msg 日志消息
     */
    auto LogInfo(const std::string_view msg) -> void
    {
        psm::trace::info("[Blake3] {}", msg);
    }

    /**
     * @brief 记录测试通过并递增计数器
     * @param msg 测试名称
     */
    auto LogPass(const std::string_view msg) -> void
    {
        ++passed;
        psm::trace::info("[Blake3] PASS: {}", msg);
    }

    /**
     * @brief 记录测试失败并递增计数器
     * @param msg 失败原因
     */
    auto LogFail(const std::string_view msg) -> void
    {
        ++failed;
        psm::trace::error("[Blake3] FAIL: {}", msg);
    }
}

/**
 * @brief 测试 BLAKE3 derive_key 确定性
 */
void TestBlake3DeriveKeyDeterministic()
{
    LogInfo("=== TestBlake3DeriveKeyDeterministic ===");

    const std::array<std::uint8_t, 3> material = {0x01, 0x02, 0x03};

    auto key1 = psm::crypto::derive_key("test context", material, 32);
    auto key2 = psm::crypto::derive_key("test context", material, 32);

    if (key1.size() != 32)
    {
        LogFail("derive_key should produce 32 bytes, got " + std::to_string(key1.size()));
        return;
    }

    if (key1 != key2)
    {
        LogFail("derive_key with same inputs should produce identical output");
        return;
    }

    LogPass("Blake3DeriveKeyDeterministic");
}

/**
 * @brief 测试不同 context 产生不同输出
 */
void TestBlake3DifferentContextDifferentOutput()
{
    LogInfo("=== TestBlake3DifferentContextDifferentOutput ===");

    const std::array<std::uint8_t, 3> material = {0x01, 0x02, 0x03};

    auto key_a = psm::crypto::derive_key("context A", material, 32);
    auto key_b = psm::crypto::derive_key("context B", material, 32);

    if (key_a == key_b)
    {
        LogFail("different contexts should produce different keys");
        return;
    }

    LogPass("Blake3DifferentContextDifferentOutput");
}

/**
 * @brief 测试不同 material 产生不同输出
 */
void TestBlake3DifferentMaterialDifferentOutput()
{
    LogInfo("=== TestBlake3DifferentMaterialDifferentOutput ===");

    const std::array<std::uint8_t, 1> mat_a = {0x01};
    const std::array<std::uint8_t, 1> mat_b = {0x02};

    auto key_a = psm::crypto::derive_key("test", mat_a, 32);
    auto key_b = psm::crypto::derive_key("test", mat_b, 32);

    if (key_a == key_b)
    {
        LogFail("different materials should produce different keys");
        return;
    }

    LogPass("Blake3DifferentMaterialDifferentOutput");
}

/**
 * @brief 测试 span 重载与 vector 重载输出一致
 */
void TestBlake3SpanVsVectorOverload()
{
    LogInfo("=== TestBlake3SpanVsVectorOverload ===");

    const std::array<std::uint8_t, 4> material = {0xAA, 0xBB, 0xCC, 0xDD};

    // vector 重载
    auto vec_result = psm::crypto::derive_key("test overload", material, 32);

    // span 重载
    std::vector<std::uint8_t> span_result(32);
    psm::crypto::derive_key("test overload", material, 32, span_result);

    if (vec_result.size() != span_result.size())
    {
        LogFail("span and vector overloads should produce same size output");
        return;
    }

    if (vec_result != span_result)
    {
        LogFail("span and vector overloads should produce identical output");
        return;
    }

    LogPass("Blake3SpanVsVectorOverload");
}

/**
 * @brief 测试输出长度匹配请求
 */
void TestBlake3OutputLengthMatchesRequest()
{
    LogInfo("=== TestBlake3OutputLengthMatchesRequest ===");

    const std::array<std::uint8_t, 4> material = {0x01, 0x02, 0x03, 0x04};

    // 请求 16 字节
    {
        auto key = psm::crypto::derive_key("len test", material, 16);
        if (key.size() != 16)
        {
            LogFail("requested 16 bytes, got " + std::to_string(key.size()));
            return;
        }
    }

    // 请求 64 字节
    {
        auto key = psm::crypto::derive_key("len test", material, 64);
        if (key.size() != 64)
        {
            LogFail("requested 64 bytes, got " + std::to_string(key.size()));
            return;
        }
    }

    LogPass("Blake3OutputLengthMatchesRequest");
}

/**
 * @brief 测试空 material 不崩溃
 */
void TestBlake3EmptyMaterial()
{
    LogInfo("=== TestBlake3EmptyMaterial ===");

    try
    {
        const std::span<const std::uint8_t> empty_material;
        auto key = psm::crypto::derive_key("empty material test", empty_material, 32);

        if (key.size() != 32)
        {
            LogFail("empty material should still produce 32 bytes, got " + std::to_string(key.size()));
            return;
        }
    }
    catch (const std::exception &e)
    {
        LogFail(std::format("empty material threw exception: {}", e.what()));
        return;
    }

    LogPass("Blake3EmptyMaterial");
}

/**
 * @brief 测试空 context 不崩溃
 */
void TestBlake3EmptyContext()
{
    LogInfo("=== TestBlake3EmptyContext ===");

    try
    {
        const std::array<std::uint8_t, 4> material = {0x01, 0x02, 0x03, 0x04};
        auto key = psm::crypto::derive_key("", material, 32);

        if (key.size() != 32)
        {
            LogFail("empty context should still produce 32 bytes, got " + std::to_string(key.size()));
            return;
        }
    }
    catch (const std::exception &e)
    {
        LogFail(std::format("empty context threw exception: {}", e.what()));
        return;
    }

    LogPass("Blake3EmptyContext");
}

/**
 * @brief 测试入口
 * @details 初始化全局内存池和日志系统，运行 BLAKE3 密钥派生测试，输出结果。
 * @return 0 表示全部通过，1 表示存在失败
 */
int main()
{
#ifdef WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    LogInfo("Starting BLAKE3 tests...");

    TestBlake3DeriveKeyDeterministic();
    TestBlake3DifferentContextDifferentOutput();
    TestBlake3DifferentMaterialDifferentOutput();
    TestBlake3SpanVsVectorOverload();
    TestBlake3OutputLengthMatchesRequest();
    TestBlake3EmptyMaterial();
    TestBlake3EmptyContext();

    psm::trace::info("[Blake3] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}
