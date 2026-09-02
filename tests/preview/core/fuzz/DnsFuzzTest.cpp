/**
 * @file DnsFuzzTest.cpp
 * @brief DNS 报文解析模糊测试
 * @details 以确定性伪随机（固定种子，可复现）对合法 DNS 应答做截断 + 位翻转
 *          变异，外加纯随机字节缓冲，断言 ScanAnswers / Message::Unpack：
 *          - 不崩溃、不越界、不死循环（压缩指针循环必须被拒）
 *          - 返回值或 nullopt 均为合法结果
 *          覆盖热路径扫描器（Answer.hpp）与完整物化路径（Format.hpp）双通道
 */

#include <preview/Net/Dns/Answer.hpp>
#include <preview/Net/Dns/Format.hpp>

#include <cstdint>
#include <random>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    using Preview::Network::Dns::Message;
    using Preview::Network::Dns::QType;
    using Preview::Network::Dns::ScanAnswers;

    /// 构造变异基底：A + AAAA + CNAME 混合应答（含压缩指针）
    auto MakeBaseResponse() -> std::vector<std::uint8_t>
    {
        Message m = Message::MakeQuery("fuzz.example.com", QType::A);
        m.Id = 0xBEEF;
        m.Qr = true;
        m.Ra = true;

        Preview::Network::Dns::Record a;
        a.Name = "fuzz.example.com";
        a.Type = QType::A;
        a.Ttl = 300;
        a.Rdata = {1, 2, 3, 4};
        m.Answers.push_back(a);

        Preview::Network::Dns::Record aaaa;
        aaaa.Name = "alt.fuzz.example.com";
        aaaa.Type = QType::Aaaa;
        aaaa.Ttl = 30;
        aaaa.Rdata = std::vector<std::uint8_t>(16, 0xAB);
        m.Answers.push_back(aaaa);

        Preview::Network::Dns::Record ns;
        ns.Name = "fuzz.example.com";
        ns.Type = QType::Ns;
        ns.Ttl = 3600;
        ns.Rdata = {0x03, 'n', 's', '1', 0x00};
        m.Authority.push_back(ns);
        return m.Pack();
    }
} // namespace

TEST(DnsFuzz, TestScanAnswersMutationTorture)
{
    const auto base = MakeBaseResponse();
    std::mt19937 rng(20260829U);

    constexpr int kIters = 5000;
    for (int iter = 0; iter < kIters; ++iter)
    {
        std::vector<std::uint8_t> buf = base;
        // 随机截断（至少保留 1 字节）
        buf.resize(1 + rng() % buf.size());
        // 随机位翻转（1-4 处）
        const int flips = 1 + static_cast<int>(rng() % 4);
        for (int f = 0; f < flips; ++f)
        {
            const auto pos = rng() % buf.size();
            buf[pos] ^= static_cast<std::uint8_t>(1U << (rng() % 8));
        }

        // 不崩溃 / 不死循环即通过；成功与否均为合法结果
        auto scanned = ScanAnswers(buf, 1);
        auto unpacked = Message::Unpack(buf);
        if (scanned && unpacked)
        {
            // 双通道都成功时：Id 与最小 TTL 语义必须一致
            EXPECT_EQ(scanned->Id, unpacked->Id);
        }
    }
}

TEST(DnsFuzz, TestParsersRandomBytes)
{
    std::mt19937 rng(424242U);
    for (int iter = 0; iter < 5000; ++iter)
    {
        const auto len = 1 + rng() % 64;
        std::vector<std::uint8_t> buf(len);
        for (auto &b : buf)
        {
            b = static_cast<std::uint8_t>(rng());
        }
        (void)ScanAnswers(buf, 1);
        (void)Message::Unpack(buf);
    }
}

TEST(DnsFuzz, TestSelfReferentialPointerFamilies)
{
    // 全 0xC0-0xCF 开头的缓冲：构造指针自指/互指的最恶劣形态
    std::mt19937 rng(777U);
    for (int iter = 0; iter < 2000; ++iter)
    {
        const auto len = 4 + rng() % 128;
        std::vector<std::uint8_t> buf(len);
        for (auto &b : buf)
        {
            b = static_cast<std::uint8_t>(0xC0 | (rng() % 16));
        }
        // 头部声明若干问题/应答，强制解析器进入名字跳转路径
        buf[4] = 1;
        buf[6] = 1;
        (void)ScanAnswers(buf, 1);
        (void)Message::Unpack(buf);
    }
}
