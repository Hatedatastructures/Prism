/**
 * @file RecognitionProtocolTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "RecognitionTestSupport.hpp"

TEST(RecognitionProtocol, Socks5Detect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x05})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x01})), Prism::Contract::ProtocolType::Socks5);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x10})), Prism::Contract::ProtocolType::Socks5);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x00})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x05, 0x11})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_TRUE(rec::CouldBeProtocolPrefix(BytesOf({0x05})));
    EXPECT_FALSE(rec::CouldBeProtocolPrefix(BytesOf({0x05, 0x00})));
    EXPECT_FALSE(rec::CouldBeProtocolPrefix(BytesOf({0x05, 0x11})));
}

TEST(RecognitionProtocol, TlsDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x16, 0x03})), Prism::Contract::ProtocolType::Tls);
    EXPECT_EQ(rec::Detect(BytesOf({0x16, 0x01})), Prism::Contract::ProtocolType::Unknown);
}

TEST(RecognitionStatus, HasStableDiagnosticStrings)
{
    ExpectRecognitionStatusStrings<rec::RecognitionStatus>();
}

TEST(RecognitionProtocol, VlessDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x56, 0x4C, 0x45, 0x53, 0x53})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x56, 0x4C})), Prism::Contract::ProtocolType::Unknown);
    // 结构化识别：version 0x00 + AddnlLen 0 + cmd Tcp + atyp domain
    std::vector<std::uint8_t> wire = {
        0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // version + uuid
        0x00,             // AddnlLen
        0x01,             // cmd Tcp
        0x00, 0x50,       // port 80
        0x02,             // atyp domain
    };
    EXPECT_EQ(rec::Detect(wire), Prism::Contract::ProtocolType::Vless);
    // cmd 非法 → 不识别
    auto bad = wire;
    bad[18] = 0x09;
    EXPECT_EQ(rec::Detect(bad), Prism::Contract::ProtocolType::Unknown);
    // cmd=0x7f（mux）不在结构化识别白名单：mux 会话首包不可与 Tcp/udp
    // 区分数据面，识别层保守拒绝，由魔数/协议层自行处理
    auto mux_cmd = wire;
    mux_cmd[18] = 0x7f;
    EXPECT_EQ(rec::Detect(mux_cmd), Prism::Contract::ProtocolType::Unknown);
    // AddnlLen 非零 → 不识别
    auto bad2 = wire;
    bad2[17] = 0x01;
    EXPECT_EQ(rec::Detect(bad2), Prism::Contract::ProtocolType::Unknown);
    // atyp 非法 → 不识别
    auto bad3 = wire;
    bad3[21] = 0x09;
    EXPECT_EQ(rec::Detect(bad3), Prism::Contract::ProtocolType::Unknown);
    // 不足 22 字节 → 不识别
    EXPECT_EQ(rec::Detect(BytesOf({0x00, 1, 2, 3})), Prism::Contract::ProtocolType::Unknown);
    // 21 字节（边界下沿）→ 不识别
    std::vector<std::uint8_t> boundary(21, 0x00);
    boundary[0] = 0x00;
    boundary[17] = 0x00;
    boundary[18] = 0x01;
    boundary[21 - 1] = 0x01;
    EXPECT_EQ(rec::Detect(boundary), Prism::Contract::ProtocolType::Unknown);
}

TEST(RecognitionProtocol, TrojanDetectDoesNotGuessCrlfPrefix)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x0D, 0x0A, 0x0D, 0x0A})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_FALSE(rec::CouldBeProtocolPrefix(BytesOf({0x0D, 0x0A, 0x0D, 0x0A})));
}

TEST(RecognitionProtocol, VmessDetectDoesNotGuessRandomPrefix)
{
    EXPECT_EQ(rec::Detect(BytesOf({0x01})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect(BytesOf({0x01, 0x00, 0x00, 0x00, 0x00, 0x42})),
              Prism::Contract::ProtocolType::Unknown);
}

TEST(RecognitionProtocol, HttpDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({'G', 'E', 'T', ' '})), Prism::Contract::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'C', 'O', 'N', 'N', 'E', 'C', 'T', ' '})), Prism::Contract::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '})), Prism::Contract::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'T', 'R', 'A', 'C', 'E', ' '})), Prism::Contract::ProtocolType::Http);
    EXPECT_EQ(rec::Detect(BytesOf({'P', 'A', 'T', 'C', 'H', ' '})), Prism::Contract::ProtocolType::Http);
}

TEST(RecognitionProtocol, UnknownDetect)
{
    EXPECT_EQ(rec::Detect(BytesOf({0xAA, 0xBB})), Prism::Contract::ProtocolType::Unknown);
    EXPECT_EQ(rec::Detect({}), Prism::Contract::ProtocolType::Unknown);
}
