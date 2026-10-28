/**
 * @file ExceptionCoverage.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ExceptionTestSupport.hpp"

TEST(ExceptionDeviant, AbstractBase)
    {
        // Deviant 为抽象基类：必须实现 TypeName() 才能实例化
        static_assert(std::is_abstract_v<exc::Deviant>);
        const exposed_deviant ex(fault::make_error_code(fault::Code::Eof));
        EXPECT_EQ(ex.TypeName(), "EXPOSED");
    }

TEST(ExceptionDeviant, ConstructWithCodeAndDesc)
    {
        // 错误码 + 描述：What() = "Message: desc"
        const exposed_deviant ex(fault::make_error_code(fault::Code::Eof), "Stream ended");
        EXPECT_EQ(std::string(ex.what()), "eof: Stream ended");
    }

TEST(ExceptionDeviant, ConstructWithCodeNoDesc)
    {
        // 仅错误码：What() = 错误码消息本身
        const exposed_deviant ex(fault::make_error_code(fault::Code::Timeout));
        EXPECT_EQ(std::string(ex.what()), "timeout");
    }

TEST(ExceptionDeviant, ConstructWithStringGenericError)
    {
        // 字符串构造：回退到 generic_error 错误码
        const exposed_deviant ex(std::string("legacy Message"));
        EXPECT_EQ(ex.ErrorCode().value(), static_cast<int>(fault::Code::GenericError));
        EXPECT_EQ(std::string(ex.what()), "generic_error: legacy Message");
    }

TEST(ExceptionDeviant, ConstructFormatted)
    {
        // 格式化构造：格式参数被替换
        const exposed_deviant ex(std::source_location::current(), "format Error {}", 42);
        EXPECT_EQ(std::string(ex.what()), "generic_error: format Error 42");
    }

TEST(ExceptionDeviant, ErrorCodeAccessors)
    {
        // ErrorCode() 保留值与分类
        const exposed_deviant ex(fault::make_error_code(fault::Code::ParseError), "bad");
        const auto &ec = ex.ErrorCode();
        EXPECT_EQ(ec.value(), static_cast<int>(fault::Code::ParseError));
        EXPECT_EQ(std::string_view(ec.category().name()), "Prism::fault");
        EXPECT_EQ(ec.message(), "parse_error");
    }

TEST(ExceptionDeviant, LocationAndFilename)
    {
        // 位置捕获：文件名、行号有效；Filename() 仅纯文件名
        const exposed_deviant ex(fault::make_error_code(fault::Code::Eof));
        const auto &loc = ex.Location();
        ASSERT_TRUE(loc.file_name());
        EXPECT_TRUE(Contains(std::string(loc.file_name()), "ExceptionCoverage"));
        EXPECT_GT(loc.line(), 0);

        const std::string fname = ex.Filename();
        EXPECT_EQ(fname, "ExceptionCoverage.cpp");
        EXPECT_EQ(fname.find('/'), std::string::npos);
        EXPECT_EQ(fname.find('\\'), std::string::npos);
    }

TEST(ExceptionDeviant, DumpExactFormat)
    {
        // Dump() 完整格式：[Filename:line] [TYPE:value] Message
        const exposed_deviant ex(fault::make_error_code(fault::Code::Eof), "Stream ended");
        const std::string expected = std::format("[{}:{}] [EXPOSED:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

TEST(ExceptionDeviant, CopySemantics)
    {
        // 拷贝：错误码、消息与 Dump 完全一致
        const exposed_deviant src(fault::make_error_code(fault::Code::ConnectionReset), "peer Reset");
        const exposed_deviant copied(src);
        EXPECT_EQ(copied.ErrorCode().value(), src.ErrorCode().value());
        EXPECT_STREQ(copied.what(), src.what());
        EXPECT_EQ(copied.Dump(), src.Dump());
    }

TEST(ExceptionDeviant, TypeNameOverride)
    {
        // 子类实现 TypeName()，Dump() 中体现
        const exposed_deviant ex(fault::make_error_code(fault::Code::Eof), "x");
        EXPECT_TRUE(Contains(ex.Dump(), "[EXPOSED:3]"));
    }

TEST(ExceptionNetwork, ConstructAllForms)
    {
        // 四种构造形态：错误码 / 错误码+描述 / 字符串 / 格式化
        const exc::Network by_code(fault::Code::Eof);
        EXPECT_EQ(std::string(by_code.what()), "eof");

        const exc::Network with_desc(fault::Code::Timeout, "handshake stalled");
        EXPECT_EQ(std::string(with_desc.what()), "timeout: handshake stalled");

        const exc::Network by_string(std::string("legacy net"));
        EXPECT_EQ(by_string.ErrorCode().value(), static_cast<int>(fault::Code::GenericError));
        EXPECT_EQ(std::string(by_string.what()), "generic_error: legacy net");

        const exc::Network formatted("net Fail {}", 7);
        EXPECT_EQ(std::string(formatted.what()), "generic_error: net Fail 7");

        const exc::Network formatted_loc(std::source_location::current(), "net Fail {}", 8);
        EXPECT_EQ(std::string(formatted_loc.what()), "generic_error: net Fail 8");
    }

TEST(ExceptionNetwork, TypeName)
    {
        const exposed_network ex(fault::Code::DnsFailed, "resolve Fail");
        EXPECT_EQ(ex.TypeName(), "NETWORK");
        EXPECT_TRUE(Contains(ex.Dump(), "NETWORK"));
    }

TEST(ExceptionNetwork, DumpFormat)
    {
        const exc::Network ex(fault::Code::ConnectionRefused, "refused");
        const std::string expected = std::format("[{}:{}] [NETWORK:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

TEST(ExceptionProtocol, ConstructCodeAndDesc)
    {
        const exc::Protocol by_code(fault::Code::ParseError);
        EXPECT_EQ(std::string(by_code.what()), "parse_error");
        EXPECT_EQ(by_code.ErrorCode().value(), static_cast<int>(fault::Code::ParseError));

        const exc::Protocol with_desc(fault::Code::BadMessage, "malformed Header");
        EXPECT_EQ(std::string(with_desc.what()), "bad_message: malformed Header");

        const exc::Protocol formatted("proto Fail {}", 3);
        EXPECT_EQ(std::string(formatted.what()), "generic_error: proto Fail 3");
    }

TEST(ExceptionProtocol, TypeName)
    {
        const exposed_protocol ex(fault::Code::ProtocolError, "State Error");
        EXPECT_EQ(ex.TypeName(), "PROTOCOL");
        EXPECT_TRUE(Contains(ex.Dump(), "PROTOCOL"));
    }

TEST(ExceptionProtocol, DumpFormat)
    {
        const exc::Protocol ex(fault::Code::ParseError, "bad Frame");
        const std::string expected = std::format("[{}:{}] [PROTOCOL:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

TEST(ExceptionSecurity, WhatGenericForSecurityCode)
    {
        // 认证失败异常：What() 仅含通用错误文本，不泄露任何凭据细节
        const exc::Security ex(fault::Code::AuthFailed);
        EXPECT_EQ(std::string(ex.what()), "auth_failed");
        EXPECT_EQ(ex.ErrorCode().message(), "auth_failed");
    }

TEST(ExceptionSecurity, ErrorCodeMessageNotContainingDesc)
    {
        // 描述包含敏感内容时，ErrorCode() 消息保持通用（描述仅出现在 What()）
        const exc::Security ex(fault::Code::AuthFailed, "user 'admin' rejected");
        EXPECT_EQ(ex.ErrorCode().message(), "auth_failed")
            << "Error Code Message must not carry user-provided details";
        EXPECT_TRUE(Contains(std::string(ex.what()), "user 'admin' rejected"));
    }

TEST(ExceptionSecurity, DumpNoPathLeak)
    {
        // Dump() 仅含纯文件名，不泄露构建路径等内部信息
        const exc::Security ex(fault::Code::AuthFailed, "rejected");
        const std::string Dump = ex.Dump();
        EXPECT_EQ(Dump.find('/'), std::string::npos);
        EXPECT_EQ(Dump.find('\\'), std::string::npos);
        EXPECT_TRUE(Contains(Dump, "ExceptionCoverage.cpp"));
    }

TEST(ExceptionSecurity, TypeName)
    {
        const exposed_security ex(fault::Code::Verifyfail, "cert invalid");
        EXPECT_EQ(ex.TypeName(), "SECURITY");
        EXPECT_TRUE(Contains(ex.Dump(), "SECURITY"));
    }

TEST(ExceptionSecurity, DumpFormat)
    {
        const exc::Security ex(fault::Code::AuthFailed, "login denied");
        const std::string expected = std::format("[{}:{}] [SECURITY:{}] {}", ex.Filename(),
                                                 ex.Location().line(), ex.ErrorCode().value(),
                                                 ex.what());
        EXPECT_EQ(ex.Dump(), expected);
    }

