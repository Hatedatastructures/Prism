/**
 * @file error.hpp
 * @brief 协议库统一错误码体系
 * @details 借鉴 Boost.Beast 的错误处理风格：轻量错误码 + 分类器，
 *          热路径编解码失败返回错误码而非抛异常。
 *          分类（error::category）可被 Boost.System 识别，
 *          与 std::error_code / boost::system::error_code 双向兼容。
 * @note 所有协议子库的错误均收敛到本文件，禁止各自造错误码。
 */

#pragma once

#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <system_error>
#include <string>

namespace psmtest
{

    /// 错误分类：协议、传输、编码解码、密钥派生
    enum class error
    {
        /// 无错误
        none = 0,
        /// 缓冲区不足，需要更多数据（增量解析）
        need_more,
        /// 数据不足但流已关闭（对端提前断开）
        unexpected_eof,
        /// 数据长度非法（超长 / 超短）
        bad_length,
        /// 协议魔数 / 版本不匹配
        bad_magic,
        /// 认证失败（口令 / UUID / 握手校验）
        bad_auth,
        /// 认证失败（BeastTest 兼容别名）
        auth_failed,
        /// 版本不匹配（BeastTest 兼容别名）
        version_mismatch,
        /// 不支持的特性（BeastTest 兼容别名）
        not_supported,
        /// 消息语义非法（枚举值越界 / 标志位冲突）
        bad_message,
        /// 目标地址非法（地址族 / 解析失败）
        bad_address,
        /// 流未打开即执行读写
        not_open,
        /// 操作被取消（cancel() / 对端关闭）
        canceled,
        /// 读写超时
        timeout,
        /// 对端已关闭写入侧（broken pipe）
        broken_pipe,
        /// 协议内部状态机错误
        protocol_error,
        /// 密钥派生失败（KDF 参数非法）
        kdf_error,
        /// 不支持的特性（加密套件 / 命令类型）
        unsupported,
    };

    namespace detail
    {
        /// 协议库错误分类器（Boost.System 接入点）
        class protocol_category final : public boost::system::error_category
        {
        public:
            [[nodiscard]] auto name() const noexcept -> const char * override
            {
                return "psmtest.protocol";
            }

            [[nodiscard]] auto message(int ev) const -> std::string override
            {
                switch (static_cast<error>(ev))
                {
                    case error::none:
                        return "no error";
                    case error::need_more:
                        return "need more data";
                    case error::unexpected_eof:
                        return "unexpected end of stream";
                    case error::bad_length:
                        return "bad message length";
                    case error::bad_magic:
                        return "bad magic or version";
                    case error::bad_auth:
                        return "authentication failed";
                    case error::auth_failed:
                        return "authentication failed";
                    case error::version_mismatch:
                        return "version mismatch";
                    case error::not_supported:
                        return "not supported";
                    case error::bad_message:
                        return "malformed message";
                    case error::bad_address:
                        return "invalid target address";
                    case error::not_open:
                        return "stream not open";
                    case error::canceled:
                        return "operation canceled";
                    case error::timeout:
                        return "operation timed out";
                    case error::broken_pipe:
                        return "broken pipe";
                    case error::protocol_error:
                        return "protocol state error";
                    case error::kdf_error:
                        return "key derivation failed";
                    case error::unsupported:
                        return "unsupported feature";
                }
                return "unknown protocol error";
            }
        };
    } // namespace detail

    /// 获取协议库错误分类器
    [[nodiscard]] inline auto error_category() noexcept -> const boost::system::error_category &
    {
        static const detail::protocol_category category;
        return category;
    }

    /// 构造协议错误码（Beast 风格：make_error_code 重载支持）
    [[nodiscard]] inline auto make_error_code(error e) noexcept -> boost::system::error_code
    {
        return {static_cast<int>(e), error_category()};
    }

    /// 协议错误码别名（协程返回值常用）
    using protocol_ec = boost::system::error_code;

} // namespace psmtest

/// 使 error 枚举可隐式转换为 error_code（std::error_code 场景）
template <>
struct std::is_error_code_enum<psmtest::error> : std::true_type
{
};

/// 使 error 枚举可隐式转换为 boost::system::error_code
namespace boost::system
{
    template <>
    struct is_error_code_enum<psmtest::error> : std::true_type
    {
    };
} // namespace boost::system
