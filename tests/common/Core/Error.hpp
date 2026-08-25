/**
 * @file Error.hpp
 * @brief 协议库统一错误码体系
 * @details 借鉴 Boost.Beast 的错误处理风格：轻量错误码 + 分类器，
 *          热路径编解码失败返回错误码而非抛异常。
 *          分类（Error::Category）可被 Boost.System 识别，
 *          与 std::error_code / boost::system::error_code 双向兼容。
 * @note 所有协议子库的错误均收敛到本文件，禁止各自造错误码。
 */

#pragma once

#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <string>
#include <expected>
#include <system_error>

namespace Preview
{

    /// 错误分类：协议、传输、编码解码、密钥派生
    enum class Error
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
        /// 操作被取消（Cancel() / 对端关闭）
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
        /// I/O 错误（底层传输失败）
        io_error,
    };

    namespace detail
    {
        /// 协议库错误分类器（Boost.System 接入点）
        class ProtocolCategory final : public boost::system::error_category
        {
        public:
            [[nodiscard]] auto name() const noexcept -> const char * override
            {
                return "preview.protocol";
            }

            [[nodiscard]] auto message(int ev) const -> std::string override
            {
                switch (static_cast<Error>(ev))
                {
                case Error::none: return "no Error";
                case Error::need_more: return "need more Data";
                case Error::unexpected_eof: return "unexpected end of Stream";
                case Error::bad_length: return "bad Message length";
                case Error::bad_magic: return "bad magic or version";
                case Error::bad_auth: return "authentication Failed";
                case Error::auth_failed: return "authentication Failed";
                case Error::version_mismatch: return "version mismatch";
                case Error::not_supported: return "not supported";
                case Error::bad_message: return "malformed Message";
                case Error::bad_address: return "invalid Target Address";
                case Error::not_open: return "Stream not Open";
                case Error::canceled: return "operation canceled";
                case Error::timeout: return "operation timed out";
                case Error::broken_pipe: return "broken pipe";
                case Error::protocol_error: return "Protocol State Error";
                case Error::kdf_error: return "key derivation Failed";
                case Error::unsupported: return "unsupported feature";
                case Error::io_error: return "io Error";
                }
                return "unknown Protocol Error";
            }
        };
    } // namespace detail

    /**
     * @brief 获取协议库错误分类器
     * @return 协议库错误分类器（const 引用）
     */
    [[nodiscard]] inline auto ErrorCategory() noexcept 
        -> const boost::system::error_category &
    {
        static const detail::ProtocolCategory Category;
        return Category;
    }

    /**
     * @brief 构造协议错误码（Beast 风格：make_error_code 重载支持）
     * @param e 协议错误枚举值
     * @return 对应的 boost::system::error_code
     */
    [[nodiscard]] inline auto make_error_code(Error e) noexcept 
        -> boost::system::error_code
    {
        return {static_cast<int>(e), ErrorCategory()};
    }

    /// 协议错误码别名（协程返回值常用）
    using ProtocolEc = boost::system::error_code;

} // namespace Preview

/// 使 Error 枚举可隐式转换为 ErrorCode（std::error_code 场景）
template <>
struct std::is_error_code_enum<Preview::Error> : std::true_type
{
};

/// 使 Error 枚举可隐式转换为 boost::system::error_code
namespace boost::system
{
    template <>
    struct is_error_code_enum<Preview::Error> : std::true_type
    {
    };
} // namespace boost::system

namespace Preview
{
    /// @brief expected<T, Error> 与 Error 枚举的 gtest 断言比较重载
    ///        （ADL 经 Preview 命名空间命中，供 EXPECT_EQ/EXPECT_NE 直接使用）。
    ///        engaged（成功态）不等于任何错误码；errored 态按 error() 值比较。
    template <typename T>
    [[nodiscard]] auto operator==(const std::expected<T, Error>& e, Error code) -> bool
    {
        return !e.has_value() && e.error() == code;
    }

    template <typename T>
    [[nodiscard]] auto operator!=(const std::expected<T, Error>& e, Error code) -> bool
    {
        return !(e == code);
    }

    template <typename T>
    [[nodiscard]] auto operator==(Error code, const std::expected<T, Error>& e) -> bool
    {
        return e == code;
    }

    template <typename T>
    [[nodiscard]] auto operator!=(Error code, const std::expected<T, Error>& e) -> bool
    {
        return !(e == code);
    }
} // namespace Preview