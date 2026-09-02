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
        None = 0,
        /// 缓冲区不足，需要更多数据（增量解析）
        NeedMore,
        /// 数据不足但流已关闭（对端提前断开）
        UnexpectedEof,
        /// 数据长度非法（超长 / 超短）
        BadLength,
        /// 协议魔数 / 版本不匹配
        BadMagic,
        /// 认证失败（口令 / UUID / 握手校验）
        BadAuth,
        /// 认证失败（BeastTest 兼容别名）
        AuthFailed,
        /// 版本不匹配（BeastTest 兼容别名）
        VersionMismatch,
        /// 不支持的特性（BeastTest 兼容别名）
        NotSupported,
        /// 消息语义非法（枚举值越界 / 标志位冲突）
        BadMessage,
        /// 目标地址非法（地址族 / 解析失败）
        BadAddress,
        /// 流未打开即执行读写
        NotOpen,
        /// 操作被取消（Cancel() / 对端关闭）
        Canceled,
        /// 读写超时
        Timeout,
        /// 对端已关闭写入侧（broken pipe）
        BrokenPipe,
        /// 协议内部状态机错误
        ProtocolError,
        /// 密钥派生失败（KDF 参数非法）
        KdfError,
        /// 不支持的特性（加密套件 / 命令类型）
        Unsupported,
        /// I/O 错误（底层传输失败）
        IoError,
    };

    namespace detail
    {
        /// 协议库错误分类器（Boost.System 接入点）
        class ProtocolCategory final : public boost::system::error_category
        {
        public:
            [[nodiscard]] auto name() const noexcept -> const char * override
            {
                return "prism.protocol";
            }

            [[nodiscard]] auto message(int ev) const -> std::string override
            {
                switch (static_cast<Error>(ev))
                {
                case Error::None: return "no Error";
                case Error::NeedMore: return "need more Data";
                case Error::UnexpectedEof: return "unexpected end of Stream";
                case Error::BadLength: return "bad Message length";
                case Error::BadMagic: return "bad magic or version";
                case Error::BadAuth: return "authentication Failed";
                case Error::AuthFailed: return "authentication Failed";
                case Error::VersionMismatch: return "version mismatch";
                case Error::NotSupported: return "not supported";
                case Error::BadMessage: return "malformed Message";
                case Error::BadAddress: return "invalid Target Address";
                case Error::NotOpen: return "Stream not Open";
                case Error::Canceled: return "operation canceled";
                case Error::Timeout: return "operation timed out";
                case Error::BrokenPipe: return "broken pipe";
                case Error::ProtocolError: return "Protocol State Error";
                case Error::KdfError: return "key derivation Failed";
                case Error::Unsupported: return "unsupported feature";
                case Error::IoError: return "io Error";
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

    // g++-13 的 std::operator==(const expected<_Tp,_Er>&, const _Up&) 约束过松，
    // 会与上方模板重载共同入围导致歧义（GCC 16 的约束已修复不受影响）。
    // 非模板精确重载在重载决议中必胜模板，跨编译器确定性地消除歧义。
    // 当前测试断言使用的值类型均为 std::size_t（Parse*/Decode*/Read* 的已消费字节数）；
    // 若未来引入其他 T 值，需照此追加对应实例。
    [[nodiscard]] inline auto operator==(const std::expected<std::size_t, Error>& e,
                                         Error code) noexcept -> bool
    {
        return !e.has_value() && e.error() == code;
    }

    [[nodiscard]] inline auto operator!=(const std::expected<std::size_t, Error>& e,
                                         Error code) noexcept -> bool
    {
        return !(!e.has_value() && e.error() == code);
    }

    [[nodiscard]] inline auto operator==(Error code,
                                         const std::expected<std::size_t, Error>& e) noexcept -> bool
    {
        return !e.has_value() && e.error() == code;
    }

    [[nodiscard]] inline auto operator!=(Error code,
                                         const std::expected<std::size_t, Error>& e) noexcept -> bool
    {
        return !(!e.has_value() && e.error() == code);
    }
} // namespace Preview
