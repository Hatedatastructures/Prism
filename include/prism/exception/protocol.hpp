/**
 * @file protocol.hpp
 * @brief 协议异常定义
 * @details 定义了 protocol 异常类，用于处理协议解析、握手、格式验证等
 * 相关的协议层错误。错误范围包括解析错误（协议格式无效、字段缺失、
 * 长度溢出、编码错误）、握手错误（TLS 握手失败、协议版本不支持、
 * 密码套件不匹配）、状态错误（协议状态机违规、顺序错误、超时未响应）、
 * 格式错误（HTTP 头部格式错误、SOCKS5 命令不支持、Trojan 认证无效）、
 * 协商错误（ALPN 协商失败、扩展不支持、压缩算法冲突）。使用场景包括
 * 协议检测阶段发现非法协议格式、协议握手过程中遇到版本或能力不匹配、
 * 协议状态机执行时遇到非法状态转换、协议数据解析时遇到格式或语义错误。
 * 协议异常通常发生在连接建立初期，频率较低，性能影响有限。
 * @note 协议异常应主要用于协议栈的初始化和验证阶段，运行时协议错误
 * 应通过错误码机制处理。
 * @warning 避免在热路径（如数据转发循环）中抛出协议异常，这会导致
 * 性能下降和连接中断。
 */
#pragma once

#include <prism/exception/deviant.hpp>

namespace psm::exception
{
    /**
     * @class protocol
     * @brief 协议异常
     * @details 表示协议层相关的异常情况，继承自 exception::deviant。
     * 该异常类用于处理协议检测、握手、解析和状态机执行过程中的错误，
     * 确保协议栈的健壮性和可诊断性。错误范围包括解析错误、握手错误、
     * 状态错误、格式错误、协商错误。
     * @note 协议异常应主要用于协议栈的初始化和验证阶段，运行时协议错误
     * 应通过错误码机制处理。
     * @warning 避免在热路径（如数据转发循环）中抛出协议异常。
     * @warning 字符串和格式化构造函数将错误分类为 generic_error，
     * 建议迁移到错误码构造函数。
     */
    class protocol : public deviant
    {
    public:
        /**
         * @brief 构造函数（协议错误码）
         * @param err 协议错误码，必须为 psm::fault::code 枚举值
         * @param loc 源码位置，默认自动捕获
         * @details 使用 psm::fault::code 错误码构造协议异常。此构造函数
         * 将协议错误码转换为 std::error_code 并存储，同时自动捕获
         * 调用点的源码位置。这是推荐的构造函数，保留了完整的错误分类
         * 和源码位置信息。错误码转换通过 psm::fault::make_error_code()
         * 内联函数完成，无运行时开销。
         * @note 这是推荐的构造函数，保留了完整的错误分类和源码位置信息。
         */
        explicit protocol(psm::fault::code err,
                          const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), {}, loc)
        {
        }

        /**
         * @brief 构造函数（协议错误码 + 额外描述）
         * @param err 协议错误码，必须为 psm::fault::code 枚举值
         * @param desc 额外描述信息，提供错误上下文或详细说明
         * @param loc 源码位置，默认自动捕获
         * @details 使用 psm::fault::code 错误码和额外描述信息构造协议异常。
         * 此构造函数在保留错误分类的基础上，添加了人类可读的额外描述，
         * 便于调试和日志记录。额外描述信息不会影响错误分类，仅用于
         * 增强错误信息的可读性。描述字符串应以 UTF-8 编码，长度适中，
         * 避免包含敏感信息。
         * @note 额外描述信息不会影响错误分类，仅用于增强错误信息的可读性。
         */
        explicit protocol(psm::fault::code err, std::string_view desc,
                          const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), desc, loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息，提供人类可读的错误描述
         * @param loc 源码位置，默认自动捕获
         * @details 使用字符串消息构造协议异常，提供向后兼容性支持。
         * 此构造函数将字符串消息转换为 generic_error 错误码，丢失
         * 具体的错误分类信息。字符串消息将复制到异常内部，可能涉及
         * 堆分配，性能较低。
         * @note 此构造函数主要用于遗留代码迁移，新代码应使用错误码构造函数。
         * @warning 丢失错误分类信息，不利于错误统计和自动化处理。
         */
        explicit protocol(const std::string &msg,
                          const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，自动获取位置）
         * @tparam Args 格式化参数类型，必须与格式化字符串兼容
         * @param fmt 格式化字符串，遵循 std::format 语法
         * @param args 格式化参数，将按值转发给格式化引擎
         * @details 使用格式化字符串和参数构造协议异常，自动捕获调用点
         * 的源码位置。此构造函数将格式化结果转换为 generic_error 错误码，
         * 丢失具体的错误分类信息。格式化过程在构造函数内部完成，
         * 可能涉及临时字符串分配。
         * @note 此构造函数主要用于遗留代码迁移，新代码应使用错误码构造函数。
         * @warning 丢失错误分类信息，不利于错误统计和自动化处理。
         */
        template <typename... Args>
        explicit protocol(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，指定位置）
         * @tparam Args 格式化参数类型，必须与格式化字符串兼容
         * @param loc 源码位置，由调用者显式提供
         * @param fmt 格式化字符串，遵循 std::format 语法
         * @param args 格式化参数，将按值转发给格式化引擎
         * @details 使用格式化字符串、参数和指定的源码位置构造协议异常。
         * 此构造函数将格式化结果转换为 generic_error 错误码，丢失
         * 具体的错误分类信息。显式指定源码位置适用于包装函数或代理
         * 抛出场景。
         * @note 此构造函数主要用于遗留代码迁移，新代码应使用错误码构造函数。
         * @warning 丢失错误分类信息，不利于错误统计和自动化处理。
         */
        template <typename... Args>
        explicit protocol(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称，固定为 PROTOCOL 字符串视图
         * @details 重写基类 exception::deviant 的虚函数，返回协议异常
         * 的类型标识符。类型名称用于异常分类、日志记录和调试信息显示。
         * 返回值为字符串字面量视图，生命周期与程序相同。
         */
        [[nodiscard]] std::string_view type_name() const noexcept override { return "PROTOCOL"; }
    };
}
