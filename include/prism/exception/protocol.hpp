/**
 * @file protocol.hpp
 * @brief 协议异常定义
 * @details 定义 protocol 异常类，用于处理协议解析、
 * 握手、格式验证等协议层错误。错误范围包括解析错误、
 * 握手错误、状态错误、格式错误和协商错误。
 * @note 协议异常应主要用于协议栈的初始化和验证阶段，
 * 运行时协议错误应通过错误码机制处理。
 * @warning 避免在热路径中抛出协议异常。
 */
#pragma once

#include <prism/exception/deviant.hpp>

namespace psm::exception
{
    /**
     * @class protocol
     * @brief 协议异常
     * @details 表示协议层相关的异常情况，继承自
     * exception::deviant。用于处理协议检测、握手、
     * 解析和状态机执行过程中的错误。
     * @note 协议异常应主要用于协议栈的初始化和验证
     * 阶段，运行时协议错误应通过错误码机制处理。
     * @warning 字符串和格式化构造函数将错误分类为
     * generic_error，建议迁移到错误码构造函数。
     */
    class protocol : public deviant
    {
    public:
        /**
         * @brief 构造函数（协议错误码）
         * @param err 协议错误码，必须为 fault::code 枚举值
         * @param loc 源码位置，默认自动获取
         * @details 使用 fault::code 错误码构造协议异常，
         * 自动捕获调用点的源码位置。这是推荐的构造函数，
         * 保留完整的错误分类和源码位置信息。
         */
        explicit protocol(psm::fault::code err,
                          const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), {}, loc)
        {
        }

        /**
         * @brief 构造函数（协议错误码 + 额外描述）
         * @param err 协议错误码，必须为 fault::code 枚举值
         * @param desc 额外描述信息，提供错误上下文
         * @param loc 源码位置，默认自动获取
         * @details 在保留错误分类的基础上，添加人类可读
         * 的额外描述，便于调试和日志记录。
         */
        explicit protocol(psm::fault::code err, std::string_view desc,
                          const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), desc, loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息
         * @param loc 源码位置，默认自动获取
         * @details 将字符串转换为 generic_error 错误码，
         * 丢失错误分类信息，建议迁移到错误码构造函数。
         */
        explicit protocol(const std::string &msg,
                          const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，自动获取位置）
         * @tparam Args 格式化参数类型
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 将格式化结果转换为 generic_error 错误码，
         * 丢失错误分类信息，建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit protocol(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，指定位置）
         * @tparam Args 格式化参数类型
         * @param loc 源码位置，由调用者显式提供
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 将格式化结果转换为 generic_error 错误码，
         * 丢失错误分类信息，建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit protocol(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称，固定为 PROTOCOL
         * @details 重写基类的虚函数，返回协议异常的
         * 类型标识符，用于异常分类和日志记录。
         */
        [[nodiscard]] std::string_view type_name() const noexcept override { return "PROTOCOL"; }
    }; // class protocol
} // namespace psm::exception
