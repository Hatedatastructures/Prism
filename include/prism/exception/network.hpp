/**
 * @file network.hpp
 * @brief 网络异常定义
 * @details 定义了 network 异常类，用于处理网络相关的错误。该异常类
 * 表示网络层错误，如连接失败、超时、DNS 解析错误、TCP 重置等。
 * 遵循异常使用原则，仅用于启动阶段网络配置错误，运行时网络错误
 * 应使用错误码。典型应用场景包括启动时监听端口绑定失败、SSL 上下文
 * 初始化失败、配置文件中的网络地址格式错误、反向代理后端服务器
 * 不可达（启动阶段检查）。错误码映射使用 psm::fault::code 中的
 * 网络相关错误码，如 connection_refused、connection_reset、
 * connection_aborted、timeout、host_unreachable、network_unreachable、
 * io_error、eof、canceled 等。
 * @note 运行时网络 I/O 错误（如读/写失败）应使用错误码而非异常。
 * @warning 不要在热路径（如 async_read 回调）中抛出此异常。
 */
#pragma once

#include <prism/exception/deviant.hpp>

namespace psm::exception
{
    /**
     * @class network
     * @brief 网络异常
     * @details 表示网络层相关的异常情况，继承自 exception::deviant。
     * 该异常类用于处理网络配置和初始化阶段的错误，运行时网络错误
     * 应使用错误码。错误范围包括连接错误（连接拒绝、连接重置、
     * 连接中止）、超时错误（操作超时、读写超时）、可达性错误
     * （主机不可达、网络不可达）、资源错误（缓冲区不足、端口不可用）、
     * 协议错误（TLS 握手失败、SSL 证书错误）。
     * @note 类型名称为 NETWORK，在 dump() 输出中标识异常分类。
     * @warning 异常构造可能分配内存，避免在内存紧张的网络回调中使用。
     * @throws 构造函数可能抛出 std::bad_alloc（如果内存分配失败）。
     */
    class network : public deviant
    {
    public:
        /**
         * @brief 构造函数（网络错误码）
         * @param err 网络错误码
         * @param loc 源码位置（默认自动获取）
         */
        explicit network(const fault::code err,
                         const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), {}, loc)
        {
        }

        /**
         * @brief 构造函数（网络错误码 + 额外描述）
         * @param err 网络错误码
         * @param desc 额外描述信息
         * @param loc 源码位置（默认自动获取）
         */
        explicit network(const fault::code err, std::string_view desc,
                         const std::source_location &loc = std::source_location::current())
            : deviant(psm::fault::make_error_code(err), desc, loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息
         * @param loc 源码位置（默认自动获取）
         * @details 此构造函数将字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         * @note 建议迁移到错误码构造函数。
         */
        explicit network(const std::string &msg,
                         const std::source_location &loc = std::source_location::current())
            : deviant(msg, loc)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，自动获取位置）
         * @tparam Args 格式化参数类型
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 此构造函数将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         * @note 建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit network(std::format_string<Args...> fmt, Args &&...args)
            : deviant(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {
        }

        /**
         * @brief 构造函数（带格式化参数，指定位置）
         * @tparam Args 格式化参数类型
         * @param loc 源码位置
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 此构造函数将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         * @note 建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit network(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : deviant(loc, fmt, std::forward<Args>(args)...)
        {
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称，固定为 NETWORK 字符串视图
         * @details 重写基类 exception::deviant 的虚函数，返回网络异常
         * 的类型标识符。类型名称用于异常分类、日志记录和调试信息显示。
         * 返回值为字符串字面量视图，生命周期与程序相同。
         */
        [[nodiscard]] std::string_view type_name() const noexcept override { return "NETWORK"; }
    };
}
