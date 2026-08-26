/**
 * @file Deviant.hpp
 * @brief 异常基类定义
 * @details 定义所有自定义异常的基类，支持源位置捕获
 * 和格式化消息。基于 std::error_code 架构，提供结构化
 * 异常信息。遵循热路径无异常原则，仅用于启动阶段
 * 配置错误或致命错误，热路径应使用错误码。
 * @note 所有自定义异常应继承自 Exception::Deviant 并
 * 实现 TypeName()。
 * @warning 异常构造和复制可能分配内存，避免在内存紧张
 * 时使用。
 * @note 镜像自 include/prism/foundation/exception/，同步策略：锁定
 */
#pragma once

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Fault/Compatible.hpp>

#include <filesystem>
#include <format>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

namespace Preview::Exception
{

    /**
     * @class Deviant
     * @brief 项目异常基类
     * @details 继承自 std::runtime_error，核心存储
     * std::error_code，自动捕获抛出点的位置信息，
     * 并支持格式化消息。该类是抽象基类，强制子类
     * 提供类型分类。
     * @note 该类是抽象基类，不能直接实例化。
     * @warning 异常对象可能较大，包含字符串和位置
     * 信息。
     */
    class Deviant : public std::runtime_error
    {
    public:
        /**
         * @brief 主构造函数（错误码 + 可选描述）
         * @param ec 错误码
         * @param desc 可选描述信息
         * @param loc 源码位置，默认自动获取
         * @details 使用错误码和可选描述构造异常，
         * 自动捕获抛出点的源码位置。这是异常构造
         * 的首选方式，提供结构化的错误信息。
         */
        explicit Deviant(std::error_code ec, std::string_view desc = {},
                         const std::source_location &loc = std::source_location::current())
            : std::runtime_error(CreateWhat(ec, desc)), Ec_(ec), Location_(loc)
        {
        }

        /**
         * @brief 构造函数（向后兼容字符串）
         * @param msg 错误消息
         * @param loc 源码位置，默认自动获取
         * @details 将字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         */
        explicit Deviant(const std::string &msg,
                         const std::source_location &loc = std::source_location::current())
            : Deviant(std::error_code(static_cast<int>(Fault::Code::GenericError), Fault::Category()), msg,
                      loc)
        {
        }

        /**
         * @brief 构造函数（带格式化参数）
         * @tparam Args 参数类型
         * @param loc 源码位置，默认自动获取
         * @param fmt 格式化字符串
         * @param args 格式化参数
         * @details 将格式化字符串转换为 generic_error 错误码，
         * 建议迁移到错误码构造函数。
         */
        template <typename... Args>
        explicit Deviant(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args)
            : Deviant(std::format(fmt, std::forward<Args>(args)...), loc)
        {
        }

        /**
         * @brief 获取异常的错误码
         * @return 错误码引用
         */
        [[nodiscard]] auto ErrorCode() const noexcept -> const std::error_code &
        {
            return Ec_;
        }

        /**
         * @brief 获取异常抛出时的位置信息
         * @return 包含文件名、行号、列号等位置信息
         */
        [[nodiscard]] auto Location() const noexcept -> const std::source_location &
        {
            return Location_;
        }

        /**
         * @brief 获取异常抛出时的文件名
         * @return 文件名，不包含路径
         */
        [[nodiscard]] auto Filename() const -> std::string
        {
            return std::filesystem::path(Location_.file_name()).filename().string();
        }

        /**
         * @brief 格式化异常信息
         * @return 格式化后的异常信息
         * @details 生成包含文件名、行号、异常类型、错误码
         * 和错误描述的详细字符串。输出格式为
         * [Filename:line] [TYPE:value] description。
         */
        [[nodiscard]] virtual auto Dump() const -> std::string
        {
            return std::format("[{}:{}] [{}:{}] {}", Filename(), Location_.line(), TypeName(), Ec_.value(),
                               std::runtime_error::what());
        }

    protected:
        /**
         * @brief 获取异常类型名称
         * @return 异常类型名称
         * @details 子类必须实现此方法，返回自己的类型名称，
         * 如 SECURITY、NETWORK。
         */
        [[nodiscard]] virtual auto TypeName() const noexcept -> std::string_view = 0;

    private:
        /**
         * @brief 构建 What() 字符串
         * @param ec 错误码
         * @param desc 额外描述
         * @return 组合后的错误消息
         */
        [[nodiscard]] static auto CreateWhat(const std::error_code &ec, std::string_view desc) -> std::string
        {
            if (desc.empty())
            {
                return ec.message();
            }
            return std::format("{}: {}", ec.message(), desc);
        }

        std::error_code Ec_;            // 错误码
        std::source_location Location_; // 异常发生的位置
    }; // class Deviant
} // namespace Preview::Exception
