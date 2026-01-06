#pragma once

#include "deviant.hpp"

namespace ngx::abnormal
{
    /**
     * @brief 安全异常
     * @details 安全异常是指在程序运行过程中，由于安全原因而导致的异常情况。
     */
    class security : public exception
    {
    public:
        template <typename... Args>
        explicit security(std::format_string<Args...> fmt, Args&&... args)
            : exception(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {}

        template <typename... Args>
        explicit security(const std::source_location& loc, std::format_string<Args...> fmt, Args&&... args)
            : exception(loc, fmt, std::forward<Args>(args)...)
        {}

        explicit security(const std::string& msg,
                                const std::source_location& loc = std::source_location::current())
            : exception(loc, msg)
        {}

    protected:
        std::string_view type_name() const noexcept override { return "SECURITY"; }
    };
}
