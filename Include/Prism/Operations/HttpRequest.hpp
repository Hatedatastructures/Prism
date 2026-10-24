/**
 * @file HttpRequest.hpp
 * @brief 已解析 Operations HTTP 请求的借用视图。
 * @details 所有字符串视图均借用连接协程拥有的原始请求缓冲，只在该请求处理期间有效；
 *          本类型不拥有 socket、buffer 或路由状态。
 */

#pragma once

#include <cstddef>
#include <string_view>

namespace Prism::Operations
{
    /**
     * @brief 已解析管理请求的非拥有视图。
     * @details 调用者必须保证所有字段指向的原始请求缓冲活到路由 awaitable 完成；handler 不得
     *          把这些视图保存到后续请求或独立任务。
     */
    struct HttpRequest final
    {
        std::string_view Method{};
        std::string_view Target{};
        std::string_view Correlation{};
        std::string_view Host{};
        std::string_view Origin{};
        std::string_view Authorization{};
        std::string_view ContentType{};
        std::string_view Body{};
        std::size_t HeaderEnd{0};
        std::size_t ContentLength{0};
        bool ContentLengthSeen{false};
    };
}
