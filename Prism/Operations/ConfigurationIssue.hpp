/** @file ConfigurationIssue.hpp @brief 安全配置校验的字段与类别值，不拥有secret或执行域。 */
#pragma once
#include <string>
namespace Prism::Operations
{
    /** @brief 真实校验首因的公开字段；消息来自固定分类，不回显配置输入值。 */
    struct ConfigurationIssue final
    {
        std::string Code;
        std::string Path;
        std::string Message;
    };
}
