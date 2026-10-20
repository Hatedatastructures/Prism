/**
 * @file Operation.hpp
 * @brief 密码学原生失败与临时秘密清理。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Utility/Crypto/SecretScope.hpp>
#include <string>
#include <system_error>

namespace Prism::Crypto::Detail
{
    /** @brief 保留 BoringSSL 错误编号的进程生命周期分类。 */
    class NativeCategory final : public std::error_category
    {
    public:
        /** @brief 标准库分类接口；返回静态名称。 */
        [[nodiscard]] auto name() const noexcept -> const char * override
        {
            return "Prism.Crypto.BoringSSL";
        }

        /** @brief 仅显式诊断时格式化原生错误；密码学热路径不调用。 */
        [[nodiscard]] auto message(int Value) const -> std::string override;
    };

    /** @brief 获取当前失败并清空已消费错误；仅紧接失败的原生调用使用。 */
    [[nodiscard]] auto NativeFailure(Fault::Code Code) noexcept -> Fault::Failure;

}
