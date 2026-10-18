/**
 * @file Error.hpp
 * @brief Error 子模块的值类型入口，转发 Expected.hpp 及其带出的 Error 枚举。
 * @details 唯一内容是指向 Prism/Foundation/Error/Expected.hpp 的 include，不声明新类型。
 *          Expected.hpp 再带 Code.hpp：那里拥有零值表示成功的 uint8 值错误 Error（InvalidArgument、
 *          InvalidDescriptor、Duplicate、MissingCapability、Frozen、NotFound、CallbackException 等）、
 *          ErrorCode 别名与 IsSuccess，并定义以该 Error 为失败值的 Expected 和 Status。
 *          失败全程按值返回给调用者，CallbackException 只用于把第三方异常在入口收口后表达为值。
 * @note 由 Foundation.hpp 聚合引入，是 Foundation 错误契约的统一入口。
 */

#pragma once

#include <Prism/Foundation/Error/Expected.hpp>
