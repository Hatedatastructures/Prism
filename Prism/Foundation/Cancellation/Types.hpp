/**
 * @file Types.hpp
 * @brief Cancellation 子模块的值类型入口，转发 Mode.hpp 的取消协作模式。
 * @details 唯一内容是指向 Prism/Foundation/Cancellation/Mode.hpp 的 include，不声明新类型。
 *          Mode.hpp 拥有 Prism::Cancellation::Mode（None、Cooperative、Required）及其 Policy、
 *          Value、CancellationMode 别名，并在 Prism 命名空间导出 CancellationMode。
 *          该枚举只表达回调对取消的协作要求，是纯值语义，不携带取消信号、executor 或资源所有权。
 * @note 由 Foundation.hpp 聚合引入；取消信号的实际发出与等待不属于本子模块。
 */

#pragma once

#include <Prism/Foundation/Cancellation/Mode.hpp>
