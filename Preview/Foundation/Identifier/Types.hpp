/**
 * @file Types.hpp
 * @brief Identifier 的值类型入口，转发 Id.hpp 的强类型数值与文本标识符。
 * @details 唯一内容是指向 Preview/Foundation/Identifier/Id.hpp 的 include，不声明新类型。
 *          Id.hpp 拥有 Id<Tag> 与 TextId<Tag> 模板、成对的 Tag 结构体，以及 BuiltinId、SnapshotId、
 *          BuiltinSnapshotId、RequestId、GenerationId、ProcessId、WorkerId、SessionId、StreamId、
 *          TaskId、OperationId、AccountId、KindId、NameId 别名，并在 Preview 命名空间逐项导出。
 *          本头不引入哈希、分配或比较策略，标识符仍是可自由复制的纯值。
 * @note 由 Identifier.hpp 聚合后经 Foundation.hpp 引入，供各层类型化身份与注册键使用。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
