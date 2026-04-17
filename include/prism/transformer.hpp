/**
 * @file transformer.hpp
 * @brief Transformer 模块聚合头文件
 * @details 聚合引入数据转换层的所有实现，包含 JSON
 * 序列化与反序列化（json）子模块。提供统一的 JSON
 * 转换接口，是配置加载和状态持久化的基础设施。
 * 基于 glaze 库实现类型安全和零拷贝解析。
 * @note 需要为序列化/反序列化的类型定义 glz::meta
 * 特化或使用 GLZ_META 宏。
 * @warning 大 JSON 文档反序列化可能消耗大量内存，需
 * 合理设置大小限制。
 */
#pragma once

#include <prism/transformer/json.hpp>
