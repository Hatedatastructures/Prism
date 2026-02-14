/**
 * @file transformer.hpp
 * @brief Transformer 模块聚合头文件
 * @details 包含数据转换层的所有实现，提供统一的数据序列化与反序列化接口。该模块是配置加载、状态持久化和 RPC 通信的基础设施。
 *
 * 模块组成：
 * @details - json.hpp：JSON 序列化与反序列化，基于 glaze 库提供高性能的 JSON 处理能力。
 *
 * 设计特性：
 * @details - 类型安全：利用 C++ 模板和编译期反射，确保序列化/反序列化的类型安全；
 * @details - 零拷贝解析：glaze 库支持零拷贝解析，减少内存分配和复制；
 * @details - PMR 内存管理：使用 memory::string 和 memory::resource_pointer 支持自定义内存分配；
 * @details - 错误处理：提供多种错误处理方式，包括返回值、错误上下文和异常安全设计。
 *
 * 使用场景：
 * @details - 配置文件加载和持久化；
 * @details - RESTful API 请求/响应序列化；
 * @details - 进程间通信数据格式转换；
 * @details - 状态快照和恢复。
 *
 * @note 需要为序列化/反序列化的类型定义 glz::meta 特化或使用 GLZ_META 宏。
 * @warning 大 JSON 文档反序列化可能消耗大量内存，需合理设置大小限制。
 */
#pragma once

#include <forward-engine/transformer/json.hpp>
