/**
 * @file pointer.hpp
 * @brief 智能指针定义（预留）
 * @details 当前暂未使用，保留作为未来扩展智能指针别名的占位符。计划支持与内存池集成的智能指针类型，提供自动内存池归还能力。
 *
 * 设计规划：
 * @details - unique_ptr 别名：支持自定义池删除器的 unique_ptr 类型；
 * @details - shared_ptr 支持：支持内存池分配的 shared_ptr 创建函数；
 * @details - make_unique 工厂：从指定内存池创建 unique_ptr 的工厂函数。
 *
 * @note 该文件当前为空，功能将在后续版本中实现。
 * @warning 不要在此文件中添加非 PMR 相关的智能指针别名。
 */
#pragma once


// namespace ngx::memory
// {
//     template <typename T>
//     using unique_ptr = std::unique_ptr<T>;
// }
