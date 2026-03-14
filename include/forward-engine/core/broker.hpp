/**
 * @file broker.hpp
 * @brief 核心组件聚合头文件
 * @details 该文件作为核心模块的统一入口，聚合了 HTTP 协议和 Agent
 * 相关的头文件，简化外部模块的引用依赖。通过包含该文件，使用者可
 * 以一次性获取所有核心组件的完整功能，无需逐个引入分散的头文件。
 * 该设计模式遵循"便利头文件"原则，在保持模块解耦的同时提供便捷的
 * 使用体验。
 */
#pragma once

#include <forward-engine/protocol/http.hpp>
#include <forward-engine/agent.hpp>
