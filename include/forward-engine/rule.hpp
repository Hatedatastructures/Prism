/**
 * @file rule.hpp
 * @brief 规则模块聚合头文件
 * @details 包含规则引擎的所有组件，提供访问控制、安全过滤等
 * 规则管理功能。该模块是代理系统安全策略的核心，负责黑名单管理
 * 和规则匹配。模块组成包括 config.hpp 规则配置结构和
 * blacklist.hpp 黑名单管理组件。设计原理方面，规则抽象将访问
 * 控制、安全过滤等规则抽象为统一的规则接口；高性能匹配使用
 * 高效的数据结构和算法实现快速规则匹配；线程安全方面规则查询
 * 操作设计为线程安全，支持多线程并发访问。使用场景包括访问
 * 控制、安全过滤和流量管理。
 * @note 规则引擎应保持无状态，规则数据通过配置加载。
 * @warning 规则匹配可能影响性能，应避免过于复杂的规则逻辑。
 */
#pragma once

#include <forward-engine/rule/config.hpp>
#include <forward-engine/rule/blacklist.hpp>
