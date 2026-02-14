/**
 * @file rule.hpp
 * @brief Rule 模块聚合头文件
 * @details 包含规则引擎的所有组件，提供访问控制、安全过滤等规则管理功能。该模块是代理系统安全策略的核心，负责黑名单管理和规则匹配。
 *
 * 模块组成：
 * @details - config.hpp：规则配置结构，定义规则引擎的配置项；
 * @details - blacklist.hpp：黑名单管理，提供基于 IP 地址和域名的黑名单匹配功能。
 *
 * 设计原理：
 * @details - 规则抽象：将访问控制、安全过滤等规则抽象为统一的规则接口；
 * @details - 高性能匹配：使用高效的数据结构和算法实现快速规则匹配；
 * @details - 线程安全：规则查询操作设计为线程安全，支持多线程并发访问。
 *
 * 使用场景：
 * @details - 访问控制：阻止黑名单中的 IP 或域名访问；
 * @details - 安全过滤：屏蔽恶意或可疑的服务器；
 * @details - 流量管理：限制特定域名的访问流量。
 *
 * @note 规则引擎应保持无状态，规则数据通过配置加载。
 * @warning 规则匹配可能影响性能，应避免过于复杂的规则逻辑。
 */
#pragma once

#include <forward-engine/rule/config.hpp>
#include <forward-engine/rule/blacklist.hpp>