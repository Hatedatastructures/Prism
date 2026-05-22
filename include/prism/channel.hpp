/**
 * @file channel.hpp
 * @brief Channel 模块聚合头文件（已迁移到 connect 和 transport）
 * @details 原 channel 子模块（连接池、健康检测、Happy Eyeballs）
 * 已迁移到 connect 模块，传输层相关代码迁移到 transport 模块。
 * 此文件保留向后兼容，包含 connect 聚合头文件。
 */
#pragma once

#include <prism/connect.hpp>
