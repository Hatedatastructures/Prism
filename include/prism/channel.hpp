/**
 * @file channel.hpp
 * @brief Channel 模块聚合头文件
 * @details 引入传输通道模块所有子头文件，提供统一的包含入口。
 */
#pragma once

#include <prism/channel/health.hpp>

#include <prism/channel/adapter/connector.hpp>
#include <prism/channel/connection/pool.hpp>
#include <prism/channel/eyeball/racer.hpp>

#include <prism/channel/transport/transmission.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/channel/transport/encrypted.hpp>
#include <prism/channel/transport/unreliable.hpp>
