/**
 * @file multiplex.hpp
 * @brief Multiplex 模块聚合头文件
 * @details 引入多路复用模块所有子头文件，提供统一的包含入口。
 */
#pragma once

#include <prism/multiplex/bootstrap.hpp>
#include <prism/multiplex/config.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>

#include <prism/multiplex/smux/config.hpp>
#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/smux/frame.hpp>

#include <prism/multiplex/yamux/config.hpp>
#include <prism/multiplex/yamux/craft.hpp>
#include <prism/multiplex/yamux/frame.hpp>
