/**
 * @file resolve.hpp
 * @brief Resolve 模块聚合头文件
 * @details 引入 DNS 解析模块所有子头文件，提供统一的包含入口。
 */
#pragma once

#include <prism/resolve/router.hpp>

#include <prism/resolve/dns/config.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/resolve/dns/upstream.hpp>

#include <prism/resolve/dns/detail/cache.hpp>
#include <prism/resolve/dns/detail/coalescer.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/resolve/dns/detail/rules.hpp>
#include <prism/resolve/dns/detail/transparent.hpp>
#include <prism/resolve/dns/detail/utility.hpp>
