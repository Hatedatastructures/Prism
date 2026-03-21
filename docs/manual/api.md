# Agent 模块公开 API 文档

## 公开头文件总入口

`include/forward-engine/agent.hpp` 是 agent 模块的公开 API 总入口，包含以下头文件：

```cpp
#pragma once

#include <forward-engine/agent/account/directory.hpp>
#include <forward-engine/agent/account/entry.hpp>
#include <forward-engine/agent/config.hpp>
#include <forward-engine/agent/session/session.hpp>
#include <forward-engine/agent/context.hpp>
#include <forward-engine/agent/dispatch/handler.hpp>
#include <forward-engine/agent/dispatch/handlers.hpp>
#include <forward-engine/agent/resolve/arbiter.hpp>
#include <forward-engine/agent/resolve/udpcache.hpp>
#include <forward-engine/agent/resolve/tcpcache.hpp>
#include <forward-engine/agent/resolve/coalescer.hpp>
#include <forward-engine/agent/resolve/router.hpp>
#include <forward-engine/agent/resolve/transparent.hpp>
#include <forward-engine/agent/front/balancer.hpp>
#include <forward-engine/agent/front/listener.hpp>
#include <forward-engine/agent/pipeline/primitives.hpp>
#include <forward-engine/agent/pipeline/protocols.hpp>
#include <forward-engine/agent/worker/launch.hpp>
#include <forward-engine/agent/worker/stats.hpp>
#include <forward-engine/agent/worker/tls.hpp>
#include <forward-engine/agent/worker/worker.hpp>
```

---

## 配置与上下文

```cpp
#include <forward-engine/agent/config.hpp>       // config 结构体
#include <forward-engine/agent/context.hpp>      // server_context, worker_context, session_context
```

---

## 账户管理

```cpp
#include <forward-engine/agent/account/directory.hpp>  // directory 类
#include <forward-engine/agent/account/entry.hpp>      // entry 结构体, lease 类
```

---

## 连接管理

```cpp
#include <forward-engine/agent/session/session.hpp> // session 类, make_session()
```

---

## 协议分发

```cpp
#include <forward-engine/agent/dispatch/handler.hpp>   // handler 基类, registry 类
#include <forward-engine/agent/dispatch/handlers.hpp>  // Http, Socks5, Tls, Unknown 处理器, register_handlers()
```

---

## 分发路由

```cpp
#include <forward-engine/agent/resolve/router.hpp>     // router 类
#include <forward-engine/agent/resolve/arbiter.hpp>    // arbiter 类
#include <forward-engine/agent/resolve/udpcache.hpp>   // udpcache 类
#include <forward-engine/agent/resolve/tcpcache.hpp>   // tcpcache 类
#include <forward-engine/agent/resolve/coalescer.hpp>  // coalescer 类
#include <forward-engine/agent/resolve/transparent.hpp> // transparent_hash, transparent_equal
```

---

## 前端监听

```cpp
#include <forward-engine/agent/front/balancer.hpp>  // balancer 类, worker_load_snapshot
#include <forward-engine/agent/front/listener.hpp>  // listener 类
```

---

## 协议管道

```cpp
#include <forward-engine/agent/pipeline/primitives.hpp>  // dial(), preview, tunnel()
#include <forward-engine/agent/pipeline/protocols.hpp>   // http(), socks5(), trojan()
```

---

## 工作线程

```cpp
#include <forward-engine/agent/worker/launch.hpp>  // launch 命名空间
#include <forward-engine/agent/worker/stats.hpp>   // stats::state 类
#include <forward-engine/agent/worker/tls.hpp>     // tls 命名空间
#include <forward-engine/agent/worker/worker.hpp>  // worker 类
```

---

## 稳定 API vs 内部实现

### 说明

- 以上头文件为稳定 API，外部代码应通过 `#include <forward-engine/agent.hpp>` 访问
- `.cpp` 文件中的实现细节不属于稳定 API
- dispatch 模块是 header-only，所有内容都在头文件中
