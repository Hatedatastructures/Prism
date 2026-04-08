# Agent 模块公开 API 文档

## 公开头文件总入口

`include/prism/agent.hpp` 是 agent 模块的公开 API 总入口，包含以下头文件：

```cpp
#pragma once

#include <prism/agent/account/directory.hpp>
#include <prism/agent/account/entry.hpp>
#include <prism/agent/config.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/agent/context.hpp>
#include <prism/agent/dispatch/handler.hpp>
#include <prism/agent/dispatch/handlers.hpp>
#include <prism/resolve/router.hpp>
#include <prism/resolve/cache.hpp>
#include <prism/resolve/cache.hpp>
#include <prism/resolve/coalescer.hpp>
#include <prism/resolve/router.hpp>
#include <prism/resolve/transparent.hpp>
#include <prism/agent/front/balancer.hpp>
#include <prism/agent/front/listener.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/pipeline/protocols.hpp>
#include <prism/agent/worker/launch.hpp>
#include <prism/agent/worker/stats.hpp>
#include <prism/agent/worker/tls.hpp>
#include <prism/agent/worker/worker.hpp>
```

---

## 配置与上下文

```cpp
#include <prism/agent/config.hpp>       // config 结构体
#include <prism/agent/context.hpp>      // server_context, worker_context, session_context
```

---

## 账户管理

```cpp
#include <prism/agent/account/directory.hpp>  // directory 类
#include <prism/agent/account/entry.hpp>      // entry 结构体, lease 类
```

---

## 连接管理

```cpp
#include <prism/agent/session/session.hpp> // session 类, make_session()
```

---

## 协议分发

```cpp
#include <prism/agent/dispatch/handler.hpp>   // handler 基类, registry 类
#include <prism/agent/dispatch/handlers.hpp>  // Http, Socks5, Tls, Unknown 处理器, register_handlers()
```

---

## 分发路由

```cpp
#include <prism/resolve/router.hpp>     // router 类
#include <prism/resolve/router.hpp>    // arbiter 类
#include <prism/resolve/cache.hpp>   // udpcache 类
#include <prism/resolve/cache.hpp>   // tcpcache 类
#include <prism/resolve/coalescer.hpp>  // coalescer 类
#include <prism/resolve/transparent.hpp> // transparent_hash, transparent_equal
```

---

## 前端监听

```cpp
#include <prism/agent/front/balancer.hpp>  // balancer 类, worker_load_snapshot
#include <prism/agent/front/listener.hpp>  // listener 类
```

---

## 协议管道

```cpp
#include <prism/pipeline/primitives.hpp>  // dial(), preview, tunnel()
#include <prism/pipeline/protocols.hpp>   // 聚合头文件，引入 http.hpp, socks5.hpp, trojan.hpp
#include <prism/pipeline/protocols/http.hpp>   // http()
#include <prism/pipeline/protocols/socks5.hpp> // socks5()
#include <prism/pipeline/protocols/trojan.hpp> // trojan()
```

---

## 工作线程

```cpp
#include <prism/agent/worker/launch.hpp>  // launch 命名空间
#include <prism/agent/worker/stats.hpp>   // stats::state 类
#include <prism/agent/worker/tls.hpp>     // tls 命名空间
#include <prism/agent/worker/worker.hpp>  // worker 类
```

---

## 稳定 API vs 内部实现

### 说明

- 以上头文件为稳定 API，外部代码应通过 `#include <prism/agent.hpp>` 访问
- `.cpp` 文件中的实现细节不属于稳定 API
- dispatch 模块是 header-only，所有内容都在头文件中
