# HTTP 请求在 ForwardEngine 内的调用流程

本文说明 HTTP 请求进入代理后的完整调用链，以及不同类型 HTTP 请求（`CONNECT`、绝对 `URI`、相对路径）在项目内的分支与路由决策。所有流程均基于协程模型运行。

## 1. 总体入口链路

1. `worker` 监听端口并接收连接，创建 `session`  
   入口位置：`include/forward-engine/agent/worker.hpp`，类 `ngx::agent::worker` 的 `do_accept`。
2. `session::diversion` 预读并识别协议，然后分流到 HTTP 处理器  
   位置：`include/forward-engine/agent/session.hpp`，类 `ngx::agent::session` 的 `diversion`。
3. `handler::http` 读取并解析 HTTP 请求，确定目标与路由方向  
   位置：`include/forward-engine/agent/handler.hpp`，命名空间 `ngx::agent::handler` 的 `http`。
4. `protocol::analysis::resolve` 判断“正向/反向”并解析目标地址  
   位置：`src/forward-engine/protocol/analysis.cpp`，类 `ngx::protocol::analysis` 的 `resolve`。
5. `handler::connect_upstream` 根据 `forward_proxy` 选择 `route_forward` 或 `route_reverse`  
   位置：`include/forward-engine/agent/handler.hpp`，命名空间 `ngx::agent::handler` 的 `connect_upstream`。
6. `distributor` 建立上游连接（直连或回退）  
   位置：`src/forward-engine/agent/distributor.cpp`，类 `ngx::agent::distributor` 的 `route_forward` 与 `route_reverse`。

## 2. HTTP 请求解析与目标判定

`handler::http` 先异步读取 HTTP 请求，然后通过 `analysis::resolve` 解析目标与正反向标记：

- 读取请求：`protocol::http::async_read`  
  位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`，以及 `include/forward-engine/protocol/http/deserialization.hpp` 的 `protocol::http::async_read`。
- 解析目标：`analysis::resolve`  
  位置：`src/forward-engine/protocol/analysis.cpp` 的 `ngx::protocol::analysis::resolve`。

判定依据是“请求行是否已经包含完整目标地址”：

- `CONNECT host:port` → 正向代理
- 绝对 `URI`（`http://` / `https://`）→ 正向代理
- 相对路径（`/path`）→ 反向代理（目标由 `Host` 头和路由表决定）

## 3. 三种 HTTP 请求的调用分支

### 3.1 `CONNECT` 请求（HTTPS 正向代理）

**示例请求：**
```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
```

**调用流程：**
1. `analysis::resolve` 将其判定为正向代理，并解析 `host:port`  
   位置：`src/forward-engine/protocol/analysis.cpp` 的 `ngx::protocol::analysis::resolve`。
2. `connect_upstream` 走 `route_forward`（直连优先，失败回退上游代理）  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::connect_upstream`，以及 `src/forward-engine/agent/distributor.cpp` 的 `ngx::agent::distributor::route_forward`。
3. 建连成功后，返回 `200 Connection Established` 给客户端  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`。
4. 进入原始 TCP 隧道透传  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::original_tunnel`。

**关键点：**
- `CONNECT` 请求完成后不再解析 HTTP 报文，而是纯 TCP 双向转发。

### 3.2 绝对 `URI` 请求（HTTP 正向代理）

**示例请求：**
```
GET http://example.com/path HTTP/1.1
Host: example.com
```

**调用流程：**
1. `analysis::resolve` 识别为正向代理并解析绝对 `URI`  
   位置：`src/forward-engine/protocol/analysis.cpp` 的 `ngx::protocol::analysis::resolve`。
2. `connect_upstream` 走 `route_forward`，建立上游连接  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::connect_upstream`。
3. 将解析后的 `req` 序列化转发给上游  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`，以及 `include/forward-engine/protocol/http/serialization.hpp` 的 `protocol::http::serialize`。
4. 若 `read_buffer` 内还有预读数据，继续转发  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`。
5. 进入隧道转发（用于持续双向流量）  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::tunnel`。

### 3.3 相对路径请求（反向代理）

**示例请求：**
```
GET /index.html HTTP/1.1
Host: myservice.com
```

**调用流程：**
1. `analysis::resolve` 判定为反向代理，目标从 `Host` 头解析  
   位置：`src/forward-engine/protocol/analysis.cpp` 的 `ngx::protocol::analysis::resolve`。
2. `connect_upstream` 走 `route_reverse`，根据路由表获取后端连接  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::connect_upstream`，以及 `src/forward-engine/agent/distributor.cpp` 的 `ngx::agent::distributor::route_reverse`。
3. 请求序列化并转发给后端  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`。
4. 继续转发预读数据并进入隧道  
   位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::tunnel`。

## 4. 路由与连接建立的关键细节

### 4.1 正向路由 `route_forward`

路由优先级：
1. 黑名单拦截（直接返回 `blocked`）
2. DNS 解析并直连（连接池 `acquire_tcp`）
3. 直连失败回退上游代理 `CONNECT`

对应实现：`src/forward-engine/agent/distributor.cpp` 的 `ngx::agent::distributor::route_forward`。

### 4.2 反向路由 `route_reverse`

从 `reverse_map_` 取目标后端 `endpoint`，通过连接池复用连接。  
对应实现：`src/forward-engine/agent/distributor.cpp` 的 `ngx::agent::distributor::route_reverse`。

### 4.3 上游代理回退 `route_positive`

当直连失败时，走 `CONNECT` 回退路径：
1. 解析上游代理  
2. 连接代理  
3. 发送 `CONNECT host:port`  
4. 解析响应行状态码（仅接受 `200`）

对应实现：`src/forward-engine/agent/distributor.cpp` 的 `ngx::agent::distributor::route_positive`。

## 5. 关键日志与排查点

以下日志有助于确认 HTTP 请求走向：
- `[Session] Detected protocol: http.`  
  位置：`include/forward-engine/agent/session.hpp` 的 `ngx::agent::session::diversion`。
- `[Handler] HTTP upstream resolving: forward_proxy=...`  
  位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`。
- `[Handler] Sent 200 Connection Established.`  
  位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::http`。

## 6. 简化调用图（文字版）

```
worker.accept -> session::diversion
  -> handler::http
      -> protocol::http::async_read
      -> analysis::resolve
      -> handler::connect_upstream
          -> distributor::route_forward | route_reverse
      -> if CONNECT:
          -> send "200 Connection Established"
          -> handler::original_tunnel (纯 TCP 透传)
      -> else:
          -> protocol::http::serialize
          -> transport::adaptation::async_write (转发请求头与正文)
          -> forward prefetched buffer (read_buffer.data)
          -> handler::tunnel (持续双向转发)
```
