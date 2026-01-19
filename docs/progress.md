# 项目进度

## 1. 项目概况
- **名称**：ForwardEngine
- **目标**：基于 C++23 与 Boost.Asio 的通用代理引擎（当前以 TCP/HTTP 为主）
- **开发环境**：Windows 11 + MinGW（第三方库安装在 `c:/bin`）
- **核心依赖**：Boost.Asio/Beast、OpenSSL、spdlog、glaze、CMake

## 2. 当前实现进度

### 2.1 HTTP 模块（`include/forward-engine/http/*`）
- [x] `request/response/header` 基础类型
- [x] 序列化/反序列化（`serialization/deserialization`）
- [x] 测试：`headers_test`、`request_test`

### 2.2 Agent（代理主流程，`include/forward-engine/agent/*`）
- [x] **接入层**：`worker` 负责监听端口并创建会话（`worker.hpp`）
- [x] **协议识别/目标解析**：`analysis::detect`、`analysis::resolve`（`analysis.hpp/.cpp`）
- [x] **会话转发**：`session` 支持
  - HTTP：区分正向/反向代理，建立上游连接并做双向转发（`session.hpp`）
  - Obscura：握手拿到目标串后走正向连接并转发（`session.hpp` + `obscura.hpp`）
  - 隧道取消：双向转发使用 `cancellation_signal/slot` 通知对向优雅退出，避免靠强制 `close()` 打断导致误报（`session.hpp`）
- [x] **路由/分发**：`distributor` 提供 `route_forward/route_reverse/route_direct`（`distributor.hpp/.cpp`）
  - 现状：`reverse_map_` 仍是内存结构，未接入配置加载
- [x] **连接池（当前仅 TCP）**：`source::acquire_tcp` + `internal_ptr` + `deleter` 回收（`connection.hpp/.cpp`）
  - 现状：按目标端点缓存空闲连接；包含基础“僵尸检测 / 最大空闲时长 / 单端点最大缓存数”
  - 未实现：UDP 连接缓存、全局 LRU、后台定时清理、跨线程共享/分片池

### 2.3 Obscura（传输封装，`agent/obscura.hpp`）
- [x] 基于 Beast WebSocket（含 SSL）的封装：`handshake/async_read/async_write`
- [x] 端到端测试：`obscura_test` 已接入 CTest 并可运行（产物名 `obscura_test_exec`）

### 2.4 日志（`include/forward-engine/trace/*`）
- [x] 基于 `spdlog` 的日志封装：异步线程池 + 文件轮转 + 可选控制台输出（`spdlog.hpp/.cpp`）
- [x] `trace::config` 字符串字段已切换为 `ngx::memory::string`（`std::pmr::string`），与项目内存策略一致
- [x] 协程日志接口与补充能力（`monitor.hpp/.cpp`）
- [x] 测试：`log_test`、`spdlog_test`

### 2.5 Transformer（`include/forward-engine/transformer/*`）
- [x] `transformer` 模块已接入：对 `glaze` 的封装入口（当前以 `JSON` 为主）
- [ ] 待完善：在 `ngx::transformer::json` 下收敛统一读写接口与项目侧默认 `opts`

### 2.6 内存（PMR 与分配策略，`include/forward-engine/memory/*`）
- [x] 统一内存资源别名：`memory::resource` / `memory::resource_pointer`（`container.hpp`）
- [x] 统一默认资源获取入口：`memory::current_resource()`
- [x] 统一对外接口签名：相关模块不直接暴露 `std::pmr::memory_resource*`
- [x] 全局池化策略入口：`system::enable_global_pooling()`（`pool.hpp`）
- [x] 线程局部帧分配器：`frame_arena`（`pool.hpp`，用于请求/会话的临时对象分配）

### 2.7 构建与测试（CMake）
- [x] 静态库 + 主程序 + 测试工程结构已搭好（根 `CMakeLists.txt`、`src/`、`test/`）
- [x] MinGW 下 OpenSSL 依赖可配置与编译
- [x] 已通过测试：`headers_test`、`glaze_test`、`request_test`、`log_test`、`session_test`、`obscura_test`、`connection_test`、`spdlog_test`、`main_test`、`json_test`
  - `session_test` 覆盖：正常转发 + 上游先断/客户端先断的双向退出语义
- [x] curl 端到端验证已跑通：HTTP/HTTPS 正向代理（含 `CONNECT`）

## 3. 近期待办（按当前缺口）
- [ ] 反向代理配置加载：把 `configuration.json`（或其它源）接入 `reverse_map_`
- [ ] Transformer 收敛：在 `ngx::transformer::json` 下统一默认 `opts` 与受限解析策略
- [ ] 连接池增强（可选）：全局 LRU/定时清理/更严格的健康检查策略
- [ ] SOCKS5 支持（可选）：新增 `protocol_type::socks5` 与 `handle_socks5`（当前未支持，`curl -x socks5://...` 不可用）

## 4. 已知问题
- 构建目录若混用生成器（例如同一 `build` 目录曾同时被 Ninja 与 MinGW Makefiles 使用），可能导致缓存冲突与文件锁问题；建议按生成器分离构建目录（例如 `build_mingw`）
