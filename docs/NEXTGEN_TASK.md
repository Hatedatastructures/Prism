# Prism Next-Gen 架构提示词（NEXTGEN_TASK.md）

> 本文件是一份**可直接执行的完整长任务提示词**：目标是把 `tests/common/`（psmtest 库）
> 从"测试协议库"演进为**可替换主项目（src/prism）的新一代架构**。
>
> **背景**：tests/common 已实现：7 代理协议 + 7 伪装方案 + 3 多路复用（模板化 frame_codec）+
> core 基础设施（crypto/fault/memory/transport/http2/http3/quic/middleware）+ authenticator。
> 它采用比主项目更干净的设计：Beast 风格编解码、统一 transmission 抽象、中间件管线。
> 当前状态 = **协议层已完成，架构层未收口**——存在误导性混乱（见第 1 节），
> 且缺 runtime/recognition/dialer/dns/user/settings 等模块，无法直接替换主项目。
>
> **执行方式**：一次性长任务，按任务栈顺序连续推进；**无人值守**——所有任务无需
> 向用户汇报，执行者自主推进、自主分析、自主决策；**禁止自动 git commit/push**。
> 所有测试数据与结论写入指定文件（见 2.3），用户只查看文件中的测试数据。
>
> 配套文件：
> - 进度记录：`docs/TASK_PROGRESS.md`（执行中自动维护，只记录事实与决策）
> - 测试数据：`docs/ngx-test-data/`（每组件一个数据文件，用户查看的唯一依据）
> - 现有规范：`tests/common/SPEC.md`（已过时，T1 中更新）
> - 架构参照：`docs/ARCHITECTURE.md`（主项目四层所有权 / 模块层级，需对齐但不过度照搬）
> - 主项目参照：`src/prism/`、`include/prism/`（功能对照与互操作目标，只读参照）

---

## 0. 使用方式

1. 完整阅读本文件，确认任务栈（第 3 节）与门禁矩阵（第 2 节）。
2. 检查 `docs/TASK_PROGRESS.md`：不存在则按第 6 节模板初始化；存在则从「当前焦点」继续。
3. **连续执行**：从当前焦点开始，按第 2 节协议逐个推进单元，直到任务栈全部完成，
   输出最终总结写入 `docs/ngx-test-data/INDEX.md` 并结束。
4. **无人值守**：执行过程中不向用户汇报、不请求确认；所有中间结果写入
   `docs/ngx-test-data/` 与 `docs/TASK_PROGRESS.md`。无法自主决策时才停止并记录问题。
5. **禁止自动提交**：任何情况下不执行 git commit/push；全部任务完成后在
   `docs/TASK_PROGRESS.md` 末尾生成「待提交清单」（文件列表+摘要），供用户自行处理。

---

## 1. 现状诊断（必须理解的事实，避免误导）

### 1.1 已有资产（完整度对照）

| 领域 | 已有（tests/common） | 缺失（对照主项目） |
|---|---|---|
| 代理协议 | vmess/vless/trojan/shadowsocks2022/socks5/hysteria2/tuic（codec+conn+dgram+聚合头，内联 connect/accept） | — |
| 伪装方案 | reality/shadowtls/restls/anytls/trusttunnel/ws/gun | **xhttp、ech、native**（原生 TLS 兜底） |
| 多路复用 | smux/yamux/h2mux（模板化 frame_codec，client/server/session） | — |
| 传输抽象 | transmission（新接口）+ transport_base（旧接口）+ legacy_bridge 桥 | **接口统一**（旧接口退役） |
| 基础设施 | crypto/fault/exception/memory/coroutine/rate/http2/http3/quic | **recognition、dialer/outbound/route、dns、settings/loader、user/directory、resource 三层、runtime 骨架** |
| 中间件 | pipeline/context/builtin(dial/mux/pad/relay) | **auth 中间件、统计中间件、会话编排** |
| 认证 | authenticator（static/reject，已接入 vless/trojan/socks5/hysteria2） | **生产目录认证器**（对接 user/directory） |

### 1.2 必须修复的误导性问题（T1 处理）

- **M1 命名空间分裂**：`common.hpp` 用 `psm_test`/`psmtest_test`，其余 `psmtest` → 统一。
- **M2 SPEC 脱节**：SPEC 描述 client/server/kdf/chunk/handshake 独立文件结构，实际是
  聚合头 + codec/conn/dgram/types 四件套 + 内联 connect/accept → 更新 SPEC 反映真实架构。
- **M3 双错误体系**：`core/error.hpp`（Beast，68 引用）vs `core/fault/code.hpp`（16 引用）：
  协议层用 error，中间件用 fault → 决策统一方案（推荐：协议层保留 error 作为编解码错误，
  middleware 迁移到 error 或保留 fault 但明确边界，二选一并在 SPEC 固化）。
- **M4 新旧接口双轨**：mux/session.hpp 仍用 transport_base（:43），legacy_bridge 桥接
  mux/client、server → 将 mux 迁移到 transmission，删除 transport_base/legacy_bridge。
- **M5 CMake 清单脱节**：transmission.hpp 等 7+ 个头未列入 target_sources；旧的重复公共
  target 已按 Foundation/Transport/Net/Runtime/Protocol/Composition 职责拆分，并完整登记头文件。
- **M6 空壳模块**：core/account、core/runstate、core/stats 仅 README → 落实实现或删除
  占位（依据主项目 user/resource/stats 功能裁剪）。
- **M7 编码问题**：middleware/context.hpp:43 乱码 + 8 文件 CRLF → 修复编码，统一 LF。
- **M8 注释错误**：transmission.hpp:3 "对齐主库 psmtest::transmission" → 改为准确描述；
  common.hpp 声明为基础但零使用 → 评估删除或并入新 core。
- **M9 覆盖缺口**：见 1.1 缺失列。
- **M10 QUIC 数据面**：hysteria2/tuic dgram 用裸 UDP，非 QUIC datagram → 记录为已知简化，
  标注 TODO 或接入 quic 基建（core/quic 已有 stream_adapter/gateway_common）。

---

## 2. 执行协议与门禁

### 2.1 单元流程

```
单元开始
├─ ① 读 docs/TASK_PROGRESS.md，确认当前任务/单元；全部 done → 汇总写入
│    docs/ngx-test-data/INDEX.md 并结束
├─ ② 前置调研：读相关文件 → 列出影响面（头文件依赖、调用方、CMake 清单）
├─ ③ 实施改动（遵守第 4 节架构红线）
├─ ④ 写/改测试（同一单元内完成）
├─ ⑤ 跑门禁（G1-G16 适用项）→ 测试数据写入 docs/ngx-test-data/<组件>.md
├─ ⑥ 自主分析：对比四象限数据（分支覆盖/覆盖率/性能/压测）——
│     全部达标 → 更新 TASK_PROGRESS.md → 下一单元
│     有红或数据不达标 → 修复重跑（≤3 次，再失败简化或 SKIP，原因记入进度文件）
└─ ⑦ 清理本轮进程（G11）
```

### 2.2 门禁矩阵

| 编号 | 门禁 | 命令/方式 | 通过标准 |
|---|---|---|---|
| G1 | 编译 | `cmake --build build --config Release -j 16`（晚间 22:00-08:00 用 `-j 1`） | 0 错误 0 警告 |
| G2 | 单元测试 | `ctest --test-dir build -R <相关target> --output-on-failure` | 全绿 |
| G3 | 全量回归 | `ctest --test-dir build --output-on-failure -j 1 --timeout 30`（每个子任务收尾） | 全绿（HandshakeTimeout flaky 除外） |
| G4 | 命名一致性 | `rg "psm_test|psmtest_test" tests/common` 零命中；全库 `psmtest` 统一 | 0 命中 |
| G5 | 接口一致性 | `rg "transport_base" tests/common` 零命中（T1 完成后） | 0 命中 |
| G6 | 错误体系一致性 | 按 T1 决策方案核查引用边界 | 通过 |
| G7 | CMake 完整性 | 全部 .hpp 在 target_sources 或聚合头可达 | 无遗漏 |
| G8 | 编码规范 | AGENTS.md 规则 1/3/13、Doxygen 中文注释、规范 v2 大驼峰（存量未迁移文件暂循旧风格） | 自查通过 |
| G9 | 协程纯度 | 无阻塞/锁/busy-wait（coroutine-audit 清单） | 自查通过 |
| G10 | 生命周期 | co-lifecycle-audit 清单（shared_ptr 捕获、PMR 资源） | 自查通过 |
| G11 | 资源清理 | `taskkill //F //PID <pid>`（只杀本轮启动的进程） | 无残留 |
| G12 | 性能 | 热路径改动跑相关 bench 对比基线 | 不劣化 ±3% |
| G13 | 分支覆盖测试 | 新组件/新函数每个分支路径（if/else、switch case、边界、半帧、坏数据、错误矩阵）必须有对应测试用例命中 | 逐分支核对清单，无未测分支 |
| G14 | 代码覆盖率 | `cmake -B build -DPRISM_ENABLE_COVERAGE=ON` + ctest + `gcovr --root . --filter "tests/common/" --html-details build/coverage.html --print-summary`（晚间用 `-j 1`） | 新组件模块覆盖率 ≥ 80%（行+分支）；既有模块新增代码 ≥ 85% |
| G15 | 压力测试 | `build/stresses/<相关>Stress.exe` 或新增 stress target 短跑（如 30s-60s），对照 AGENTS.md stress 用法 | 无崩溃、无内存泄漏、错误计数为 0 |
| G16 | 压测回归 | 并发/长跑压测（连接风暴、并发流、UDP 长跑、内存曲线），记录峰值内存与泄漏曲线 | 曲线平稳，无单调增长泄漏 |

### 2.3 测试四象限（每个新组件/积木必须覆盖）

```
每个新组件（模块/积木/中间件/协议实现）按四象限验收：
┌──────────────┬──────────────────┐
│  Q1 正确性    │  Q2 覆盖          │
│  分支覆盖测试  │  代码覆盖率门禁    │
│  （G13）      │  （G14 ≥80%）     │
├──────────────┼──────────────────┤
│  Q3 性能      │  Q4 压测          │
│  基准+回归     │  压力+泄漏长跑     │
│  （G12）      │  （G15/G16）      │
└──────────────┴──────────────────┘
```

- **Q1 正确性（G13）**：逐分支枚举测试——正常路径、每个 if/else 分支、每个 switch
  case、边界值（0/1/最大值/溢出）、半包/坏数据/错误矩阵、超时/取消路径。
  产出：测试文件中按 `// 分支: <路径描述>` 注释标注每个用例命中的分支。
- **Q2 覆盖率（G14）**：新组件必须跑覆盖率构建并达标；覆盖率报告随测试数据文件记录
  （百分比 + 未覆盖函数清单）。
- **Q3 性能（G12）**：新组件若有热路径方法，必须建 bench target（`build/benchmarks/`）
  并记录基线；后续改动对比 ±3%。
- **Q4 压测（G15/G16）**：新组件若有状态/并发/长生命周期，必须建 stress target
  （`stresses/` 或 tests/common/stress）跑短跑压测；涉及内存池/缓存的组件额外跑
  内存曲线长跑。

### 2.4 测试数据文件（用户查看的唯一依据）

**无人值守约定**：执行者不向用户汇报；每单元完成门禁后，把原始数据与结论写入
`docs/ngx-test-data/<组件>.md`（不存在则按下方模板创建），用户只查看这些文件。

```
# <组件名> 四象限测试数据

> 单元：<任务编号> · 日期：<日期> · 状态：PASS / FAIL / SKIP(原因)

## Q1 分支覆盖（G13）
- 用例数：<n>，命中分支：<列表或指向测试文件标注>
- 覆盖分支清单：正常路径 / 每个 if-else / switch case / 边界 / 半包 / 坏数据 / 错误矩阵 / 超时 / 取消

## Q2 代码覆盖率（G14）
- 行覆盖率：<xx%>（阈值 80%）
- 分支覆盖率：<xx%>（阈值 80%）
- 未覆盖函数：<列表；无则填"无">

## Q3 性能（G12）
- bench 命令：<命令>
- 基线 vs 本次：<表：指标 | 基线 | 本次 | 偏差%>
- 结论：达标 / 劣化(原因)

## Q4 压测（G15/G16）
- stress 命令：<命令>（时长）
- 结果：<错误数 / 崩溃 / 内存曲线摘要>
- 结论：通过 / 失败(原因)

## 执行者分析结论
<自主分析：四象限是否全部达标；有无性能/安全问题；是否进入下一单元>
```

**数据纪律**：
- 每个门禁的**原始输出**（bench 表格、gcovr 摘要、stress 日志尾部）必须贴入文件，
  不允许只写结论不写数据。
- 数据不达标 → 修复重跑并更新文件，直到该组件文件状态为 PASS 才进入下一单元。
- 小改动豁免（见 2.5）在文件中注明「豁免 Q3/Q4」及依据。
- 全部任务完成后汇总到 `docs/ngx-test-data/INDEX.md`（组件 | 状态 | 覆盖率 | 性能结论 | 压测结论）。

### 2.5 小改动豁免规则

仅同时满足以下条件时，可豁免 Q3/Q4（G12/G15/G16），**Q1/G13 与 Q2/G14 永不免除**：

| 豁免条件 | 说明 |
|---|---|
| 行为无变化 | 纯注释、格式化、重命名（IDE 级 rename）、Doxygen 文档修正 |
| 改动量极小 | 单文件 ≤ 10 行有效代码改动（不含测试文件），且无新函数/新分支 |
| 非逻辑改动 | 常量提取、聚合头 include 修正、CMake 清单补充、编码/行尾修复 |

**豁免流程**：在 TASK_PROGRESS 当前焦点注明「小改动豁免 Q3/Q4（依据：行为无变化/≤10行）」，
仍需跑 G1 编译 + 相关 G2 回归；任何有行为变化或新增分支的改动**必须全象限**。

### 2.6 提交纪律

- **禁止自动提交**：任何情况下不得 `git commit`/`git push`/`git amend`。
- 不向用户汇报、不请求提交批准；全部任务完成后在 `docs/TASK_PROGRESS.md` 末尾
  生成「待提交清单」：按任务分组列出文件清单 + 摘要 + 建议 message
  （`fix:`/`feat:`/`refactor:`/`test:`/`docs:`），供用户自行处理。
- 期间若用户主动指示提交，按指示执行（仅 `git add <指定文件>`，禁止 `git add -A`）。

### 2.7 纠错协议

| 级别 | 触发 | 处理 |
|---|---|---|
| L1 | G1/G2 红 | 修复重跑（≤3 次） |
| L2 | 架构违规（跨层 include、接口分裂新增） | 停止该单元，回退，重新设计 |
| L3 | 行为漂移（夹带无关改动） | 回退漂移部分，记录候选 |
| L4 | 连续 3 次失败 | 简化方案或 SKIP（记录原因），继续下一单元 |
| L5 | 回归异常 | 定位引入单元 → 回退 → 修复重跑 |

---

## 3. 任务栈（按序执行）

> **统一测试要求**：以下每个任务（除小改动豁免，见 2.4）必须走测试四象限——
> Q1 分支覆盖（G13）+ Q2 覆盖率（G14）+ Q3 性能（G12）+ Q4 压测（G15/G16）。
> 每个任务的验收条目中已注明适用的象限；未注明时默认 Q1+Q2 必做，
> Q3/Q4 按组件性质（有热路径→Q3；有状态/并发/长生命周期→Q4）执行。

```
T0 传输接口补齐（P0，D1） → T1 架构收口（P0，清误导）
→ T2 协议面补缺（xhttp/ech/native/recognition/http2 真实实现）
→ T3 网络层（dialer/route/dns/UDP 中继/http1.1）
→ T4 运行时骨架（session 编排 + 中间件完善 + 超时背压）
→ T5 运营层积木（O1-O7 认证/统计/账户/限速/可观测/注册表/API + settings + stress）
→ T6 替代验证（对拍 + 互操作 + 性能 + fuzz + 路线图）
→ T7 质量加固（四象限测试平台化：覆盖率基线/分支模板/压测工具/基准固化/收口审计）
```

### T0 传输接口补齐（P0 — Next-Gen 地基，D1）

> **前置发现**：`transmission` 接口（`preview/Transport/Transmission.hpp`）缺少
> `shutdown()/set_timeout()/is_open()`，但实现类（memory_stream/socket_stream）已有
> （`:158-205`、`:167-216`）——**接口比实现薄**，SPEC 2.2 要求的会话接口能力无法通过
> 多态调用。本任务先把地基补齐，后续所有协议 conn 才能统一超时/半关/状态查询。

- **T0-1 接口补全**：`transmission` 增加 `shutdown()`（半关，虚函数默认转发 next_layer）、
  `set_timeout(ms)`（读超时，0=禁用）、`is_open()`；同步更新 concept
  （transmission_like）与 `legacy_bridge` 桥。
- **T0-2 全库透传**：各协议 conn（7 proxy + 7 stealth）装饰器逐层透传
  shutdown/set_timeout/is_open（对照 ws/gun 现有实现补齐）。
- **T0-3 超时语义测试**：memory_stream/socket_stream 超时行为单测（读挂起 →
  set_timeout 触发 → operation_timed_out 返回）。
- 门禁：G1 + G2（transport 相关 target）+ G4 + G6。
- 验收：`rg "async_read_some" tests/common/stealth/*/conn.hpp` 逐个确认均有超时路径；
  SPEC 2.2 会话接口 8 项能力全部可通过 transmission 多态调用。
- **四象限**：Q1（分支：超时触发/未触发/0 禁用/取消/EOF 各路径）+ Q2（transmission 相关
  模块 ≥80%）+ Q3（若 conn 透传为热路径：TransportBench 对比）+ Q4（T0 为接口层，
  连接级并发由 T4 压测覆盖，此处豁免 Q4 并注明）。
- 关联 skills：coroutine-audit、write-test、co-lifecycle-audit。

### T1 架构收口（P0 — 清理误导，统一基线）

- **T1-1 命名统一**：`common.hpp` 的 `psm_test`/`psmtest_test` → `psmtest`；删除或重构
  `common.hpp`（byte_reader/byte_writer 零使用，评估废弃，保留 varint 部分迁入 core）。
  门禁：G4。
- **T1-2 错误体系决策**：对照 `core/error.hpp`（协议层编解码错误）与 `core/fault/code.hpp`
  （中间件/流程错误）的引用范围，产出一致性方案（推荐：编解码保留 error；
  middleware 的 fault 迁移到 error 或建立显式转换层），写入 SPEC 固化。
  门禁：G6 + 全量回归。
- **T1-3 传输接口统一**：mux/session.hpp + mux/{smux,yamux,h2mux}/session.hpp 从
  transport_base 迁移到 transmission；删除 `legacy_bridge.hpp`、`transport_base.hpp`。
  门禁：G5 + 全部 mux 测试回归。
- **T1-4 CMake 整合**：删除旧的聚合 INTERFACE 库，按 Foundation/Transport/Net/Runtime/
  Protocol/Composition 拆分 target；target_sources 完整列出全部头文件（含
  transmission/authenticator/legacy_bridge（若 T1-3 后仍存）等）；更新所有
  `target_link_libraries`（17+4 处）。
  门禁：G7 + 全量回归。
- **T1-5 编码与清理**：修复 middleware/context.hpp 乱码；统一 LF；空壳模块
  （account/runstate/stats）落实实现或删除占位；修正 transmission.hpp 错误注释。
  门禁：G1 + G3。
- **T1-6 SPEC 重写**：按真实架构（聚合头 + codec/conn/dgram/types 四件套 + 内联
  connect/accept + transmission 统一接口 + middleware 管线）重写 `tests/common/SPEC.md`，
  补充模块归属表与错误体系边界。门禁：文档核对。

### T2 协议面补缺（P1 — 对齐主项目 handshake 面）

- **T2-1 native 方案**：原生 TLS 兜底（对齐主项目 `handshake/native`）：标准 TLS 握手 +
  证书校验 + 直通。含 codec（TLS 记录层纯函数?）与 conn（transmission 装饰器）。
  验收：与主项目 native 互操作 + 自签证书 E2E。
  四象限：Q1（握手成功/证书失败/超时/半包）+ Q2 + Q3（握手延迟 bench）+ Q4（并发握手压测）。
- **T2-2 xhttp 方案**：对齐主项目 `handshake/xhttp`：stream-one（h2 POST）+ stream-up +
  packet-up（评估 h3，若 core/http3+quic 可支撑则实现）。
  **前置依赖**：D2（http2 真实实现）——xhttp stream-one 需要 h2 帧循环，不可复用
  主项目实现（Next-Gen 自包含原则）。验收：Go xhttp 客户端互操作。
  四象限：Q1（h2 帧边界/坏帧/中断/孤儿会话回收）+ Q2 + Q3 + Q4（多会话并发压测）。
- **T2-3 ech 方案**：ECH 解密（BoringSSL SSL_ECH_KEYS，主项目已有实现可参照移植）。
  验收：ECH 客户端（主项目 EchKeygen 生成密钥）互操作。
  四象限：Q1（合法/非法 ECH config/无 ECH 回落）+ Q2 + Q4（并发握手）。
- **T2-4 recognition 识别流水线**：probe 首包检测（24 字节预读 → 协议类型枚举）+
  TLS ClientHello 特征分析 + SNI 路由表。**设计定位**：作为 pipeline 的前置步骤产出
  `context.detected`，与 middleware 管线衔接（对齐主项目 recognition 但按 psmtest 风格重构）。
  验收：7+3 协议自动识别单测 + 未知流量拒绝。
  四象限：Q1（每协议正样本 + 错位/截断/未知 负样本矩阵）+ Q2 + Q3（识别吞吐 bench）+
  Q4（随机字节洪水压测，验证无崩溃/误判率受控）。
- **T2-5 stealth 对齐审计**：对照主项目 10 伪装方案逐一核对已实现的 7 个的协议细节
  （帧格式/握手序列/超时），产出差异清单并修复。验收：互操作测试矩阵全绿。
- **T2-6 http2 真实实现（D2）**：`core/http2` 从接口骨架 → 完整帧编解码 + 会话状态机
  （帧头 9 字节 + HPACK 静态表 + 流状态），独立于 nghttp2（自包含）。供 gun/xhttp/h2mux
  复用。验收：h2 帧/会话单测 + gun/xhttp E2E。
  四象限：Q1（每帧类型/长度边界/流状态迁移/坏帧/RST/GOAWAY）+ Q2（h2 模块 ≥80%）+
  Q3（帧编解码 bench）+ Q4（多流并发压测）。

### T3 网络层（P1 — dialer/route/dns + UDP 中继）

- **T3-1 dialer**：拨号抽象（TCP/复用注入点），对齐主项目 `net/connection/dialer`：
  `async_connect` 封装 + 超时 + 取消。验收：真实 socket E2E。
  四象限：Q1（连接成功/拒绝/超时/取消/无效端口）+ Q2 + Q3（连接延迟 bench）+ Q4（并发拨号压测）。
- **T3-2 outbound/route**：路由表（positive/reverse）+ 拨号上下文（供 dial 中间件注入）。
  验收：正向/反向代理路由单测 + E2E。
  四象限：Q1（命中/未命中/通配/反向/边界键）+ Q2 + Q3（查找 bench，验证无临时分配）。
- **T3-3 dns**：resolver 封装（async_resolve）+ 缓存（LRU）+ upstream 抽象。
  验收：DNS 单测 + 缓存命中测试。
  四象限：Q1（命中/未命中/过期/负缓存/坏响应/超时）+ Q2 + Q3（缓存查找 bench）+ Q4（高并发解析压测）。
- **T3-4 UDP 中继完整化（D5）**：`udp_transmission` 之上补 relay_datagram 双向中继
  （对照主项目 socks5/conn.cpp:322-373）：UDP 关联生命周期（bind → 会话表 → 超时回收）、
  双 socket 并发中继、错误传播。验收：UDP echo E2E + 关联超时测试 + 错误矩阵。
  四象限：Q1（双向/单侧关闭/关联超时/坏包/端口不匹配）+ Q2 + Q3（UDP 吞吐 bench）+
  Q4（UDP 风暴压测 + 会话表内存曲线）。
- **T3-5 http/1.1 入站（D4）**：HTTP CONNECT 代理入口（对照主项目 protocol/http）：
  CONNECT 方法解析 + 407 认证 + 直连转发，作为 pipeline 的一个协议分支。
  验收：HTTP CONNECT E2E + 认证 407 测试。
  四象限：Q1（方法/URI/头边界/认证成功失败/坏请求）+ Q2 + Q3（解析 bench）+ Q4（并发 CONNECT 压测）。

### T4 运行时骨架（P1 — 把中间件管线变成可用代理）

- **T4-1 auth 中间件**：基于 authenticator 的中间件（消费 ctx.identity，接入
  T5-1 user/directory），补全 T6-1 已定义的 builtin 集合。
  四象限：Q1（认证成功/失败/拒绝/空凭据）+ Q2 + Q4（并发认证压测）。
- **T4-2 会话编排（runtime/session 等价物）**：accept → recognition（T2-4）→
  pipeline（auth/dial/mux/pad/relay）→ 统计上报。对齐主项目 session::diversion 语义。
  四象限：Q1（识别失败/未知协议/超时/管线中途拒绝/统计上报各路径）+ Q2 +
  Q4（E2E 连接风暴压测，验证会话生命周期无泄漏）。
- **T4-3 listener 骨架**：TCP listener + 亲和性分发（简化：单 ioc 或 worker 池）。
  验收：E2E 全链路（listener → 识别 → 管线 → 转发）。
  四象限：Q1（accept 失败/背压/优雅停止）+ Q2 + Q3（吞吐基准）+ Q4（高连接率压测）。
- **T4-4 统计中间件**：流量统计（up/down、identity 聚合）接入 relay 结束点。
  验收：多用户流量统计测试。
  四象限：Q1（0 流量/大流量/多 identity/并发上报）+ Q2 + Q3（统计热路径 bench，验证原子代价）+ Q4。
- **T4-5 管线超时/背压（D9）**：pipeline 级读超时注入（context 增加 timeout 字段，
  relay 中间件消费）+ 空闲超时可配置化（替换硬编码 300s）。验收：超时/背压单测。
  四象限：Q1（超时触发/未触发/0 禁用/背压阻塞/解除）+ Q2 + Q4（超时风暴压测）。

### T5 用户与设置（P2 — 运营层积木式实现）

> **详设**：`docs/NGX_OPS_DESIGN.md`（积木 O1-O7 + 热路径代价 + 测试计划）。
> **原则**：接口先行、积木独立、可替换、每积木独立测试 target。

- **T5-1 O1 认证积木**：`directory_authenticator`（对接 directory：存在性 + 凭据 +
  未禁用/未过期 → identity）。验收：存在/禁用/过期/错误凭据测试。
  四象限：Q1（全凭据分支矩阵）+ Q2 + Q4（并发认证压测，验证无锁）。
- **T5-2 O2 统计积木**：`per_worker_traffic`（alignas(64) 原子计数）+ 协议/用户双维度
  聚合 + COW 注册表（register/unregister/aggregate）+ 快照 POD。
  验收：单 worker 累加 / 多 worker 聚合一致性 / identity 维度测试。
  四象限：Q1（边界 0/最大值/溢出语义）+ Q2 + Q3（原子热路径 bench）+ Q4（16 worker 并发压测）。
- **T5-3 O3 账户积木**：`core/memory/cow_map` 下沉（模板化，O3/O6 共用）→ entry
  （原子字段 + 配额/过期/禁用预留）+ directory（upsert/remove/find/for_each）+
  lease（配额 RAII）。验收：CRUD/并发/for_each/配额判定测试。
  四象限：Q1（CRUD 全分支/并发读写/配额临界）+ Q2 + Q3（find 哈希 bench）+ Q4（COW 高压替换压测）。
- **T5-4 O4 限速积木**：`token_bucket`（rate/burst，1 CAS）+ `throttle_middleware` +
  `ban_middleware`（counter 达阈值动态封禁，带过期）。验收：速率/突发/耗尽 +
  throttle 全链路测试。
  四象限：Q1（速率边界/突发/耗尽/桶重置/封禁到期解封）+ Q2 + Q3（try_take CAS bench）+
  Q4（满速率风暴压测，验证限速精确性与无锁）。
- **T5-5 O5 可观测接口**：hdr/ewma/trace 三个 observer 纯接口 + mock。
  验收：接口编译 + mock 注入测试。
  四象限：Q1（每 observer 接口契约测试）+ Q2（mock 路径）。
- **T5-6 O5 可观测实现**：EWMA → HDR（~200 bucket，1 CAS）→ 采样追踪（1/N 原子 +
  SPSC ring 满即丢）。验收：bucket 精度 / EWMA 收敛 / 采样率统计测试。
  四象限：Q1（bucket 边界/溢出/ring 满丢旧/采样命中未命中）+ Q2 + Q3（record 原子 bench）+
  Q4（高速率记录压测，验证 ring 不阻塞）。
- **T5-7 O6 会话注册表**：`session_registry`（COW，值拷贝快照，严禁 L3 引用）。
  验收：并发读写 / 值拷贝语义 / 快照一致性测试。
  四象限：Q1（put/remove/查空/并发更新/源释放后快照有效）+ Q2 + Q3（COW 快照读 bench）+
  Q4（万级会话注册/注销压测 + 内存曲线）。
- **T5-8 O7 管理 API 接口**：`api_manager` 接口 + 资源树契约 + 骨架（独立 ioc，
  消费 O1-O6 快照类型）。验收：路由注册 / 鉴权拒绝（mock 数据源）测试。
  四象限：Q1（路由/鉴权/缺数据源/停止中请求）+ Q2（骨架路径）+ Q4（API 高负载下
  worker 延迟无劣化——bench 对比）。
- **T5-9 settings/loader**：配置加载（JSON + glaze）+ 校验（缺省/非法值）。
  验收：配置解析单测（含错误路径）。
  四象限：Q1（合法/缺失/非法类型/超范围/空文件）+ Q2 + Q4（反复加载压测，验证无泄漏）。
- **T5-10 stress 工具链（D7）**：tests/common/stress 从 helper 扩展为协议 stress 工具
  （连接风暴/并发流/UDP relay 长跑），ctest 注册 smoke 级用例。验收：stress 可运行不泄漏。
  四象限：Q4 为主（连接风暴/并发流/UDP 长跑/内存曲线），Q1 覆盖 helper 分支。

### T6 替代验证（P2 — 证明可替换主项目）

- **T6-1 对拍矩阵**：对 7+3 协议逐一跑「psmtest 实现 vs 主项目实现」互通 E2E
  （同一端口双实现交替收发）。验收：全协议双向通过。
  四象限：Q1（每协议对拍含坏包/超时路径）+ Q2 + Q4（对拍期间双实现并发压测）。
- **T6-2 Go 互操作**：用现有 tests/go（hysteria2/tuic/vmess/singvmess + 7 cmp）对拍
  psmtest 实现。验收：GoCompat/GoCmp 全绿。
- **T6-3 性能对标**：CodecPerf/AllProtoTransfer 类基准跑 psmtest 实现 vs 主项目 vs
  Go 参考，产出对比报告（docs/ngx-performance.md）。验收：不低于主项目同量级。
  四象限：Q3 为主（全协议基准 + 回归基线固化）。
- **T6-4 fuzz 扩展（D6）**：CodecFuzzTest 从 7 codec 扩展到 mux 帧、stealth 帧、
  http3/qpack + 结构化变异（边界长度/坏 magic/半帧）；评估 libFuzzer 化。
  验收：扩展 target 无崩溃。
  四象限：Q1 强化（每 target 定种子 + 边界字典）；配合 ASAN 构建跑短跑。
 - **T6-5 替换路线图**：产出「tests/common → src/prism 替代」迁移方案文档：
   模块映射、删除清单、双实现共存策略（如 feature 开关）、回归计划。
   验收：方案归档 docs/，并在测试数据文件记录核心结论。

### T7 质量加固（P2 — 四象限测试平台化，贯穿执行）

> 本任务把四象限要求**工具化**，让后续每个组件都能一键跑全象限。
> 可在 T0-T6 执行中逐步落地（T7-x 随依赖就绪即做），不阻塞主线。

- **T7-1 覆盖率基线**：跑一次全量覆盖率（G14 命令），产出 `docs/ngx-coverage-baseline.json`
  （各模块行/分支百分比），作为后续新增代码的对比基线。
  验收：基线文件生成；测试覆盖情况可查询。
- **T7-2 分支矩阵模板**：建立 `tests/quadrant/` 模板目录：分支核对清单模板
  （`BRANCH_CHECKLIST.md`，含 if/switch/边界/半包/坏数据/超时/取消分类）、
  gtest 骨架（`QuadrantFixture`，命名规范 `<Module>QuadrantTest`）。
  验收：模板可复制使用；样例（选 1 个既有模块）完成全分支标注。
- **T7-3 压测工具化**：`stresses/` 增加 `ngx-*` 系列（ngx-connection-storm、
  ngx-mux-streams、ngx-udp-relay、ngx-memory-curve），ctest 注册 smoke 用例
  （30s 短跑），长跑模式参数化（`--duration`）。验收：smoke 全绿 + 内存曲线无泄漏。
- **T7-4 性能基准固化**：`benchmarks/` 增加 ngx 系列基准（对齐 T0-T6 各 Q3 项），
  产出 `docs/bench-baseline.json` 固化基线，后续对比 ±3%。
  验收：基线文件 + CI/脚本可重复运行。
- **T7-5 四象限收口审计**：T0-T6 全部完成后，逐组件核对四象限完成度
  （覆盖率报告 vs 分支清单 vs 基准 vs 压测记录），产出 `docs/ngx-quadrant-report.md`。
  验收：报告覆盖全部新组件，无缺象限项。

---

## 4. 架构红线（低耦合高内聚）

1. **单一命名空间**：全库 `psmtest`，禁止 `psm_test`/`psmtest_test`/`psm::` 混用。
2. **单一传输接口**：所有模块（含 mux）使用 `transmission`；`transport_base`/
   `legacy_bridge` 只作为 T1-3 迁移中间态，迁移后删除。
3. **错误体系边界**：编解码错误走 `core/error.hpp`（Beast 风格）；中间件/流程错误按
   T1-2 决策固化，禁止新增第三种体系。
4. **依赖单向性**：core → protocol/stealth → mux → middleware；core 内
   transport → crypto/fault；禁止反向依赖。
5. **聚合头同步**：新增子头必须加入聚合头 + CMake target_sources。
6. **接口收敛**：函数参数 ≤3；opts 结构收敛构造参数；热路径 span 视图零拷贝。
7. **资源归属**：对象生命周期用 shared_ptr 值持有；detached 协程（若有）严禁引用
   session 级裸指针；热路径容器用 PMR（memory::vector/string）。
8. **测试伴随**：每个协议/模块三层测试（codec 纯函数 / 回环 session / 错误矩阵），
   异步测试用 `co_spawn + ioc.run()` 模式。
9. **主项目参照只读**：`src/prism/` 只作功能参照与互操作目标，**禁止修改**；
   除非用户明确要求。

---

## 5. 达标标准（DoD）

- [ ] T0-T7 顺序完成；T1 误导项（M1-M10）全部关闭并记录；D1-D9 全部落地
- [ ] 全量回归绿；G4（命名）、G5（接口）、G7（CMake）零命中
- [ ] 7+3 协议 + 3 mux + middleware 管线在统一架构下可用；runtime 骨架跑通全链路 E2E
- [ ] Go 互操作全绿；对拍矩阵全绿；性能报告产出
- [ ] **四象限完成**：每个新组件有分支清单（G13）+ 覆盖率达标（G14 ≥80%）+
  基准记录（G12）+ 压测记录（G15/G16）；`docs/ngx-test-data/INDEX.md` 无缺象限项、
  无 FAIL 状态
- [ ] 覆盖率基线、bench 基线、分支模板、stress 工具均已固化（T7）
- [ ] SPEC.md 与实现一致；替换路线图文档归档
- [ ] 进度文件完整（含决策/错误/SKIP 记录 + 末尾「待提交清单」）
- [ ] `docs/ngx-test-data/` 每个组件数据文件齐全且状态 PASS（用户查看的唯一依据）

---

## 6. 进度记录模板（docs/TASK_PROGRESS.md）

```markdown
# TASK_PROGRESS

> 自动维护。目标：tests/common → Next-Gen 架构（替换主项目）。
> 无人值守：只记录事实与决策，不向用户汇报。测试数据见 docs/ngx-test-data/。

## 总览
| 任务 | 状态 | 进度 | 备注 |
|---|---|---|---|
| T0 传输接口补齐 | pending/in_progress/done | 0-100% | D1：shutdown/set_timeout/is_open |
| T1 架构收口 | pending/in_progress/done | 0-100% | M1-M10 |
| T2 协议面补缺 | pending/in_progress/done | 0-100% | 含 D2 http2 真实实现 |
| T3 网络层 | pending/in_progress/done | 0-100% | 含 D4/D5 |
| T4 运行时骨架 | pending/in_progress/done | 0-100% | 含 D9 |
| T5 运营层积木 | pending/in_progress/done | 0-100% | O1-O7 + settings + stress，详设 NGX_OPS_DESIGN |
| T6 替代验证 | pending/in_progress/done | 0-100% | 含 D6 |
| T7 质量加固 | pending/in_progress/done | 0-100% | 四象限平台化，随主线落地 |

## 当前焦点
- 任务：T0-1 传输接口补全
- 单元：transmission 增加 shutdown/set_timeout/is_open
- 门禁：G1 / G2 / G4

## 已完成单元
- [x] 无（完成后记录：单元 → 数据文件路径 → PASS）

## 决策记录
- 错误体系：T1-2 决策后填写

## 错误日志
- 无

## SKIP 记录
- 无

## 后续候选
- 无

## 待提交清单（全部任务完成后生成，供用户处理）
- 无
```

---

## 7. 长任务执行提示词（一次性启动）

```text
你是 Prism Next-Gen 架构的长任务执行代理（任务规范：docs/NEXTGEN_TASK.md，必须先完整阅读）。
目标：把 tests/common（psmtest 库）演进为可替换主项目 src/prism 的新一代架构。
运行模式：一次性长任务，连续执行直到任务栈（T0-T7）完成。
无人值守：不向用户汇报、不请求确认、不自动 git commit/push；所有测试数据与结论
写入 docs/ngx-test-data/<组件>.md，用户只查看这些文件。

执行流程：
1. 读 docs/TASK_PROGRESS.md 确定当前任务与单元；不存在则按第 6 节模板初始化；
   全部 done → 汇总写入 docs/ngx-test-data/INDEX.md 并结束。
2. 按第 2 节单元流程推进：调研 → 改动 → 测试 → 门禁（G1-G16 适用项）。
3. 每单元门禁完成后，把原始数据（bench 表/gcovr 摘要/stress 日志尾部）写入
   docs/ngx-test-data/<组件>.md（模板见 2.4），自主分析四象限是否达标：
   - 全部 PASS → 更新 TASK_PROGRESS.md → 下一单元。
   - 任一 FAIL → 修复重跑并更新数据文件（≤3 次）；仍失败 → 简化方案或 SKIP
     （原因记入进度文件与数据文件）后继续。
4. 每单元结束清理本轮进程（G11）。

纪律：一次只动一个单元；不夹带无关改动；数据文件未 PASS 不得前进；不自动提交；
主项目 src/prism 只读参照、禁止修改；tests/common 之外的测试文件（tests/**）仅在
涉及链接/回归时修改；每单元必须有实际进展（改动或有效调研结论），禁止无产出空转；
全部任务完成后在 TASK_PROGRESS.md 末尾生成「待提交清单」（文件列表+摘要+建议 message）。
```
