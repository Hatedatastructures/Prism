# account 模块（已实现）

账户/用户认证与目录模块，T5 阶段已落地：

- `cow_map.hpp` — 模板化 COW（写时复制）映射：快照 + CAS 更新
- `directory.hpp` — 账户目录：entry 原子活跃计数 + lease RAII + try_acquire CAS
- `authenticator.hpp` — `directory_authenticator`：未禁用 / 未过期 / 配额校验

配套消费方：`core/middleware/builtin/auth.hpp`（中间件）、`core/runtime/session.hpp`（会话）。

> 历史备注：本目录曾为「预留」占位（计划从主库 `user/` 移植），现已由 preview 库自行实现。
