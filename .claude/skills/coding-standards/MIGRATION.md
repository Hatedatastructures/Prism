---
name: coding-standards-migration
description: Prism 项目现有文件命名迁移对照表。从编码规范正文拆出的工程路线图，不是长期编码规则。
---

# 文件命名迁移路线图

本文档是 `coding-standards` 规范 Rule 2.2（文件名单词规则）的执行路线图。
迁移完成后本文件应归档删除。

## 迁移对照表

| 现有路径 | 推荐新路径 | 说明 |
|----------|-----------|------|
| `protocol/protocol_type.hpp` | `protocol/types.hpp` | types 语义更简洁 |
| `protocol/common/udp_relay.hpp` | `protocol/common/udprelay.hpp` | 合并为单词 |
| `recognition/layered_pipeline.hpp` | `recognition/pipeline.hpp` | 目录已提供上下文 |
| `recognition/scheme_route_table.hpp` | `recognition/routes.hpp` | 缩短 |
| `recognition/tls/feature_bitmap.hpp` | `recognition/tls/features.hpp` | 目录已提供上下文 |
| `stealth/anytls/mux/stream_transport.hpp` | `stealth/anytls/mux/transport.hpp` | 目录已提供上下文 |

对应的 `.cpp` 文件同步迁移。迁移时需更新所有 `#include` 引用和 CMakeLists.txt。
