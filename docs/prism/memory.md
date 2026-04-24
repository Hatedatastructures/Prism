# Memory 模块

**源码位置**: `include/prism/memory/`

PMR（多态内存资源）容器和分配器，实现热路径零堆分配。

## 文件结构

```
memory/
├── pool.hpp         # 全局内存池、线程独占池、frame_arena、system 类
└── container.hpp    # PMR 容器类型别名
```

## 核心类型

| 类型 | 说明 |
|------|------|
| `memory::string` | `std::pmr::string` |
| `memory::vector<T>` | `std::pmr::vector<T>` |
| `memory::map<K,V>` | `std::pmr::map<K,V>` |
| `memory::unordered_map<K,V>` | `std::pmr::unordered_map<K,V>` |
| `memory::list<T>` | `std::pmr::list<T>` |
| `memory::unordered_set<T>` | `std::pmr::unordered_set<T>` |
| `memory::resource_pointer` | `std::pmr::memory_resource*` |
| `memory::frame_arena` | 单调增长资源，会话级临时分配 |
| `memory::system::thread_local_pool()` | 线程独占内存池 |

## 使用约定

1. 启动时调用 `memory::system::enable_global_pooling()` 初始化全局池
2. 热路径容器使用 `memory::` 命名容器
3. 会话级临时数据使用 `frame_arena`
4. 线程独占数据使用 `thread_local_pool()`
