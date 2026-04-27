# Memory 模块

**源码位置**: `include/prism/memory/`（header-only）

PMR（多态内存资源）容器和分配器，实现热路径零堆分配。

## 文件结构

```
memory/
├── pool.hpp         # 全局内存池、线程独占池、frame_arena、system 类
└── container.hpp    # PMR 容器类型别名（string、vector、map 等）
```

## 核心类型

| 类型 | 说明 |
|------|------|
| `memory::resource` | `std::pmr::memory_resource`，内存资源基类 |
| `memory::resource_pointer` | `std::pmr::memory_resource*`，内存资源指针 |
| `memory::allocator<T>` | `std::pmr::polymorphic_allocator<T>`，多态分配器模板 |
| `memory::synchronized_pool` | `std::pmr::synchronized_pool_resource`，线程安全池 |
| `memory::unsynchronized_pool` | `std::pmr::unsynchronized_pool_resource`，非线程安全池 |
| `memory::monotonic_buffer` | `std::pmr::monotonic_buffer_resource`，单调增长缓冲区 |
| `memory::string` | `std::pmr::string`，使用全局池或帧竞技场 |
| `memory::vector<T>` | `std::pmr::vector<T>` |
| `memory::map<K,V>` | `std::pmr::map<K,V>` |
| `memory::unordered_map<K,V>` | `std::pmr::unordered_map<K,V>` |
| `memory::list<T>` | `std::pmr::list<T>` |
| `memory::unordered_set<T>` | `std::pmr::unordered_set<T>` |
| `memory::frame_arena` | 单调增长资源，会话级临时分配 |
| `memory::current_resource()` | 获取当前默认内存资源 |
| `memory::system::thread_local_pool()` | 线程独占内存池 |

## 使用约定

1. 启动时必须调用 `memory::system::enable_global_pooling()` 初始化全局池
2. 热路径容器使用 `memory::` 命名容器而非 `std::` 容器
3. 会话级临时数据使用 `frame_arena`（单调分配，会话结束释放）
4. 线程独占数据使用 `thread_local_pool()`

## 性能考量

- **全局池**: 跨线程共享，适合长期存活对象
- **帧竞技场**: 单调分配器，零释放开销，适合会话级临时数据
- **线程本地池**: 避免锁竞争，适合单线程高频分配场景
