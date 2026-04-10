---
name: cpp-lifetime-audit
description: C++ 代码变更后的生命周期、迭代器、资源指针安全审计。在每次修改 C++ 代码后自动触发，逐项检查生命周期、所有权、迭代器有效性、协程安全性等问题。
---

# Skill: C++ 生命周期与资源安全审计

在每次修改 C++ 代码后，必须对变更部分执行以下审计清单。逐项检查，发现问题立即修复。

## 触发条件

- 修改了涉及指针、引用、智能指针、迭代器的代码
- 修改了协程（`co_await`/`co_return`/`co_yield`）相关代码
- 修改了 `co_spawn`、`net::detached`、回调 lambda 相关代码
- 修改了容器操作（insert/erase/emplace）相关代码
- 修改了 RAII 对象（socket、file、lock、timer）相关代码
- 修改了 `std::move`/`std::forward` 相关代码

## 审计清单

### 1. 智能指针与所有权

| 检查项 | 说明 |
|--------|------|
| **shared_ptr 捕获** | `co_spawn` 的 lambda 是否捕获了 `self`（shared_ptr）以保持对象存活？协程可能在调用者退出后仍在运行 |
| **裸指针悬空** | 协程帧内是否持有裸 `this` 或裸指针？如果所指向的对象可能先于协程销毁，则存在 use-after-free |
| **weak_ptr 过期** | `weak_ptr::lock()` 后是否在使用前检查了返回值？lock() 与使用之间对象可能已销毁 |
| **unique_ptr 移动** | `std::move` 后是否不再访问源对象？移动后的 unique_ptr 为 nullptr |
| **shared_ptr 循环引用** | 父子对象是否互相持有 shared_ptr？应将一方改为 weak_ptr |

### 2. 协程与异步安全

| 检查项 | 说明 |
|--------|------|
| **co_spawn 生命周期** | `co_spawn` 启动的协程是否独立持有保持对象存活的 shared_ptr？不能依赖调用者的局部变量 |
| **lambda 捕获类型** | co_spawn 的 lambda 是按值捕获 shared_ptr 还是引用捕获？引用捕获在协程恢复时可能悬空 |
| **net::detached 风险** | 使用 `net::detached` 的协程没有任何回调来报告错误或管理生命周期，确保对象生命周期不依赖外部 |
| **挂起后重新获取指针** | `co_await` 挂起恢复后，之前获取的裸指针/迭代器/引用是否仍然有效？容器可能已被修改 |
| **close() 与协程竞态** | `close()` 关闭 socket 后，协程的 completion handler 执行时对象是否仍然存活？ |

### 3. 迭代器与容器安全

| 检查项 | 说明 |
|--------|------|
| **erase 后迭代器失效** | `erase()`/`insert()` 后是否更新了迭代器？循环中 erase 必须使用返回值 |
| **范围 for 中修改容器** | 范围 for 循环中是否调用了可能修改容器的操作（insert/erase/clear）？ |
| **map 迭代器失效** | `std::unordered_map::erase` 只使被删元素的迭代器失效，其他迭代器仍有效 |
| **vector 重新分配** | `push_back`/`resize` 可能触发重新分配，导致所有指针、引用、迭代器失效 |
| **并发容器访问** | 同一容器是否可能被多个线程/协程同时访问？是否需要加锁或使用 concurrent_channel？ |

### 4. RAII 资源管理

| 检查项 | 说明 |
|--------|------|
| **socket 关闭时序** | `close()` 后是否立即析构对象？pending 的异步操作 completion handler 是否需要对象存活？ |
| **timer 取消** | `timer.cancel()` 后是否等待关联协程退出？还是依赖 operation_aborted 错误码？ |
| **channel 取消** | `channel.cancel()` 后 send_loop 是否能安全退出？channel 中未消费的数据是否会导致资源泄漏？ |
| **析构顺序** | 成员变量的析构顺序是否正确？后构造的先析构，如果成员间有依赖关系是否安全？ |

### 5. 引用与悬挂引用

| 检查项 | 说明 |
|--------|------|
| **返回局部引用** | 函数是否返回了局部变量或临时对象的引用？ |
| **span 生命周期** | `std::span` 是否引用了可能先于 span 销毁的容器？例如函数返回 span 指向局部 vector |
| **string_view 悬空** | `std::string_view` 是否指向了临时 `std::string`？临时对象在表达式结束后销毁 |
| **co_await 后引用** | `co_await` 恢复后，之前持有的引用是否仍然有效？底层容器可能已被修改 |

### 6. PMR 与内存资源

| 检查项 | 说明 |
|--------|------|
| **PMR allocator 传播** | 移动 PMR 容器时 allocator 是否正确传播？不同 allocator 的容器之间的操作是否安全？ |
| **上游资源释放** | `monotonic_buffer_resource` 上分配的内存在 reset 前是否全部不再使用？ |
| **线程本地池** | `unsynchronized_pool_resource` 是否在正确的线程使用？跨线程使用会导致数据竞争 |

## 审计流程

1. **识别变更范围**：确定本次修改涉及的对象、函数、类
2. **追踪所有权链**：从创建点到使用点，确认每个对象的谁拥有、谁借用
3. **标注异步边界**：找出所有 `co_await` 和 `co_spawn`，标注挂起/恢复点
4. **逐项检查**：按上述清单检查每个变更点
5. **确认修复**：发现问题时立即修复，并在修复后重新审计受影响区域

## 常见反模式（禁止）

```cpp
// ❌ 协程不持有 shared_ptr，run() 退出后 craft 可能被销毁
net::co_spawn(executor(), self->send_loop(), net::detached);

// ✅ lambda 捕获 self，协程独立持有生命周期
auto wrapper = [self]() -> net::awaitable<void> { co_await self->send_loop(); };
net::co_spawn(executor(), std::move(wrapper), net::detached);

// ❌ erase 后使用旧迭代器
for (auto it = map.begin(); it != map.end(); ++it) {
    map.erase(it);  // it 失效！
}

// ✅ 使用 erase 返回值
for (auto it = map.begin(); it != map.end(); ) {
    it = map.erase(it);
}

// ❌ co_await 后使用前置引用
auto& ref = container[key];
co_await async_op();  // 挂起，container 可能被修改
ref.use();  // 可能悬空！

// ✅ co_await 后重新获取
co_await async_op();
auto& ref = container[key];  // 重新获取
```
