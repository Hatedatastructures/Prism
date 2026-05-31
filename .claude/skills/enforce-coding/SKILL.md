---
name: enforce-coding
description: 编写或修改任何 C++ 代码时必须遵循此规范。
---

# Skill: C++ 编码规范

## 触发条件

编写或修改任何 C++ 代码时必须遵循此规范。

> **优先级声明**：本项目（Prism）的编码规范以本 skill 为准。用户级通用 C++ 规范（如 `cpp-code-rules`、`cpp-doxygen-comment`）与本规范冲突时，以本规范为准。关键差异：行宽 200 字符（非 100）、函数体 120 行（非 100）、include 顺序（项目 → 第三方 → 标准库）、禁止 std::mutex（协程架构）、Doxygen 仅限 .hpp 文件（非全部 C++ 文件）。

## 1. 函数参数上限

**规则：函数参数不超过 3 个。** 超过 3 个时必须用结构体收敛。这个函数包括类里面的构造等所有函数

```cpp
// 禁止：4 个参数
auto connect(const memory::string &host, std::uint16_t port, bool use_tls, std::uint32_t timeout) 
    -> net::awaitable<void>;

// 正确：结构体收敛
struct connect_options
{
    memory::string host;
    std::uint16_t port = 0;
    bool use_tls = false;
    std::uint32_t timeout_ms = 5000;
};

auto connect(connect_options opts) 
    -> net::awaitable<void>;
```

**例外**：第三方 C 库回调签名（无法修改）。
- `main()` 函数
- 构造函数的成员初始化列表（但鼓励用结构体收敛配置参数）

## 审查清单

每次编写或修改 C++ 代码后，逐项检查：

- [ ] 函数参数 <= 3 个？
- [ ] 函数体 <= 120 行？
- [ ] 标识符最多 2 个词（1 个下划线）？
- [ ] 文件名只用单词（多词用目录分层）？
- [ ] 命名全 snake_case（测试函数除外）？
- [ ] 纯数据用 struct，有行为/不变量用 class？
- [ ] 枚举用 enum class + 底层类型？
- [ ] 类型过长时用 using 别名？
- [ ] 尾随返回类型中 void 用直接 `void func()`，非 void 用 `auto func() -> type`？
- [ ] 局部变量允许 auto，函数参数/类成员禁止 auto 推导？
- [ ] auto 引用严格区分值语义 / const auto& 只读 / auto&& 完美转发？
- [ ] 所有构造函数标注 explicit？
- [ ] .hpp 中 Doxygen 文档，.cpp 中只用 `//` 行注释？
- [ ] .hpp 中无多余 include（优先前向声明）？
- [ ] unique_ptr 前向声明的类型，析构函数在 .cpp 中定义？
- [ ] include 按四组排序，项目内用尖括号？
- [ ] 无 `using namespace std/boost`？
- [ ] 有意义的返回值标注 `[[nodiscard]]`？
- [ ] 热路径容器用 PMR 类型？
- [ ] 虚函数重写标注 override？
- [ ] 使用固定宽度整数类型？
- [ ] 禁止 bool 函数参数，用枚举替代（bool 成员字段允许）？
- [ ] 头文件保护用 `#pragma once`？
- [ ] TODO 格式正确且有标签？
- [ ] 析构函数和移动操作标 noexcept？
- [ ] 使用 `nullptr` 而非 `NULL`/`0`？
- [ ] 编译期能计算的用 constexpr？
- [ ] std::move 用于转移所有权，std::forward 仅用于完美转发？
- [ ] 新增头文件已同步更新聚合头文件？
- [ ] 行宽不超过 200 字符？
- [ ] 缩进 4 空格，无 Tab？
- [ ] 函数/类/命名空间和控制结构的开括号均独占一行（Allman 风格）？
- [ ] 返回类型独占一行，尾随返回换行缩进 4 空格？
- [ ] 函数参数不换行（超过 3 个用结构体收敛）？
- [ ] 命名空间括号独占一行，括号后空 1 行？
- [ ] 函数间 2 空行，逻辑段间 1 空行？
- [ ] switch/case 同级不缩进？
- [ ] const 在类型左侧（`const T&`）？
- [ ] 初始化列表无尾随逗号？
- [ ] 函数间空行规范（头文件 1 行，源文件 2 行）？
- [ ] lambda 提取为命名变量，co_spawn 用 std::move？

---

## 规则详情（按需加载）

- 语义规则（命名规范 2、函数体 3、头文件 4、注释 5、返回类型 6、nodiscard 7、PMR 8、using 9、auto 10-11、const 12、错误处理 13、lambda 14、头文件保护 15、TODO 16、访问排序 17、命名空间 18、override 19、构造函数 20、整数类型 21、成员访问 22、类型安全 23）详见 semantic-rules.md。
- 类型系统规则（struct/class 24、enum 25、智能指针 26、noexcept 27、特殊成员 28、nullptr 29、constexpr 30、初始化 31、static 32、模板 33、move/forward 34）和格式化规范详见 type-and-style.md。
- 生命周期与资源安全审计（智能指针所有权、协程异步安全、迭代器容器安全、RAII、悬挂引用、PMR）详见 co-lifecycle-audit。
