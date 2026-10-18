# 旧版 Prism 资料边界

旧实现位于 `include/prism/`、`src/prism/` 和旧测试树；这些路径已经退役，不属于当前构建目标，也没有兼容层。旧版的 API、协议工厂、PMR 容器别名和 L1/L2/L3/L4 资源模型不得用于新增或修改当前 Prism 代码。

仍然适用的通用原则是：协程挂起后检查借用对象生命周期，异步 I/O 由规定 executor 驱动，资源由真实 owner 关闭并 drain。当前规则见 [Prism 所有权与异步生命周期](../prism/ownership-and-lifecycle.md)。
