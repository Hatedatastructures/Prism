# 常见问题

## Prism 默认从哪里读取配置？

命令行提供了第一个参数时，使用该参数的配置路径；否则读取可执行文件同目录下的 `PrismConfiguration.json`。

## 配置文件里的 SecretRef 应该写真实密码吗？

不需要。配置保存引用名，程序通过 `PRISM_SECRET_` 前缀的环境变量解析对应值。环境变量名的构造规则见[配置说明](configuration.md)。

## 配置中出现协议名称，是否说明程序一定支持它？

不一定。配置能力必须和当前构建中的 protocol/carrier binding 一致，并通过启动能力校验。协议实现与测试以 `Include/Prism/Protocols/`、`Src/Prism/Protocols/` 和 `Test/Prism/Protocols/` 为准；本手册不提供逐协议专题页。

## CTest 通过是否表示所有场景都通过？

只表示本次实际运行且通过的注册用例。互操作、Linux、压力、性能和真实部署请求需要单独执行并记录。
