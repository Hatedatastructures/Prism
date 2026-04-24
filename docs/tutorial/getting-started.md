# 快速开始

## 从源码编译

```bash
git clone https://github.com/Hatedatastructures/prism.git
cd Prism
cmake -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release --config Release
```

## 基本配置

配置文件位于 `src/configuration.json`。程序启动时会优先查找 exe 同目录下的 `configuration.json`，也可通过命令行参数 `--config <path>` 指定路径。最简配置：

```json
{
  "agent": {
    "addressable": {
      "host": "0.0.0.0",
      "port": 8081
    }
  }
}
```

更多配置项参考 [configuration.md](configuration.md)。

## 启动与测试

1. **启动**: 运行 `build_release/src/Prism.exe`
2. **测试 HTTP 代理**:
   ```cmd
   curl -v -x http://127.0.0.1:8081 http://www.baidu.com
   ```
3. **浏览器**: 代理设置填入 `127.0.0.1:8081`

看到网页内容即表示代理工作正常。
