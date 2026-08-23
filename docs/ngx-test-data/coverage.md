# Preview 覆盖率报告

> 采集日期：2026-08-18 晚间
> 命令：`gcovr --root . --gcov-ignore-errors=no_working_dir_found --gcov-ignore-parse-errors=negative_hits.warn --merge-mode-functions=separate --filter "tests/common/" --exclude ".*_deps.*" --exclude ".*core/http[23].*" --html-details build/coverage.html --print-summary`
> 报告文件：`build/coverage.html`
> 数据来源：build/ 内各测试 exe 的 .gcda 积累（coverage 配置 Release 构建）

## 总体

| 指标 | 数值 |
|---|---|
| lines | 91.2%（7386/8102） |
| functions | 93.6%（1495/1597） |
| branches | 44.5%（5387/12094） |

## 说明

- lines/functions 超过 90%，公共库主线基本全覆盖；
- branches 44.5% 偏低主因是大量错误路径/边界分支（模板实例化 + 错误矩阵覆盖不均），后续按协议矩阵补错误路径可提升；
- 排除项：`tests/common/core/http2/`、`http3/` 为 CMakeLists 历史残留条目（源文件不存在），不影响真实覆盖；
- `statistics.hpp:92` 为 gcov 工具已知 bug（negative hits），已忽略。

## 与门禁的关系

- 当前 line 覆盖（91%）满足"主线全覆盖"要求；
- 建议下一步补分支覆盖：relay 关闭路径、mux 非法帧矩阵、udp_assoc/udp_tunnel 错误分支、XHTTP channel 背压路径。
