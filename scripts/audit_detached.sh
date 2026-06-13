#!/usr/bin/env bash
# detached 协程资源所有权审计
#
# 扫描所有 net::co_spawn + net::detached 的 lambda 捕获，检测：
#   ❌ DANGEROUS：捕获 session 裸引用/指针、frame_arena.get() 等 L3 资源
#   ⚠ REVIEW   ：其他 detached 协程，需人工确认捕获列表
#
# 用法：bash scripts/audit_detached.sh [src_dir]
# 默认 src_dir=src
#
# 详见 docs/ARCHITECTURE.md "资源所有权模型"
#
# 退出码：
#   0 - 无 DANGEROUS（REVIEW 项需人工确认）
#   1 - 发现 DANGEROUS 捕获

set -euo pipefail

SRC="${1:-src}"

if [[ ! -d "$SRC" ]]; then
    echo "错误：源目录不存在：$SRC" >&2
    exit 2
fi

ABS_SRC="$(cd "$SRC" && pwd)"

# 危险捕获模式（正则）
DANGEROUS_PATTERN='session\s*[&*]|frame_arena\.get|ctx\.inbound\s*[&]|ctx\.outbound\s*[&]|&ctx\.session'

# 临时文件收集结果
tmp_danger=$(mktemp)
tmp_review=$(mktemp)
trap 'rm -f "$tmp_danger" "$tmp_review"' EXIT

# 找到所有包含 net::detached 的源文件
files=$(grep -rlE "net::detached" "$ABS_SRC" --include="*.cpp" --include="*.hpp" 2>/dev/null || true)

if [[ -z "$files" ]]; then
    echo "✓ 未发现任何 net::detached 调用"
    exit 0
fi

echo "=== Prism detached 协程审计 ==="
echo "源目录：$ABS_SRC"
echo ""

for f in $files; do
    rel_path="${f#$ABS_SRC/}"

    # 用 grep -o 获取所有 co_spawn 行号
    spawn_lines=$(grep -nE "net::co_spawn\(" "$f" 2>/dev/null | cut -d: -f1 || true)

    for line in $spawn_lines; do
        # 取 co_spawn 后 40 行作为分析窗口（lambda + co_spawn 后面的 detached）
        end_line=$((line+40))
        window=$(sed -n "${line},${end_line}p" "$f")

        # 必须在同一窗口内出现 net::detached
        if ! echo "$window" | grep -q "net::detached"; then
            continue
        fi

        # 提取 lambda 捕获 [...]（第一个出现的方括号对）
        lambda=$(echo "$window" | grep -m1 -oE '\[[^]]+\]' || true)
        if [[ -z "$lambda" ]]; then
            continue
        fi

        # 跳过空捕获 / 隐式捕获
        if [[ "$lambda" =~ ^\[\]$ || "$lambda" =~ ^\[=\]$ ]]; then
            continue
        fi

        # 检测危险模式
        if echo "$lambda" | grep -qE "$DANGEROUS_PATTERN"; then
            printf "❌ DANGEROUS %s:%d\n   lambda: %s\n   建议：改为 shared_ptr 捕获或值拷贝，详见 docs/ARCHITECTURE.md\n\n" \
                "$rel_path" "$line" "$lambda" >> "$tmp_danger"
        else
            printf "⚠ REVIEW    %s:%d\n   lambda: %s\n\n" \
                "$rel_path" "$line" "$lambda" >> "$tmp_review"
        fi
    done
done

# 输出结果
cat "$tmp_danger"
cat "$tmp_review"

# 计数（grep -c 在无匹配时返回 1 + 输出 0，set -e 会触发，所以用 || true）
danger_count=$(grep -c "^❌" "$tmp_danger" || true)
review_count=$(grep -c "^⚠" "$tmp_review" || true)
[[ -z "$danger_count" ]] && danger_count=0
[[ -z "$review_count" ]] && review_count=0

echo "=== 审计结果 ==="
echo "DANGEROUS: $danger_count"
echo "REVIEW:    $review_count"
echo ""

if [[ "$danger_count" -gt 0 ]]; then
    echo "❌ 发现 $danger_count 处危险 detached 协程捕获，请修复后重试"
    echo "   参考 docs/ARCHITECTURE.md 中 'detached 协程规则'"
    exit 1
fi

echo "✓ 审计通过：未发现 DANGEROUS 捕获"
echo "  REVIEW 项需人工确认捕获列表无 L3 资源依赖"
exit 0
