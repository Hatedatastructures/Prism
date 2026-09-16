#!/usr/bin/env bash
# detached 协程资源所有权审计
#
# 扫描所有 net::co_spawn + net::detached 的完整调用表达式，检测：
#   ❌ DANGEROUS：捕获 session 裸引用/指针、frame_arena.get() 等 L3 资源
#   ⚠ REVIEW   ：其他 detached 协程，需人工确认捕获列表或 operation helper
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

# 项目同时使用 net/Net 别名和 boost::asio 直接限定名，三种形式都必须进入审计范围。
DETACHED_PATTERN='(net|Net|boost::asio)::detached'
SPAWN_PATTERN='(net|Net|boost::asio)::co_spawn'

# 这些入口把真正的 awaitable 封装在 helper 调用中。它们不是 lambda
# capture，但仍是 detached 的 operation，必须作为独立审计项输出。
OPERATION_HELPERS='RunOperation|MaintenanceLoop|ServerCoroutine|server_coro[0-9]*|SessionOperation|EchoMemory|TcpEchoServer|writer'

files=$(grep -rlE "$SPAWN_PATTERN" "$ABS_SRC" --include="*.cpp" --include="*.hpp" 2>/dev/null || true)

if [[ -z "$files" ]]; then
    echo "✓ 未发现任何 net::detached 调用"
    exit 0
fi

echo "=== Prism detached 协程审计 ==="
echo "源目录：$ABS_SRC"
echo ""

extract_spawn_calls() {
    awk '
    function append_to_active(Text, Index) {
        for (Index = 1; Index <= CallCount; ++Index) {
            if (Active[Index]) {
                Expression[Index] = Expression[Index] Text
            }
        }
    }

    function count_char(Text, Character, Index, Count) {
        Count = 0
        for (Index = 1; Index <= length(Text); ++Index) {
            if (substr(Text, Index, 1) == Character) {
                ++Count
            }
        }
        return Count
    }

    function start_call(LineNumber, Token, Index) {
        for (Index = 1; Index <= CallCount; ++Index) {
            if (Active[Index]) {
                Expression[Index] = Expression[Index] Token
                Depth[Index] += count_char(Token, "(") - count_char(Token, ")")
            }
        }
        ++CallCount
        Active[CallCount] = 1
        StartLine[CallCount] = LineNumber
        Depth[CallCount] = 1
        Expression[CallCount] = Token
    }

    function finish_call(Index) {
        if (Expression[Index] ~ /(^|[^[:alnum:]_])((net|Net|boost::asio)::detached)([^[:alnum:]_]|$)/) {
            gsub(/[\t\r\n ]+/, " ", Expression[Index])
            print StartLine[Index] "\t" Expression[Index]
        }
        Active[Index] = 0
    }

    BEGIN {
        CallCount = 0
        InBlockComment = 0
        Quote = ""
        Escaped = 0
    }

    {
        Line = $0
        Position = 1
        while (Position <= length(Line)) {
            Character = substr(Line, Position, 1)
            Rest = substr(Line, Position)

            if (InBlockComment) {
                if (substr(Line, Position, 2) == "*/") {
                    append_to_active("*/")
                    InBlockComment = 0
                    Position += 2
                } else {
                    append_to_active(Character)
                    ++Position
                }
                continue
            }

            if (Quote != "") {
                append_to_active(Character)
                if (Escaped) {
                    Escaped = 0
                } else if (Character == "\\") {
                    Escaped = 1
                } else if (Character == Quote) {
                    Quote = ""
                }
                ++Position
                continue
            }

            if (substr(Line, Position, 2) == "//") {
                append_to_active(substr(Line, Position))
                break
            }
            if (substr(Line, Position, 2) == "/*") {
                append_to_active("/*")
                InBlockComment = 1
                Position += 2
                continue
            }
            if (Character == "\"" || Character == sprintf("%c", 39)) {
                append_to_active(Character)
                Quote = Character
                ++Position
                continue
            }

            if (Rest ~ /^(net|Net|boost::asio)::co_spawn[[:space:]]*\(/) {
                match(Rest, /^(net|Net|boost::asio)::co_spawn[[:space:]]*\(/)
                Token = substr(Rest, RSTART, RLENGTH)
                start_call(NR, Token)
                Position += RLENGTH
                continue
            }

            append_to_active(Character)
            if (Character == "(") {
                for (Index = 1; Index <= CallCount; ++Index) {
                    if (Active[Index]) {
                        ++Depth[Index]
                    }
                }
            } else if (Character == ")") {
                for (Index = 1; Index <= CallCount; ++Index) {
                    if (Active[Index]) {
                        --Depth[Index]
                    }
                }
                for (Index = CallCount; Index >= 1; --Index) {
                    if (Active[Index] && Depth[Index] == 0) {
                        finish_call(Index)
                    }
                }
            }
            ++Position
        }
    }
    ' "$1"
}

split_spawn_arguments() {
    awk '
    function trim(Text) {
        sub(/^[[:space:]]+/, "", Text)
        sub(/[[:space:]]+$/, "", Text)
        return Text
    }

    {
        Expression = $0
        Open = index(Expression, "(")
        if (Open == 0) {
            next
        }

        Parentheses = 1
        Brackets = 0
        Braces = 0
        Quote = ""
        Escaped = 0
        Argument = 1
        Arguments[1] = ""

        for (Position = Open + 1; Position <= length(Expression); ++Position) {
            Character = substr(Expression, Position, 1)
            if (Quote != "") {
                Arguments[Argument] = Arguments[Argument] Character
                if (Escaped) {
                    Escaped = 0
                } else if (Character == "\\") {
                    Escaped = 1
                } else if (Character == Quote) {
                    Quote = ""
                }
                continue
            }
            if (Character == "\"" || Character == sprintf("%c", 39)) {
                Quote = Character
                Arguments[Argument] = Arguments[Argument] Character
                continue
            }
            if (Character == "(") {
                ++Parentheses
            } else if (Character == ")") {
                --Parentheses
                if (Parentheses == 0) {
                    break
                }
            } else if (Character == "[") {
                ++Brackets
            } else if (Character == "]") {
                --Brackets
            } else if (Character == "{") {
                ++Braces
            } else if (Character == "}") {
                --Braces
            }

            if (Character == "," && Parentheses == 1 && Brackets == 0 && Braces == 0) {
                ++Argument
                Arguments[Argument] = ""
                continue
            }
            Arguments[Argument] = Arguments[Argument] Character
        }
        print trim(Arguments[2]) "\t" trim(Arguments[3])
    }
    '
}

while IFS= read -r f; do
    rel_path="${f#$ABS_SRC/}"
    while IFS=$'\t' read -r line expression; do
        [[ -z "$line" ]] && continue
        while IFS=$'\t' read -r operation completion; do
            [[ -z "$completion" ]] && continue
            if ! printf '%s\n' "$completion" | grep -qE "$DETACHED_PATTERN"; then
                continue
            fi

            if [[ "$operation" =~ ^[[:space:]]*(\[[^]]*\]) ]]; then
                lambda="${BASH_REMATCH[1]}"
                if printf '%s\n' "$lambda" | grep -qE "$DANGEROUS_PATTERN"; then
                    printf "❌ DANGEROUS %s:%d\n   capture: %s\n   建议：改为 shared_ptr 捕获或值拷贝，详见 docs/ARCHITECTURE.md\n\n" \
                        "$rel_path" "$line" "$lambda" >> "$tmp_danger"
                else
                    printf "⚠ REVIEW    %s:%d\n   capture: %s\n\n" \
                        "$rel_path" "$line" "$lambda" >> "$tmp_review"
                fi
            else
                helper_name="${operation%%(*}"
                helper_name="${helper_name//[[:space:]]/}"
                if [[ "$helper_name" =~ (^|::)($OPERATION_HELPERS)$ ]]; then
                    helper_label="configured operation helper"
                else
                    helper_label="operation helper"
                fi
                if printf '%s\n' "$operation" | grep -qE "$DANGEROUS_PATTERN"; then
                    printf "❌ DANGEROUS %s:%d\n   %s: %s\n   建议：改为 shared_ptr 捕获或值拷贝，详见 docs/ARCHITECTURE.md\n\n" \
                        "$rel_path" "$line" "$helper_label" "$operation" >> "$tmp_danger"
                else
                    printf "⚠ REVIEW    %s:%d\n   %s: %s\n\n" \
                        "$rel_path" "$line" "$helper_label" "$operation" >> "$tmp_review"
                fi
            fi
        done < <(printf '%s\n' "$expression" | split_spawn_arguments)
    done < <(extract_spawn_calls "$f")
done < <(printf '%s\n' "$files")

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
