#!/usr/bin/env python3
"""Copy the harness documentation starter into an existing repository."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="为现有仓库创建不覆盖已有文件的智能体文档脚手架。"
    )
    parser.add_argument("--target", required=True, type=Path, help="现有仓库的根目录")
    parser.add_argument(
        "--force", action="store_true", help="覆盖已有的文档模板文件"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target.expanduser().resolve()
    source = Path(__file__).resolve().parents[1] / "assets" / "repository-docs"

    if not target.is_dir():
        print(f"错误：目标不是目录：{target}", file=sys.stderr)
        return 2
    if not source.is_dir():
        print(f"错误：未找到模板资源：{source}", file=sys.stderr)
        return 2

    created: list[Path] = []
    preserved: list[Path] = []
    for template in sorted(source.rglob("*")):
        if not template.is_file():
            continue
        relative_path = template.relative_to(source)
        destination = target / relative_path
        if destination.exists() and not args.force:
            preserved.append(relative_path)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(template, destination)
        created.append(relative_path)

    for relative_path in created:
        print(f"已创建：{relative_path}")
    for relative_path in preserved:
        print(f"已保留：{relative_path}")
    print(f"汇总：已创建={len(created)} 已保留={len(preserved)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
