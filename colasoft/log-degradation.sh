#!/bin/bash

pushd `git rev-parse --show-toplevel`

# 使用 find 查找所有 .go 文件
find . -path "./colasoft" -prune -o -type f -name "*.go" -print | while read -r file; do
    # 将 Info/Debug 替换为 Trace
    sed -i 's/log\.Info/log.Trace/g' "$file"
    sed -i 's/log\.Infof/log.Tracef/g' "$file"
    sed -i 's/log\.Debug/log.Trace/g' "$file"
    sed -i 's/log\.Debugf/log.Tracef/g' "$file"
done

echo "修改日志级别成功"