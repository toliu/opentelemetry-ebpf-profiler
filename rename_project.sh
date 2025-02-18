#!/bin/bash

# 设置新的项目路径
OLD_PATH="go.opentelemetry.io/ebpf-profiler"
NEW_PATH="github.com/toliu/opentelemetry-ebpf-profiler"

# 使用 find 查找所有 .go 文件
find . -type f -name "*.go" | while read -r file; do
    # 使用 sed 替换 import 语句中的路径
    sed -i "s|\"${OLD_PATH}|\"${NEW_PATH}|g" "$file"
    
    # 替换注释中的路径
    sed -i "s|${OLD_PATH}|${NEW_PATH}|g" "$file"
    
    # 将 log.Info 替换为 log.Trace
    sed -i 's/log\.Info/log.Trace/g' "$file"
    sed -i 's/log\.Infof/log.Tracef/g' "$file"
done

# 替换 go.mod 中的模块名
sed -i "1s|^module.*|module ${NEW_PATH}|" go.mod

echo "项目重命名完成!" 