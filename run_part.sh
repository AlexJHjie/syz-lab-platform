#!/bin/bash

ids=(
4649ea695ca98903ae82280a3b7aa97dbeb7fd07
9b857c714d3e890900acbe48172866a93ab8589a
fc06b7648458c074fcb68b09007fdc1877827791
)

total=${#ids[@]}
success=0
failed=0

mkdir -p work/case_logs

for i in "${!ids[@]}"; do
    id="${ids[$i]}"
    log_file="work/case_logs/${id}.log"

    echo "[$((i+1))/$total] Running: $id"

    # 执行任务，同时打印并保存输出
    syzrun run "/path/to/KBenchSYZ/${id}.json" \
        --work-dir work --timeout 30m \
        2>&1 | tee "$log_file"

    # 只根据输出中的 verdict 判断是否复现成功
    if grep -Fq "verdict: reproduced (matched in attempt 1)" "$log_file"; then
        echo "SUCCESS: $id"
        ((success+=1))
    else
        echo "FAILED: $id (skipping)"
        ((failed+=1))
    fi

    echo "--------------------------------"
done

echo "================================"
echo "All cases finished!"
echo "Total:   $total"
echo "Success: $success"
echo "Failed:  $failed"