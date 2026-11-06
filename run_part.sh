#!/bin/bash

ids=(
0264f823322ea8600fbe3fb7e9e016569ca542d8
32c85d199d85c11202246570956a2cbe272f235a
43332d148577054abb1088752ddad8730beee2f9
47ff89a13ed39d393e043ec2715452a5b23ce8b2
5e2e50e2c145ca06459e9e0900c20eefd1a0877e
724cf869d3bb512081588651530d8071a4b61ceb
74c4de068e77c137156235cc06a904c9baea491f
7ba391f8e821454d748011f0dbd3ed0f862dfb78
80cd1e9033a1460be92ea438e6c5b8e0ef52101a
d21cb12ee03822236d82ba4e83a1f8968e7832fb
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
    syzrun run "../KBenchSYZ/${id}.json" \
        --work-dir work --timeout 30m \
        2>&1 | tee "$log_file"

    # 仅完整的 verdict: reproduced 行算成功
    if grep -Fxq 'verdict: reproduced' "$log_file"; then
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
