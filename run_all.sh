#!/bin/bash

mkdir -p work/case_logs

success=0
failed=0
total=0

shopt -s nullglob
cases=(../KBenshSYZ/*.json)
total=${#cases[@]}

# 从中断点时启用
# START_ID="4e787d7ede986c6bdabd8a46e10dcee11b5768c7"
# started=false
# ---

for i in "${!cases[@]}"; do
    # 从中断点时启用
    # id=$(basename "${cases[$i]}" .json)

    # if [[ "$id" == "$START_ID" ]]; then
    #     started=true
    # fi

    # if [[ "$started" == false ]]; then
    #     continue
    # fi
    #---
    
    case_file="${cases[$i]}"
    id=$(basename "$case_file" .json)
    log_file="work/case_logs/${id}.log"

    echo "[$((i+1))/$total] Running: $id"

    syzrun run "$case_file" \
        --work-dir work --timeout 30m \
        2>&1 | tee "$log_file"

    # 只有指定 verdict 才算成功
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