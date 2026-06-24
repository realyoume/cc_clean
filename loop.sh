#!/usr/bin/env bash
set -u
set -o pipefail

BASE_URL="https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-21/segments/1778213376756.47/wet"
DATA_DIR="/root/cc_clean"
OUT_DIR="/root/cc_clean/filter"
LOG_DIR="/root/cc_clean/logs"

PYTHON="python"
SCRIPT="/root/cc_clean/security_segment_filter.py"

START_ID="${1:-0}"
END_ID="${2:-100}"
MAX_JOBS="${3:-4}"

mkdir -p "$DATA_DIR" "$OUT_DIR" "$LOG_DIR"

echo "============================================================"
echo "[INFO] START_ID: ${START_ID}"
echo "[INFO] END_ID:   ${END_ID}"
echo "[INFO] MAX_JOBS: ${MAX_JOBS}"
echo "============================================================"

# -----------------------------
# 核心处理函数
# -----------------------------
process_one() {
    local i="$1"
    local ID
    ID=$(printf "%05d" "$i")

    local FILE="CC-MAIN-20260508074046-20260508104046-${ID}.warc.wet.gz"
    local URL="${BASE_URL}/${FILE}"
    local INPUT="${DATA_DIR}/${FILE}"
    local OUTPUT="${OUT_DIR}/security_segments_candidates_${ID}.jsonl"
    local LOG="${LOG_DIR}/security_segments_candidates_${ID}.log"

    {
        echo "============================================================"
        echo "[INFO] Processing ${ID}"
        echo "[INFO] URL: ${URL}"
        echo "[INFO] INPUT: ${INPUT}"
        echo "[INFO] OUTPUT: ${OUTPUT}"
        echo "[INFO] Start: $(date '+%F %T')"

        # -----------------------------
        # 如果结果已存在：直接跳过 + 删除旧输入（防脏数据）
        # -----------------------------
        if [ -s "$OUTPUT" ]; then
            echo "[SKIP] Output exists"

            # 防止残留 WET
            rm -f "$INPUT"
            exit 0
        fi

        # -----------------------------
        # 下载（失败也会清理 INPUT）
        # -----------------------------
        echo "[INFO] Downloading..."
        if ! wget -q -c -O "$INPUT" "$URL"; then
            echo "[ERROR] Download failed"

            rm -f "$INPUT"
            exit 1
        fi

        # -----------------------------
        # 过滤（失败也清理 INPUT）
        # -----------------------------
        echo "[INFO] Filtering..."
        if ! "$PYTHON" "$SCRIPT" \
            --input "$INPUT" \
            --output "$OUTPUT" \
            --target-segment-chars 1200 \
            --max-segment-chars 1800 \
            --min-segment-chars 300 \
            --overlap-chars 150 \
            --no-count
        then
            echo "[ERROR] Filter failed"

            rm -f "$INPUT"
            exit 1
        fi

        # -----------------------------
        # 成功也要清理 INPUT
        # -----------------------------
        rm -f "$INPUT"

        echo "[DONE] ${ID}"
        echo "[INFO] End: $(date '+%F %T')"

    } > "$LOG" 2>&1
}

# -----------------------------
# 并发控制
# -----------------------------
running_jobs=0
failed_jobs=0

for i in $(seq "$START_ID" "$END_ID"); do
    ID=$(printf "%05d" "$i")
    LOG="${LOG_DIR}/security_segments_candidates_${ID}.log"

    echo "[LAUNCH] $(date '+%F %T') ${ID} -> ${LOG}"

    process_one "$i" &
    running_jobs=$((running_jobs + 1))

    if [ "$running_jobs" -ge "$MAX_JOBS" ]; then
        if ! wait -n; then
            failed_jobs=$((failed_jobs + 1))
        fi
        running_jobs=$((running_jobs - 1))
    fi
done

# -----------------------------
# 收尾
# -----------------------------
while [ "$running_jobs" -gt 0 ]; do
    if ! wait -n; then
        failed_jobs=$((failed_jobs + 1))
    fi
    running_jobs=$((running_jobs - 1))
done

echo "============================================================"
echo "[INFO] Done"
echo "[INFO] Failed jobs: ${failed_jobs}"
echo "[INFO] Logs: ${LOG_DIR}"
echo "============================================================"

exit $((failed_jobs > 0))