#!/usr/bin/env bash
set -u

BASE_URL="https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-21/segments/1778213376756.47/wet"
DATA_DIR="/root/xk/cc_security"
OUT_DIR="/root/xk/cc_security/filter"
PYTHON="/root/.local/share/mamba/envs/dev/bin/python"
SCRIPT="security_segment_filter.py"

mkdir -p "$OUT_DIR"

for i in $(seq 0 100); do
    ID=$(printf "%05d" "$i")

    FILE="CC-MAIN-20260508074046-20260508104046-${ID}.warc.wet.gz"
    URL="${BASE_URL}/${FILE}"
    INPUT="${DATA_DIR}/${FILE}"
    OUTPUT="${OUT_DIR}/security_segments_candidates_${ID}.jsonl"

    echo "============================================================"
    echo "[INFO] Processing ${ID}"
    echo "[INFO] URL: ${URL}"
    echo "[INFO] INPUT: ${INPUT}"
    echo "[INFO] OUTPUT: ${OUTPUT}"

    if [ -s "$OUTPUT" ]; then
        echo "[SKIP] Output already exists: ${OUTPUT}"
        continue
    fi

    echo "[INFO] Downloading..."
    wget -c -O "$INPUT" "$URL"

    if [ $? -ne 0 ]; then
        echo "[ERROR] Download failed: ${URL}"
        rm -f "$INPUT"
        continue
    fi

    echo "[INFO] Filtering..."
    "$PYTHON" "$SCRIPT" \
        --input "$INPUT" \
        --output "$OUTPUT" \
        --target-segment-chars 1200 \
        --max-segment-chars 1800 \
        --min-segment-chars 300 \
        --overlap-chars 150

    if [ $? -ne 0 ]; then
        echo "[ERROR] Filter failed: ${INPUT}"
        continue
    fi

    echo "[INFO] Removing WET file..."
    rm -f "$INPUT"

    echo "[DONE] ${ID}"
done

echo "All done."