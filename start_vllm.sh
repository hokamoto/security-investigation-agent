uv run vllm serve openai/gpt-oss-20b \
  --gpu-memory-utilization 0.94 \
  --max-model-len auto \
  --max-num-seqs 1 \
  --max-num-batched-tokens 2048 \
  --async-scheduling \
  --tool-call-parser openai \
  --reasoning-parser openai_gptoss