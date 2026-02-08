// Learn more about clients at https://docs.boundaryml.com/docs/snippets/clients/overview

client<llm> GptOss {
  provider "openai-generic"
  options {
    base_url "http://localhost:8000/v1"
    api_key "EMPTY"
    model "openai/gpt-oss-20b"
    allowed_roles ["system", "developer", "assistant", "user"]
    default_role "user" // Required for using VLLM
    temperature 0.2
    reasoning_effort medium
  }
}

// https://docs.boundaryml.com/docs/snippets/clients/retry
retry_policy Constant {
  max_retries 3
  strategy {
    type constant_delay
    delay_ms 200
  }
}

retry_policy Exponential {
  max_retries 2
  strategy {
    type exponential_backoff
    delay_ms 300
    multiplier 1.5
    max_delay_ms 10000
  }
}