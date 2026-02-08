client<llm> GptOss {
  provider "openai-generic"
  options {
    base_url "http://localhost:8000/v1"
    api_key "EMPTY"
    model "openai/gpt-oss-20b"
    allowed_roles ["system", "developer", "assistant", "user"]
    default_role "user"
    temperature 0.2 
    reasoning_effort medium
  }
}
