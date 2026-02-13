// Translation function for non-English user questions

class TranslationResult {
  original_language string @description("The detected language name in English, e.g. 'Japanese', 'Spanish'")
  translated_question string @description("The question translated into English")
}

function TranslateQuestion(user_question: string) -> TranslationResult {
  client GptOss
  prompt #"
    {{ _.role("system") }}
    You are a translator. Detect the language of the user's question and translate it into English.
    Preserve all technical terms, hostnames, IP addresses, and timestamps exactly as they appear.
    Assume the original question relates to security logs of web application firewalls.

    Original text:
    {{ _.role("user") }}
    {{ user_question }}

    {{ _.role("system") }}
    {{ ctx.output_format }}
  "#
}
