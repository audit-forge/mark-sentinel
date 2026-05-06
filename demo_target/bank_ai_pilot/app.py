from openai import OpenAI

api_key = "sk-fake-hardcoded-in-source-abc1234567890def"

client = OpenAI(api_key=api_key)

SYSTEM_PROMPT = "You are a PNC Bank AI assistant. Help customers with banking questions."

def chat(user_message):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    while True:
        user_input = input("Customer: ")
        reply = chat(user_input)
        print(f"Assistant: {reply}")
