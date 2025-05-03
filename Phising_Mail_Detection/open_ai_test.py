from openai import OpenAI
import os
from dotenv import load_dotenv  # Import load_dotenv from dotenv

load_dotenv()
print(os.getenv('OPENAI_API_KEY'))
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}]
)
print(response.choices[0].message.content)