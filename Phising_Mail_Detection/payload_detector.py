from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import uvicorn
from openai import OpenAI

# Initialize FastAPI app
app = FastAPI(
    title="Payload Type Detector with Open AI",
    description="API to detect command payload types using Open AI",
    version="1.0.0"
)

# Initialize Open AI client
client = OpenAI(api_key="your-openai-api-key")  # Replace with your Open AI API key

# Define the expected JSON payload structure using Pydantic
class Payload(BaseModel):
    data: Dict[str, Any]

# Function to analyze payload using Open AI
def analyze_payload_with_openai(payload: Dict[str, Any]) -> str:
    """
    Sends the payload to Open AI for analysis and returns the detected type.
    """
    try:
        # Create a prompt for Open AI
        prompt = (
            "You are a cybersecurity expert. Analyze the following JSON payload for potential threats "
            "and determine its command payload type (e.g., command injection, SQL injection, script payload, safe, etc.). "
            "Provide a concise response with the detected type and a brief explanation:\n\n"
            f"Payload: {payload}"
        )

        # Call Open AI API
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # You can use "gpt-3.5-turbo" if you don't have access to GPT-4
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,  # Limit response length
            temperature=0.5  # Adjust for creativity (lower = more deterministic)
        )

        # Extract and return the result
        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Error analyzing payload with Open AI: {str(e)}"

# Define the API endpoint
@app.post("/detect-payload/")
async def detect_payload(payload: Payload):
    """
    Endpoint to receive JSON payload and detect its type using Open AI.
    Example request: {"data": {"cmd": "system('whoami')"}}
    """
    try:
        result = analyze_payload_with_openai(payload.data)
        return {
            "status": "success",
            "payload": payload.data,
            "detected_type": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {str(e)}")

# Root endpoint for testing
@app.get("/")
async def root():
    return {"message": "Welcome to the Payload Type Detector API with Open AI"}

# Run the app
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)