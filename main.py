from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
from urllib.parse import parse_qs, unquote
import hmac
import hashlib
import json

app = FastAPI()

# --- CORS Configuration ---
# You should restrict this to the actual origin of your Mini App in production
origins = ["*"]  # For development, allow all.

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# It's crucial to get the bot token from environment variables for security.
BOT_TOKEN = os.environ.get("7225306313:AAHpTF-10ovexz4jQlS-QGimiLXfjiieHyw")


class URLPayload(BaseModel):
    url: str


def validate_init_data(init_data: str, bot_token: str) -> dict | None:
    """Validates the initData string from the Telegram Mini App."""
    try:
        # The initData is URL-encoded.
        unquoted_data = unquote(init_data)

        # Split data into hash and other params
        data_parts = sorted([
            part.split('=', 1) for part in unquoted_data.split('&')
            if part.split('=', 1)[0] != 'hash'
        ])

        data_check_string = "\n".join(
            [f"{key}={value}" for key, value in data_parts])

        # Extract the hash from the original query string
        received_hash = dict(part.split('=', 1)
                             for part in unquoted_data.split('&')).get('hash')
        if not received_hash:
            return None

        # Generate the secret key and calculate the hash
        secret_key = hmac.new("WebAppData".encode(),
                              bot_token.encode(), hashlib.sha256).digest()
        calculated_hash = hmac.new(
            secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

        # Compare hashes
        if hmac.compare_digest(received_hash, calculated_hash):
            # Return parsed user data on success
            user_data_str = dict(data_parts).get('user')
            if user_data_str:
                return json.loads(user_data_str)
        return None
    except Exception:
        return None


@app.post("/upload-url")
async def upload_url(request: Request, payload: URLPayload):
    if not BOT_TOKEN:
        raise HTTPException(
            status_code=500, detail="TELEGRAM_BOT_TOKEN environment variable not set.")

    # Get initData from a custom header sent by the frontend
    init_data = request.headers.get("X-Telegram-Init-Data")
    if not init_data:
        raise HTTPException(
            status_code=401, detail="X-Telegram-Init-Data header is missing.")

    # Validate the request and get user info
    user_info = validate_init_data(init_data, BOT_TOKEN)
    if not user_info:
        raise HTTPException(
            status_code=403, detail="Invalid initData. Request could not be verified.")

    user_id = user_info.get('id')
    if not user_id:
        raise HTTPException(
            status_code=400, detail="Could not extract user ID from initData.")

    # Process the URL and send a confirmation message back to the user
    message_text = f"✅ I've received your URL: {payload.url}"

    async with httpx.AsyncClient() as client:
        send_message_url = f"httpss://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        try:
            res = await client.post(send_message_url, json={
                "chat_id": user_id,
                "text": message_text
            })
            res.raise_for_status()
        except httpx.HTTPStatusError as e:
            print(f"Error sending message to Telegram: {e.response.text}")
            raise HTTPException(
                status_code=500, detail="Failed to send confirmation message.")

    return {"status": "success", "message": "URL received and confirmation sent."}


@app.get("/")
def read_root():
    return {"status": "Backend is running!"}

# Handle CORS preflight requests


@app.options("/upload-url")
async def options_upload_url():
    return Response(status_code=200)
