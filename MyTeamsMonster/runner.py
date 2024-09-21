import google.generativeai as genai
import asyncio
import aiohttp

genai.configure(api_key="")
model = genai.GenerativeModel("gemini-1.5-flash")

my_message = ("")

async def get_ai_response():
    AI_response = await asyncio.to_thread(model.generate_content, my_message)

    # Check if AI_response has a .text attribute; if so, get the text content
    if hasattr(AI_response, 'text'):
        AI_response_text = AI_response.text  # Extract the text
    else:
        AI_response_text = AI_response  # Assume it's already a string

    message_to_send = f"{my_message}\n\n{AI_response_text}"
    return message_to_send

async def send_message(access_token, chat_id, message):
  url = f"https://graph.microsoft.com/v1.0/chats/{chat_id}/messages"

  headers = {
      "Authorization": f"Bearer {access_token}",
      "Content-Type": "application/json"
  }
  payload = {
      "body": {
          "content": message
      }
  }

  # Use aiohttp to send the request asynchronously
  async with aiohttp.ClientSession() as session:
      async with session.post(url, json=payload, headers=headers) as response:
          if response.status == 201:
              print("Message sent successfully!")
          else:
              error_text = await response.text()  # Get the response text for debugging
              print(f"Failed to send message: {response.status}")
              print(error_text)


async def main():
    access_token_send_message = ""
    chat_id_k = ""

    send_payload = await get_ai_response()

    # Send message with the combined content
    await send_message(access_token_send_message, chat_id_k, send_payload)


# Run the asyncio event loop
if __name__ == '__main__':
    asyncio.run(main())






