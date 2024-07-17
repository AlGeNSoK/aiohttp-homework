import aiohttp
import asyncio


async def main():
    client = aiohttp.ClientSession()

    # response = await client.post('http://127.0.0.1:8080/user',
    #                             json={'username': 'user1', 'password': '123456789', 'email': '11@yandex.ru'}
    #                              )
    # data = await response.text()
    # print(data)
    # await client.close()

    # response = await client.post('http://127.0.0.1:8080/user',
    #                              json={'username': 'user2', 'password': '987654321', 'email': '22@yandex.ru'}
    #                              )
    # data = await response.text()
    # print(data)
    # await client.close()

    # response = await client.post('http://127.0.0.1:8080/user',
    #                              json={'username': 'user3', 'password': '54321', 'email': '33@yandex.ru'}
    #                              )
    # data = await response.text()
    # print(data)
    # await client.close()

    # response = await client.get('http://127.0.0.1:8080/user/4',)
    # data = await response.text()
    # print(data)
    # await client.close()

    response = await client.patch('http://127.0.0.1:8080/user/4',
              json={'username': 'user2', 'password': '987654321', 'email': '22@yandex.ru', "new_email": "77@yandex.ru"}
                                  )
    data = await response.text()
    print(data)
    await client.close()

asyncio.run(main())
