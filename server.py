from aiohttp import web
import json
from typing import Any
from models import Base, engine, Session, User, Advertisement
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select, Select
from schema import (CreateUser, UpdateUser, DeleteUser, Schema,
                    CreateAdvertisement, UpdateAdvertisement, DeleteAdvertisement)
import pydantic
import bcrypt


app = web.Application()


def hash_password(password: str):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


def validate(schema_cls: Schema, json_data: dict):
    try:
        return schema_cls(**json_data).dict(exclude_unset=True)
    except pydantic.ValidationError as err:
        error = err.errors()[0]
        error.pop('ctx', None)
        raise get_http_error(web.HTTPConflict, error)


async def select_one(query: Select[Any], session: Session):
    item = (await session.execute(query)).first()
    if not item:
        return None
    return item[0]


async def orm_context(app):
    print("START")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()
    print("END")


@web.middleware
async def session_middleware(request: web.Request, handler):
    async with Session() as session:
        request.session = session
        response = await handler(request)
        return response

app.cleanup_ctx.append(orm_context)
app.middlewares.append(session_middleware)


def get_http_error(error_class, msg):
    return error_class(text=json.dumps({"error": msg}),
                       content_type='application/json'
                       )


async def add_user(session: Session, user: User):
    try:
        session.add(user)
        await session.commit()
        return user
    except IntegrityError:
        raise get_http_error(web.HTTPConflict, 'User already exists')


async def get_user(session: Session, user_id: int) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise get_http_error(web.HTTPNotFound, f'User {user_id} not found')
    return user


async def add_advertisement(session: Session, advertisement: Advertisement):
    try:
        session.add(advertisement)
        await session.commit()
        return advertisement
    except IntegrityError:
        raise get_http_error(web.HTTPBadRequest, 'The title and description fields must be filled in')


async def get_advertisement(session: Session, advertisement_id):
    advertisement = await session.get(Advertisement, advertisement_id)
    if advertisement is None:
        raise get_http_error(web.HTTPNotFound,'Advertisement not found')
    return advertisement


class UserView(web.View):

    @property
    def session(self) -> Session:
        return self.request.session

    @property
    def user_id(self) -> int:
        return int(self.request.match_info['user_id'])

    async def get(self):
        user = await get_user(self.session, self.user_id)
        return web.json_response(user.json)

    async def post(self):
        json_data = await self.request.json()
        json_data = validate(CreateUser, json_data)
        json_data["password"] = hash_password(json_data["password"])
        user = User(**json_data)
        user = await add_user(self.session, user)
        return web.json_response(user.json)

    async def patch(self):
        json_data = await self.request.json()
        json_data = validate(UpdateUser, json_data)
        user = await get_user(self.session, self.user_id)
        if user.username == json_data["username"] and check_password(json_data["password"], user.password):
            if "new_username" in json_data:
                user.username = json_data["new_username"]
            if "new_password" in json_data:
                user.password = hash_password(json_data["new_password"])
            if "new_email" in json_data:
                user.email = json_data["new_email"]
            await add_user(self.session, user)
        else:
            raise get_http_error(web.HTTPUnauthorized, 'Incorrect username or password')
        return web.json_response(user.json)

    async def delete(self):
        json_data = await self.request.json()
        json_data = validate(DeleteUser, json_data)
        user = await get_user(self.session, self.user_id)
        if user.username == json_data["username"] and check_password(json_data["password"], user.password):
            await self.session.delete(user)
            await self.session.commit()
            return web.json_response({"status": "User deleted"})
        else:
            raise get_http_error(web.HTTPUnauthorized, 'Incorrect username or password')


class AdvertisementView(web.View):

    @property
    def session(self) -> Session:
        return self.request.session

    @property
    def advertisement_id(self) -> int:
        return int(self.request.match_info['advertisement_id'])

    async def get(self):
        advertisement = await get_advertisement(self.session, self.advertisement_id)
        return web.json_response(advertisement.json)

    async def post(self):
        json_data = await self.request.json()
        json_data = validate(CreateAdvertisement, json_data)
        query = select(User).where(User.username == json_data["username"]).limit(1)
        user = await select_one(query, self.session)
        if user is None:
            raise get_http_error(web.HTTPNotFound, 'User not found')
        if check_password(json_data["password"], user.password):
            json_data["owner"] = user.id
            json_data.pop("username", None)
            json_data.pop("password", None)
            advertisement = await add_advertisement(self.session, Advertisement(**json_data))
            return web.json_response(advertisement.json)
        raise get_http_error(web.HTTPUnauthorized, 'Invalid password')

    async def patch(self):
        json_data = await self.request.json()
        json_data = validate(UpdateAdvertisement, json_data)
        advertisement = await get_advertisement(self.session, self.advertisement_id)
        query = select(User).where(User.username == json_data["username"]).limit(1)
        user = await select_one(query, self.session)
        if user is None:
            raise get_http_error(web.HTTPNotFound, 'User not found')
        if user.id == advertisement.owner:
            if check_password(json_data["password"], user.password):
                json_data.pop("username", None)
                json_data.pop("password", None)
                for field, value in json_data.items():
                    setattr(advertisement, field, value)
                await add_advertisement(self.session, advertisement)
                return web.json_response(advertisement.json)
            else:
                raise get_http_error(web.HTTPUnauthorized, 'Invalid password')
        raise get_http_error(web.HTTPForbidden,'Access denied')

    async def delete(self):
        json_data = await self.request.json()
        json_data = validate(DeleteAdvertisement, json_data)
        advertisement = await get_advertisement(self.session, self.advertisement_id)
        query = select(User).where(User.username == json_data["username"]).limit(1)
        user = await select_one(query, self.session)
        if user is None:
            raise get_http_error(web.HTTPNotFound, 'User not found')
        if user.id == advertisement.owner:
            if check_password(json_data["password"], user.password):
                await self.session.delete(advertisement)
                await self.session.commit()
                return web.json_response({"status": "Advertisement deleted"})
            else:
                raise get_http_error(web.HTTPUnauthorized, 'Invalid password')
        raise get_http_error(web.HTTPForbidden,'Access denied')


app.add_routes(
    [
        web.post('/user', UserView),
        web.get(r'/user/{user_id:\d+}', UserView),
        web.patch(r'/user/{user_id:\d+}', UserView),
        web.delete(r'/user/{user_id:\d+}', UserView),
        web.post('/advertisement', AdvertisementView),
        web.get(r'/advertisement/{advertisement_id:\d+}', AdvertisementView),
        web.patch(r'/advertisement/{advertisement_id:\d+}', AdvertisementView),
        web.delete(r'/advertisement/{advertisement_id:\d+}', AdvertisementView),
    ]
)

web.run_app(app)
