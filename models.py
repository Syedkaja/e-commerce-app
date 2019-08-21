import base64
from datetime import datetime
from os import environ

import pytz
from pony.orm import Database, Json, Optional, PrimaryKey, Required, Set

db = Database()


class UserMixin:
    def dictionary(self):
        user_dict = self.to_dict(
            exclude=["password", "pwd_rst_code", "auth_token", "events"]
        ).copy()
        user_dict["created_at"] = user_dict["created_at"].isoformat()
        user_dict["updated_at"] = user_dict["updated_at"].isoformat()
        return user_dict


class User(db.Entity, UserMixin):
    id = PrimaryKey(int, auto=True)
    firstname = Optional(str)
    lastname = Optional(str)
    username = Required(str, unique=True)
    email = Required(str, unique=True)
    password = Required(str)
    pwd_rst_code = Optional(str, nullable=True, default=None)
    auth_token = Optional(str, nullable=True, default=None)
    role = Required("Role")
    created_at = Required(datetime, default=lambda: datetime.now(pytz.UTC))
    updated_at = Required(datetime, default=lambda: datetime.now(pytz.UTC))
    events = Set("Event")


db.bind(
    provider="mysql",
    host=environ["DOCKER_HOST_IP"],
    user="zasti",
    password="Zastipass1@",
    db="tms",
)
db.generate_mapping(create_tables=True)
