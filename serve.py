#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import jwt
import json
import time
import logging
import tornado.auth
import tornado.ioloop
from tornado.options import define, options, parse_command_line, parse_config_file
import tornado.web

logger = logging.getLogger()
formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
file_handler = logging.FileHandler('requests.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

define("debug", default=True, type=bool)
define("port", default=3001, type=int)
token_secret = "jAXJgvBHuSKgOWdSRGYmF1Ah32fIuHrkgXCMeEX59d4G7G"
cookie_secret = "DfzSYeRsoqj8aVoMUpN8zOUHFMZcyhgixHuaCoL87GoQn"

status_info = [
  {
    "cpu": [{"num": 2, "idle": 140, "sys": 2}],
    "ram": {"free": 2, "total": 8},
    "storage": [
      {"name": "dev1", "free": 120, "total": 520},
      {"name": "dev2", "free": 50, "total": 120},
      {"name": "dev3", "free": 240, "total": 320}
    ]
  },
  {
    "cpu": [{"num": 4, "idle": 160, "sys": 2}],
    "ram": {"free": 4, "total": 16},
    "storage": [
      {"name": "dev1", "free": 220, "total": 520},
      {"name": "dev2", "free": 150, "total": 420},
      {"name": "dev3", "free": 250, "total": 320}
    ]
  }
]
users = [
  {
    "username": "qwerty_user",
    "user_id": 13,
    "full_name": "Гадя Петрович Хренова",
    "join_time": 1666038496,
    "password": "qVass"
  },
  {
    "username": "operator",
    "user_id": 4,
    "full_name": "Иванов Иван Евгениевич",
    "join_time": 1665033496,
    "password": "Oper21vbn"
  }
]
devices = [
  {
    "device_id": 22,
    "serial_number": "RDDC1000149",
    "model_name": "R40-L2.WG",
    "last_seen": 1666033496,
    "tag_list": ["spb", "выборгское"],
    "blocked": False
  },
  {
    "device_id": 29,
    "serial_number": "RGDC1000432",
    "model_name": "R50-L4.WA",
    "last_seen": 1666023496,
    "tag_list": ["мурнаск", "холодно"],
    "blocked": True
  },
  {
    "device_id": 7,
    "serial_number": "RDHC1000290",
    "model_name": "RL21w",
    "last_seen": 1666021496,
    "tag_list": ["сочи"],
    "blocked": True
  }
]

def find_element(value, field, items):
    if field == "user_id" or field == "device_id":
        value = int(value)
    founded = {}
    for (index, el) in enumerate(items):
        if el[field] == value:
            founded = el
            return [index, founded]
    return founded

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/dashboard", DashboardHandler),
            (r"/users", UserHandler),
            (r"/users/(\d{1,5})", UserHandler),
            (r"/devices", DeviceHandler),
            (r"/devices/(\d{1,5})", DeviceHandler),
            (r"/login", AuthHandler),
        ]
        settings = {
            "cookie_secret": cookie_secret,
            "debug": options.debug
        }
        tornado.web.Application.__init__(self, handlers, **settings)

class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', 'POST, PATCH')
        self.set_header('Access-Control-Allow-Headers', 'Content-Type')
        self.set_header('Content-Type', 'application/json')
    def get_current_user(self):
        secured_token = self.get_secure_cookie("auth_token")
        if not secured_token:
            return False
        else:
            decoded_token = jwt.decode(secured_token, token_secret, algorithms='HS256')
            logger.info(f'User with login "{decoded_token["username"]}" requested "{self.request.uri}", method: {self.request.method}')
            return True

class DashboardHandler(BaseHandler):
    def post(self):
        self.write(json.dumps(status_info))

class UserHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self, id = None):
        if not id is None:
            founded_user = find_element(id, "user_id", users)
            if not founded_user:
                self.write({"error": True, "message": f'User with id {id} does not exist'})
            else:
                self.write(json.dumps(founded_user[1]))
                self.finish()
        else:
            self.write(json.dumps(users))

    def patch(self, id = None):
        try:
            full_name = self.get_argument('full_name')
        except tornado.web.MissingArgumentError as ex:
            self.write(json.dumps('Argument full_name missing'))
            self.finish()
        if not id is None:
            founded_user = find_element(id, "user_id", users)
            if not founded_user:
                self.write({"error": True, "message": f'User with id {id} does not exist'})
            else:
                index, obj = founded_user
                users[index]["full_name"] = full_name
                self.write(json.dumps(f'User with id {id} has been updated'))
                self.finish()

class DeviceHandler(BaseHandler):
    @tornado.web.authenticated
    def post(self, id = None):
        if not id is None:
            founded_device = find_element(id, "device_id", devices)
            if not founded_device:
                self.write({"error": True, "message": f'Device with id {id} does not exist'})
            else:
                self.write(json.dumps(founded_device[1]))
                self.finish()
        else:
            self.write(json.dumps(devices))

    def patch(self, id = None):
        if not id is None:
            founded_device = find_element(id, "device_id", devices)
            tag_list_updated = False
            blocked_updated = False
            if not founded_device:
                self.write({"error": True, "message": f'Device with id {id} does not exist'})
            else:
                index, obj = founded_device
                device_obj = {
                    "device_id": obj["device_id"],
                    "serial_number": obj["serial_number"],
                    "model_name": obj["model_name"],
                    "last_seen": int(time.time()),
                    "tag_list": list(json.loads(self.get_argument('tag_list'))) if self.get_argument('tag_list') else obj["tag_list"],
                    "blocked": bool(self.get_argument('blocked')) if self.get_argument('blocked') else bool(obj["blocked"])
                }
                devices[index] = device_obj
                if self.get_argument('tag_list'):
                    tag_list_updated = True
                if self.get_argument('blocked'):
                    blocked_updated = True
                self.write(json.dumps({
                    "last_seen_updated": device_obj["last_seen"],
                    "tag_list_updated": tag_list_updated,
                    "blocked_updated": blocked_updated,
                }))
                self.finish()
        else:
            self.write(json.dumps("You must patch device with id parameter"))
            self.finish()
class AuthHandler(BaseHandler):
    def post(self):
        try:
            username = self.get_argument('username')
            password = self.get_argument('password')
        except:
            self.set_status(403)
            self.write(json.dumps("Missing arguments: Login or Password"))
            self.finish()

        if username and password:
            founded_user = find_element(username, "username")
            if not founded_user:
                self.write(json.dumps('Invalid credentials'))
            else:
                index, obj = founded_user
                if users[index]["password"] != password:
                    self.write(json.dumps('Invalid password'))
                else:
                    token = jwt.encode(obj, token_secret, algorithm='HS256')
                    self.set_secure_cookie("auth_token", token)
                    self.write({"username": obj["username"], "token": token})
                    self.finish()

def main():
    tornado.options.parse_command_line()
    application = Application()
    logging.info('Server listening port: '+ str(options.port))
    application.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()