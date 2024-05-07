#!/usr/bin/python3
# Copyright 2024 Chasing1020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""A tool for automatically booking badminton courts of Yanqi Lake Campus of the UCAS"""

import logging
import asyncio
import io
from logging import Formatter
import sys
import datetime
import re
import time
import aiohttp
from PIL import Image
import ddddocr
from rich.logging import RichHandler
from rich.console import Console
import base64
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA

# TODO(you): Replace the following username and password with your own.
USERNAME = "yourname23@mails.ucas.ac.cn"
PASSWORD = "yourpassword"
# TODO(you): Modify the following targets according to your needs.
TARGETS = [
    # for west campus
    {"location": "west", "abscissa": "3号场地", "yaxis": ["19:30-20:30", "20:30-21:30"]},
    {"location": "west", "abscissa": "3号场地", "yaxis": ["19:00-20:00", "20:00-21:00"]},
    {"location": "west", "abscissa": "2号场地", "yaxis": ["19:30-20:30", "20:30-21:30"]},
    {"location": "west", "abscissa": "2号场地", "yaxis": ["19:00-20:00", "20:00-21:00"]},
    {"location": "west", "abscissa": "1号场地", "yaxis": ["19:30-20:30", "20:30-21:30"]},
    {"location": "west", "abscissa": "1号场地", "yaxis": ["19:00-20:00", "20:00-21:00"]},
    # for east campus
    {"location": "east", "abscissa": "1号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "2号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "3号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "4号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "5号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "6号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "7号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
    {"location": "east", "abscissa": "8号场地", "yaxis": ["18:00-19:00", "19:00-20:00"]},
]  # fmt: skip

# The date of booking, which is the day after tomorrow by default.
date = (datetime.datetime.today() + datetime.timedelta(days=2)).strftime("%Y-%m-%d")


def encrpt_password(password) -> str:
    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxG1zt7VW/VNk1KJC7Au
oInrMZKTf0h6S6xBaROgCz8F3xdEIwdTBGrjUKIhIFCeDr6esfiVxUpdCdiRtqa
CS9IdXO+9Fs2l6fx6oGkAA9pnxIWL7bw5vAxyK+liu7BToMFhUdiyRdB6erC1g/
fwDVBywCWhY4wCU2/TSsTBDQhuGZzy+hmZGEB0sqgZbbJpeosW87dNZFomn/uGh
fCDJzswjS/x0OXD9yyk5TEq3QEvx5pWCcBJqAoBfDDQy5eT3RR5YBGDJODHqW1c
2OwwdrybEEXKI9RCZmsNyIs2eZn1z1Cw1AdR+owdXqbJf9AnM3e1CN8GcpWLDyO
naRymLgQIDAQAB
-----END PUBLIC KEY-----"""
    rsakey = RSA.importKey(public_key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(password.encode()))
    return cipher_text.decode()


async def login(session):
    await session.post(
        "https://sep.ucas.ac.cn/slogin",
        data={
            "userName": USERNAME,
            "pwd": encrpt_password(PASSWORD),
            "loginFrom": "",
            "sb": "sb",
        },
    )
    async with session.get("https://sep.ucas.ac.cn/portal/site/416/2095") as resp:
        pattern = r'<h4>2秒钟没有响应请点击<a href="(.*?)"><strong>这里</strong></a>直接跳转</h4>'
        match = re.search(pattern, await resp.text())
        if match:
            await session.get(match.group(1))
        else:
            logging.error("Login failed, please check your username and password.")


async def get_resource_info_margin(session, resource_id) -> dict:
    """
    Retrieves resource information margin for east and west campus. (6 for west and 14 for east)
    """
    url = f"https://ehall.ucas.ac.cn/site/reservation/resource-info-margin?resource_id={resource_id}&start_time={date}&end_time={date}"
    async with session.get(url) as resp:
        json = await resp.json()
        if json["d"] == []:
            logging.error(
                "Your cookie is invalid, please check it: \n%s",
                session.cookie_jar.filter_cookies("https://ehall.ucas.ac.cn"),
            )
            sys.exit(1)
        return json


async def process_captcha(session, ocr) -> str:
    """
    Process the captcha image and return the result as a string.
    """
    async with session.get("https://ehall.ucas.ac.cn/site/login/code") as resp:
        captcha_result = ocr.classification(Image.open(io.BytesIO(await resp.read())))
        return "".join(captcha_result.split())


def init_logger(console, filename="result.log"):
    """
    Configures the logger with a rich handler for console output and a file handler for logging to a file.
    """
    rich_handler = RichHandler(console=console)
    rich_handler.setFormatter(Formatter("%(message)s"))
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s %(levelname)s] %(message)s",
        datefmt="%b-%d %H:%M:%S",
        handlers=[
            rich_handler,
            logging.FileHandler(filename=filename, mode="a"),
        ],
    )


async def generate_data_list(session):
    """
    Generate a list of data based on the given session.
    """
    east = (await get_resource_info_margin(session, 14))["d"]["46"]
    west = (await get_resource_info_margin(session, 6))["d"]["55"]
    data_list = []
    for target in TARGETS:
        data = []
        for i in range(len(target["yaxis"])):
            for item in east if target["location"] == "east" else west:
                if (
                    item["abscissa"] == target["abscissa"]
                    and item["yaxis"] == target["yaxis"][i]
                ):
                    data.append(
                        {
                            "date": date,
                            "period": item["time_id"],
                            "sub_resource_id": item["sub_id"],
                        }
                    )
        data_list.append(str(data).strip().replace("'", '"'))
    return data_list


async def main():
    console = Console()
    init_logger(console)

    async with aiohttp.ClientSession() as session:
        await login(session)

        data_list = await generate_data_list(session)
        logging.info(
            "Start booking, your account is: %s\n%s",
            USERNAME,
            session.cookie_jar.filter_cookies("https://ehall.ucas.ac.cn"),
        )

        ocr = ddddocr.DdddOcr()
        with console.status("[bold green]Still booking, please wait..."):
            while True:
                for i, data in enumerate(data_list):
                    payload = {
                        "resource_id": "6"
                        if TARGETS[i]["location"] == "west"
                        else "14",
                        "code": await process_captcha(session, ocr),
                        "remarks": "",
                        "deduct_num": "",
                        "data": data,
                    }
                    async with session.post(
                        "https://ehall.ucas.ac.cn/site/reservation/launch",
                        data=payload,
                    ) as resp:
                        message = (await resp.json())["m"]
                        logging.info({"target": TARGETS[i], "message": message})

                        if message == "预约成功" or message == "未结束的预约":
                            logging.warning(
                                {"target": TARGETS[i], "message": "预约成功"}
                            )
                            return
                        elif (
                            message == "不在服务时间"
                            or message == "预约日期已被禁用"
                            or message == "预约次数限制达到上限"
                        ):
                            current_time = time.strftime("%H:%M", time.localtime())
                            if current_time >= "12:40" or current_time <= "12:20":
                                return


if __name__ == "__main__":
    asyncio.run(main())
