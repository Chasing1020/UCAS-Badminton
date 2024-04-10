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

import aiohttp
from PIL import Image
import ddddocr
from fake_useragent import UserAgent
from rich.logging import RichHandler
from rich.console import Console


# TODO(you): Replace the following cookie with your own cookie.
COOKIE = "PHPSESSID=abcdefghijklmnopqrstuvwxyz; vjuid=123456; vjvd=abcdefghijklmnopqrstuvwxyz123456; vt=123456789"
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
]


date = (datetime.datetime.today() + datetime.timedelta(days=2)).strftime("%Y-%m-%d")
ua = UserAgent().chrome
headers = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "zh-CN,zh;q=0.9,zh-TW;q=0.8,en-US;q=0.7,en;q=0.6",
    "Connection": "keep-alive",
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": COOKIE,
    "Host": "ehall.ucas.ac.cn",
    "Origin": "https://ehall.ucas.ac.cn",
    "Referer": "https://ehall.ucas.ac.cn/v2/reserve/reserveDetail?id=6",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": ua,
    "X-Requested-With": "XMLHttpRequest",
}


async def get_resource_info_margin(session, resource_id) -> dict:
    """
    Retrieves resource information margin for east and west campus. (6 for west and 14 for east)
    """
    url = f"https://ehall.ucas.ac.cn/site/reservation/resource-info-margin?resource_id={resource_id}&start_time={date}&end_time={date}"
    async with session.get(url) as resp:
        json = await resp.json()
        if json["d"] == []:
            logging.error("Your cookie is invalid, please check it: \n%s", COOKIE)
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

    async with aiohttp.ClientSession(headers=headers) as session:
        data_list = await generate_data_list(session)

        logging.info("Start booking, your current cookie is: \n%s", COOKIE)

        ocr = ddddocr.DdddOcr(show_ad=False)
        with console.status("[bold green]Still booking, please wait..."):
            while True:
                for i, data in enumerate(data_list):
                    payload = {
                        "resource_id": "6" if TARGETS[i]["location"] == "west" else "14",
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
                            # current_time = time.strftime("%H:%M", time.localtime())
                            # if current_time >= "12:40" or current_time <= "12:20":
                            #     return
                            pass


if __name__ == "__main__":
    asyncio.run(main())
