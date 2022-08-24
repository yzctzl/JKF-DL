import os
import time
import asyncio
import logging
import platform
import subprocess

import jwt
import m3u8
import httpx
import opencc
import webvtt
import aiohttp

from tqdm import tqdm
from copy import copy
from urllib.parse import urlparse
from base64 import b64decode, b64encode
from tenacity import retry, stop_after_attempt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Res import *
from Req import *


class SpeedJav:
    def __init__(self, config: dict, videoid: str, dest_path: str = "."):
        logging.basicConfig(format="'%(asctime)s %(levelname)s %(message)s'", level=config['level'])

        self.codaid = int(videoid, 16) ^ 66778899
        self.api_url = config["server"]["SPEEDJAV_API_GRPC_URL"]
        self.obj_url = config["server"]["OBJECT_URL"]
        self.usr_url = config["server"]["MEMBER_API_URL"]
        self.pub_url = config["server"]["PUBLIC_URL"]

        self.ap_pot = config["header"]["ap-pot"]
        self.comman_header = {
            'accept': '*/*',
            'origin': config['header']['referer'],
            'referer': config['header']['referer'],
            'user-agent': config['header']['user-agent']
        }
        self.proxy = config["proxy"]
        self.proxies = {
            "http://": config["proxy"],
            "https://": config["proxy"]
        }
        self.ffmpeg = config["ffmpeg"]

        self.uid = self.get_uid_from_ap_pot()
        self.sub_key = config["sub_key"].encode("utf8")
        self.sub_iv = bytes([ord(char) for char in str(self.uid)]).zfill(16)

        self.access_token = ""
        self.ticket_token = ""
        self.video_detail = {}
        self.stream = None

        self.dest_path = dest_path
        if not os.path.exists(self.dest_path):
            os.mkdir(self.dest_path)
        self.temp_path = os.path.join(dest_path, "temp/")
        if not os.path.exists(self.temp_path):
            os.mkdir(self.temp_path)
        self.subtitle_path = {"tw": "", "cn": ""}
        self.still_names = []

        if platform.system() == 'Windows':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        self.semaphore = asyncio.Semaphore(config["semaphore"])
        self.session = None

        self.tw2s = opencc.OpenCC("tw2s.json")

    def get_uid_from_ap_pot(self):
        jwtoken_proto = self.get_proto_from_text(self.ap_pot)
        jwtoken = AtokenRes().parse(jwtoken_proto).token1
        if not self.verify_jwt_exp(jwtoken):
            logging.critical("INVALID COOKIE")
            exit(1)
        else:
            payload = jwt.decode(jwtoken, "", algorithms=["HS512", "HS256"], options={'verify_signature': False})
            return payload['uid']

    @staticmethod
    def verify_jwt_exp(jwtoken: str) -> bool:
        if jwtoken == "":
            return False
        payload = jwt.decode(jwtoken, "", algorithms=["HS512", "HS256"], options={'verify_signature': False})
        exp = "expire" if "expire" in payload else "Expire"
        return True if payload[exp] - time.time() > 3 else False

    @staticmethod
    def get_proto_from_text(response: str) -> bytes:
        response_bytes = b64decode(response.encode("utf8"))
        proto_length = int.from_bytes(response_bytes[:5], 'big')
        return response_bytes[5:5 + proto_length]

    @staticmethod
    def get_proto_from_response(response: httpx.Response) -> bytes:
        response_bytes = b64decode(response.content)
        proto_length = int.from_bytes(response_bytes[:5], 'big')
        return response_bytes[5:5 + proto_length]

    def get_new_header(self, url: str = None, authorization: str = None, cookie: str = None, accept: str = None):
        header = copy(self.comman_header)
        if url:
            header["authority"] = urlparse(url).netloc
        if authorization:
            header["authorization"] = authorization
        if cookie:
            header["cookie"] = f"authorization={cookie}"
        if accept:
            header["accept"] = accept
            header["content-type"] = accept
        return header

    @retry(stop=stop_after_attempt(3))
    def get_access_token(self) -> str:
        if not self.verify_jwt_exp(self.access_token):
            url = self.usr_url + "/pan.general.member.MemberServiceV2/AccessToken"
            header = self.get_new_header(url, accept="application/grpc-web-text")
            response = httpx.post(url, headers=header, proxies=self.proxies, data=self.ap_pot)
            self.access_token = AtokenRes().parse(self.get_proto_from_response(response)).token2
        logging.debug("ACCESS TOKEN: " + self.access_token)
        return self.access_token

    @staticmethod
    def get_grpc_payload(proto: betterproto.Message, payload: dict):
        payload_body = proto.from_dict(payload).SerializeToString()
        payload_header = len(payload_body).to_bytes(5, "big")
        return b64encode(bytearray(payload_header) + bytearray(payload_body)).decode('utf8')

    @retry(stop=stop_after_attempt(3))
    def get_ticket_token(self) -> str:
        if not self.verify_jwt_exp(self.ticket_token):
            url = self.api_url + "/speedjav.client.ClientService/UseTicket"
            header = self.get_new_header(url,
                                         authorization=self.get_access_token(),
                                         accept="application/grpc-web-text")
            response = httpx.post(url, headers=header, proxies=self.proxies,
                                  content=self.get_grpc_payload(UseTicketReq(), {
                                      "codaid": self.codaid,
                                      "is_new": True,
                                      "auto_use_ticket": True
                                  }))
            self.ticket_token = AtokenRes().parse(self.get_proto_from_response(response)).token2
            logging.warning(f"Got New ticket_token: {self.ticket_token}")
        return self.ticket_token

    @retry(stop=stop_after_attempt(3))
    def get_video_detail(self):
        url = self.api_url + "/speedjav.client.ClientService/AvideoDetail"
        header = self.get_new_header(url, authorization=self.get_access_token(), accept="application/grpc-web-text")
        response = httpx.post(url, headers=header, proxies=self.proxies, verify=False,
                              content=self.get_grpc_payload(AvideoReq(), {"codaid": self.codaid}))
        video_detail = AvideoDetailRes().parse(self.get_proto_from_response(response)).to_dict()
        logging.debug(video_detail)
        self.video_detail = video_detail

    @retry(stop=stop_after_attempt(7))
    def get_video_subtitle(self):
        if "hasSubtitle" not in self.video_detail:
            logging.warning(f"SUBTITLE DOES NOT EXIST: {self.codaid}")
            return
        self.subtitle_path["tw"] = os.path.join(self.temp_path, f"{self.video_detail['productId']}_tw.vtt")
        self.subtitle_path["cn"] = os.path.join(self.temp_path, f"{self.video_detail['productId']}_cn.vtt")
        try:
            url = self.api_url + "/speedjav.client.ClientService/AvideoSubtitle"
            header = self.get_new_header(url, authorization=self.get_access_token(), accept="application/grpc-web-text")
            response = httpx.post(url, headers=header, proxies=self.proxies, verify=False,
                                  content=self.get_grpc_payload(AvideoReq(), {"codaid": self.codaid}))
            subtitle_enc = AvideoSubtitleRes().parse(self.get_proto_from_response(response)).subtitle
            decryptor = Cipher(algorithms.AES(self.sub_key), modes.CBC(self.sub_iv)).decryptor()
            subtitle_pad = decryptor.update(b64decode(subtitle_enc)) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            subtitle = unpadder.update(subtitle_pad) + unpadder.finalize()
            with open(self.subtitle_path["tw"], "wb") as s:
                s.write(subtitle)
            vtt = webvtt.read(self.subtitle_path["tw"])
            for caption in vtt:
                caption.text = self.tw2s.convert(caption.text)
            vtt.save(self.subtitle_path["cn"])
        except httpx.HTTPError:
            logging.critical(f"VIDEO SUBTITLE GET ERROR: {self.video_detail['productId']}")

    def stills_dl(self):
        base_url = f"{self.pub_url}/v/{self.video_detail['productId']}/data/{self.video_detail['productId']}"
        self.still_names = ["cover.jpg", *[f"jp-{i}.jpg" for i in range(1, self.video_detail["stillsNum"] + 1)]]
        pbar = tqdm(total=len(self.still_names), desc='Still Downloading: ', unit="pic")
        loop = asyncio.get_event_loop()
        tasks = [self.dl_with_semaphore(base_url, name, self.temp_path, pbar) for name in self.still_names]
        loop.run_until_complete(asyncio.gather(*tasks))

    @retry(stop=stop_after_attempt(3))
    def load_m3u8(self):
        m3u8_path = os.path.join(self.temp_path, "first.m3u8")
        try:
            main_url = f"{self.obj_url}/v/{self.video_detail['productId']}/main.m3u8"
            header = self.get_new_header(main_url, cookie=self.get_ticket_token())
            with httpx.Client(headers=header, proxies=self.proxies) as client:
                main_m3u8 = m3u8.loads(client.get(main_url).text, main_url)
                bandwidths = [main_m3u8.playlists[i].stream_info.bandwidth for i in range(0, len(main_m3u8.playlists))]
                best_quality_url = main_m3u8.playlists[bandwidths.index(max(bandwidths))].absolute_uri
                if os.path.exists(m3u8_path):
                    self.stream = m3u8.loads(open(m3u8_path, 'r', encoding='utf8').read(), best_quality_url)
                else:
                    self.stream = m3u8.loads(client.get(best_quality_url).text, best_quality_url)
                    self.stream.version = 4
                    for key in self.stream.keys:
                        with open(os.path.join(self.temp_path, key.uri), 'wb') as k:
                            k.write(client.get(key.absolute_uri).content)
        except httpx.HTTPError:
            logging.critical("M3U8 LOAD ERROR!")

    def stream_dl(self):
        self.load_m3u8()
        pbar = tqdm(total=len(self.stream.files), desc='Video Downloading: ', unit="ts")
        try:
            loop = asyncio.get_event_loop()
            tasks = [self.dl_with_semaphore(segment, self.temp_path, pbar) for segment in self.stream.segments]
            loop.run_until_complete(asyncio.gather(*tasks))
            loop.close()
        finally:
            self.stream.dump(os.path.join(self.temp_path, "first.m3u8"))

    @staticmethod
    def ts_exist_by_segment(segment: m3u8.Segment, ts_path: str):
        try:
            if os.path.getsize(ts_path) == int(segment.title.lstrip('bytes=')):
                ''.lstrip()
                return True
            else:
                return False
        except OSError:
            return False

    @retry(stop=stop_after_attempt(7))
    async def dl_with_semaphore(self, segment: m3u8.Segment, dest_path: str, pbar: tqdm = None):
        url = segment.absolute_uri
        file = segment.uri
        ts_path = os.path.join(dest_path, file)
        if os.path.exists(ts_path) and segment.title:
            if self.ts_exist_by_segment(segment, ts_path):
                logging.debug(f"{file} already downloaded")
                if pbar:
                    pbar.update(1)
                return
        async with self.semaphore:
            lock = asyncio.Lock()
            async with lock:
                header = self.get_new_header(url, cookie=self.get_ticket_token())
            async with aiohttp.ClientSession(headers=header) as session:
                async with session.get(url, proxy=self.proxy) as resp:
                    resp.raise_for_status()
                    logging.debug(f"{file}: {resp.status}: {self.verify_jwt_exp(self.ticket_token)}:"
                                  f" {resp.headers['content-length']}")
                    segment.title = f'bytes={resp.headers["content-length"]}'
                    with open(ts_path, "wb") as fd:
                        async for chunk in resp.content.iter_chunked(2 ** 18):
                            fd.write(chunk)
                    if pbar:
                        pbar.update(1)

    def video_convert(self):
        actress = [actress["name"]["jp"] for actress in self.video_detail["actressList"]]
        keyword = [self.tw2s.convert(keyword["name"]["tw"]) for keyword in self.video_detail["keywordList"]]
        title = self.tw2s.convert(self.video_detail["title"]["tw"])

        command_protocol = [self.ffmpeg,
                            "-allowed_extensions", "ALL",
                            "-protocol_whitelist", "file,http,https,tcp,tls,crypto"]
        command_import = ["-i", os.path.join(self.temp_path, "first.m3u8")]
        command_map = ["-map", "0:v", "-map", "0:a"]
        command_codec = ["-c:v", "copy", "-c:a", "copy"]
        command_metadata = ["-f", "mp4", "-movflags", "+use_metadata_tags+faststart",
                            "-metadata", f"title={title}",
                            "-metadata", f"artist={', '.join(actress)}",
                            "-metadata", f"keyword={'#' + ' #'.join(keyword)}",
                            "-metadata", f"copyright={self.video_detail['publisher']['displayName']}",
                            "-metadata", f"episode_id={self.video_detail['no']}"]
        if "hasSubtitle" in self.video_detail:
            command_import.extend(["-i", self.subtitle_path["cn"], "-i", self.subtitle_path["tw"]])
            command_map.extend(["-map", f"1:s", "-map", f"2:s"])
            command_codec.extend(["-c:s", "mov_text"])
            command_metadata.extend(["-metadata:s:s:0", "language=zhs", "-metadata:s:s:1", "language=zht"])

        command = [*command_protocol, *command_import, *command_map, *command_codec, *command_metadata,
                   os.path.join(self.dest_path, f"{self.video_detail['no']}.mp4")]
        subprocess.run(command)

    @retry(stop=stop_after_attempt(3))
    def search_by_param(self, gapi: str, Req: betterproto.Message, Res: betterproto.Message, param: dict):
        url = self.api_url + "/speedjav.client.ClientService/" + gapi
        payload = self.get_grpc_payload(Req, param)
        header = self.get_new_header(url, authorization=self.get_access_token(), accept="application/grpc-web-text")
        response = httpx.post(url, headers=header, proxies=self.proxies, content=payload)
        result = Res.parse(self.get_proto_from_response(response)).to_dict()
        return result

    def search(self, gapi: str, param: dict):
        if gapi == "SearchPlaylist":
            self.search_by_param(gapi, SearchPlaylistReq(), SearchPlaylistRes(), param)
        elif gapi == "ActressListByIds":
            self.search_by_param(gapi, IdsReq(), ActressListRes(), param)
        elif gapi == "PublisherListByIds":
            self.search_by_param(gapi, IdsReq(), Publishers(), param)
        elif gapi == "AvideoList":
            self.search_by_param(gapi, AvideoListReq(), AvideoListRes(), param)
        elif gapi == "AvideoSchedule":
            self.search_by_param(gapi, AvideoScheduleReq(), AvideoScheduleRes(), param)
        elif gapi == "AvideoListByCodaids":
            self.search_by_param(gapi, IdsReq(), AvideoListRes(), param)
        elif gapi == "ActressList":
            self.search_by_param(gapi, ActressListReq(), ActressListRes(), param)
        elif gapi == "SearchAvideo":
            self.search_by_param(gapi, SearchAvideoReq(), SearchAvideoRes(), param)
