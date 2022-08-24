import sys
import json
from SpeedJAV import SpeedJav

with open("config.json", "r", encoding='utf8') as f:
    config = json.load(f)

start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
base_path = f"{config['download']}/"

for aid in range(start, end):
    codaid = aid ^ 66778899
    cid = codaid.to_bytes(4, "big").hex().lstrip('0')
    jav = SpeedJav(config, cid, base_path)
    jav.get_video_detail()
    jav.get_video_subtitle()
    jav.stream_dl()
    jav.video_convert()
