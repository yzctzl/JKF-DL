import sys
import json
from SpeedJAV import SpeedJav

with open("config.json", "r", encoding='utf8') as f:
    config = json.load(f)

aid = sys.argv[1]
base_path = f"{config['download']}/{aid}"

jav = SpeedJav(config, aid, base_path)
jav.get_video_detail()
jav.get_video_subtitle()
jav.stream_dl()
jav.video_convert()
