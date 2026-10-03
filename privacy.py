#!/usr/bin/env python3
"""Selective LG G5 privacy installer. Self-contained; never records or uploads audio."""
import argparse
import copy
import fcntl
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import pty
import select
import shutil
import signal
import subprocess
import sys
import time
import uuid

VERSION = '0.2.0'

BASE = Path('/var/lib/webosbrew/dangbro-privacy')
HOOK = Path('/var/lib/webosbrew/init.d/05-dangbro-privacy')
PREFS = Path('/var/luna/preferences')
CHAIN = 'DANGBRO_PRIVACY'
HOST_MARKER = '# dangbro selective privacy hosts'
MIC_INFO = Path('/proc/asound/card1/pcm0c/info')
STARTUPS = [Path('/var/lib/webosbrew/startup.sh'), Path('/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service/startup.sh')]
HEALTH_NAME = 'pwn-glass-health'
UNIT_DIR = Path('/run/systemd/system')
OPTIONAL_FLAGS = {'voiceAllowed', 'voice2Allowed', 'marketingOnAllowed', 'acrAllowed',
                  'acrGdprAllowed', 'acrAdAllowed', 'acrOnAllowed', 'remoteDiagAllowed',
                  'customAdAllowed', 'customadsAllowed', 'thirdPartySharingAllowed', 'veranceOnAllowed'}
OPTIONAL_DOCS = {'S_ADG', 'S_ADC', 'S_ADD', 'S_VNG', 'S_NVC', 'S_NVD', 'S_VDC',
                 'S_VDD', 'S_TAG', 'S_TAD', 'S_MKT', 'S_DPA'}
QUEUES = ['/var/spool/rdxd', '/var/spool/uploadd/pending', '/tmp/rdxd', '/tmp/uploadd']
POLICY = json.loads(r'''{
  "activation_decisions": {
    "/usr/share/dbus-1/services/com.webos.app.voice.service": {
      "action": "block",
      "asset": "activation/d9cf5ba0495cf19e7032.service",
      "executable": "/usr/bin/com.webos.app.voice",
      "original_sha256": "fdba66c69337da2fe57e9bfb0297480b8379c8511083d7609b13c554af52eb3a",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.app.voice\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "d7af95aaa8966ba3390d3e7047abc33fb7b270e24110c53905b918a685d5bc2c"
    },
    "/usr/share/dbus-1/services/com.webos.service.acr.service": {
      "action": "block",
      "asset": "activation/99908b8aa22d2a833aee.service",
      "executable": "/usr/sbin/acr2",
      "original_sha256": "fcc5ee5b9413095b686992293958dd727e9b1d0a6526ba92abd159e5710e4e8e",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.acr;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "dfb78153a340d9518831db2c0e50025114612392636a3074edf4f5cf30fc3514"
    },
    "/usr/share/dbus-1/services/com.webos.service.admanager.service": {
      "action": "block",
      "asset": "activation/bc03c6760be86cacd8c1.service",
      "executable": "/usr/sbin/admanager",
      "original_sha256": "0c3efcf5a4f396a60cc30e818db239fb290d0ce426446333e3169781665a8410",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.admanager\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "7d9a74231b12f9d7586daa7ccb1b10eba1195f33c0189b091725f751f9f66bd6"
    },
    "/usr/share/dbus-1/services/com.webos.service.sdx.service": {
      "action": "preserve",
      "executable": "/usr/sbin/sdx",
      "original_sha256": "f0f057d6f383fbecc9adc589c4c528b1805f5059d61fa3219dfb3169dca540da",
      "reason": "Shared service deliberately retained"
    },
    "/usr/share/dbus-1/services/com.webos.service.update.service": {
      "action": "block",
      "asset": "activation/d058c2e7bfc77c145111.service",
      "executable": "/usr/sbin/update",
      "original_sha256": "ac5fcda9fda7853fae88f220d280a226aafd7a32c7ae881c65d714e542258608",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.update\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n\n\n",
      "replacement_sha256": "16c02083db82231d3ab250fb40df39ffb9e675e642ddda2dc145e34ac6525dfe"
    },
    "/usr/share/dbus-1/system-services/com.webos.app.voice.service": {
      "action": "block",
      "asset": "activation/113a1aee3718325fb3f1.service",
      "executable": "/usr/bin/com.webos.app.voice",
      "original_sha256": "fdba66c69337da2fe57e9bfb0297480b8379c8511083d7609b13c554af52eb3a",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.app.voice\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "d7af95aaa8966ba3390d3e7047abc33fb7b270e24110c53905b918a685d5bc2c"
    },
    "/usr/share/dbus-1/system-services/com.webos.service.acr.service": {
      "action": "block",
      "asset": "activation/d777f6c6156f0ceba8c1.service",
      "executable": "/usr/sbin/acr2",
      "original_sha256": "fcc5ee5b9413095b686992293958dd727e9b1d0a6526ba92abd159e5710e4e8e",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.acr;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "dfb78153a340d9518831db2c0e50025114612392636a3074edf4f5cf30fc3514"
    },
    "/usr/share/dbus-1/system-services/com.webos.service.admanager.service": {
      "action": "block",
      "asset": "activation/89608e0a48ad2a4306f9.service",
      "executable": "/usr/sbin/admanager",
      "original_sha256": "0c3efcf5a4f396a60cc30e818db239fb290d0ce426446333e3169781665a8410",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.admanager\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "7d9a74231b12f9d7586daa7ccb1b10eba1195f33c0189b091725f751f9f66bd6"
    },
    "/usr/share/dbus-1/system-services/com.webos.service.sdx.service": {
      "action": "preserve",
      "executable": "/usr/sbin/sdx",
      "original_sha256": "f0f057d6f383fbecc9adc589c4c528b1805f5059d61fa3219dfb3169dca540da",
      "reason": "Shared service deliberately retained"
    },
    "/usr/share/dbus-1/system-services/com.webos.service.update.service": {
      "action": "block",
      "asset": "activation/f1f9ea32f1f273b0a340.service",
      "executable": "/usr/sbin/update",
      "original_sha256": "ac5fcda9fda7853fae88f220d280a226aafd7a32c7ae881c65d714e542258608",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.update\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n\n\n",
      "replacement_sha256": "16c02083db82231d3ab250fb40df39ffb9e675e642ddda2dc145e34ac6525dfe"
    },
    "/usr/share/luna-service2/services.d/amazon.alexa.adapter.plugin.service": {
      "action": "block",
      "asset": "activation/6a720375bf7f66e1a372.service",
      "executable": "/usr/sbin/amazon-alexa-adapter",
      "original_sha256": "94ec8e11d17d0158b4b8e63c62fe82ef22368a13b8830261b9abf01248549e47",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=amazon.alexa.adapter.plugin\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "f6c10d4a6c9debaa00d662318750c0cbb582deba55d8a49f839fa44fad8688cf"
    },
    "/usr/share/luna-service2/services.d/com.palm.uploadd.service": {
      "action": "block",
      "asset": "activation/1d47074bea6faff34f2c.service",
      "executable": "/usr/sbin/uploadd",
      "original_sha256": "699ec5b1b0ce4616999f693c0fa214f560b456149f6fc77db1c8922330a1437a",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.palm.uploadd\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "e6b419774db51cac4ce00b7ad75a848a8764f0d89ad87d24f2f276cb5414075e"
    },
    "/usr/share/luna-service2/services.d/com.webos.rdxd.service": {
      "action": "block",
      "asset": "activation/74316c5b66ba914e1911.service",
      "executable": "/usr/sbin/rdxd",
      "original_sha256": "d7b3ef15ad64fbb668747672e9bc99cb536810eee3e87a62e9408f4fe132beaf",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.rdxd\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "2b0fb4f7e5923ba1dc4d0e0f86a03c0ea0b79ad074333b7b81a029e039f37d5d"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.contentminer.service": {
      "action": "block",
      "asset": "activation/070e20d074c63d9373c7.service",
      "executable": "/usr/sbin/contentminer",
      "original_sha256": "9c7c60a9747f374ca14111cefb97f9f42a341151e8f1ef4bb23aaa02f839d9cc",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.contentminer;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "ccddc3850766677dbc8011cf28b2ce1cddff5712fe958d04b2601873b0bfabf6"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.microphone.service": {
      "action": "block",
      "asset": "activation/1a4bdbf9e4fd186f546e.service",
      "executable": "/usr/sbin/com.webos.service.microphone",
      "original_sha256": "3eb1c2021a85f8b9bce75c3bc723269899c44acf0dfbb4b981240822381b6ba8",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.microphone\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n\n",
      "replacement_sha256": "8b7b4a083cd65df0f08eb8b00d27a1ebc1e7b9ae1cbbf416644d9f8c27afcacf"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.nlpmanager.service": {
      "action": "block",
      "asset": "activation/ead1feb6cb9e36842873.service",
      "executable": "/usr/sbin/nlpmanager",
      "original_sha256": "d58c6d0ab54d55b0e014f838a4e40edeb1dcf6f560469a6b4fc8efff323bb8fa",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.nlpmanager\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "b2c2f5af69c116c073a688a3564bc7f40101a1552bbe468d5551de4464add4ae"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.nudge.service": {
      "action": "block",
      "asset": "activation/9651b022ce3f893a4a0d.service",
      "executable": "/usr/sbin/nudge",
      "original_sha256": "e680669edb1d277b3587f5ee8afca236a455a13dd221bd49fb4bc5c2d6c28e0f",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.nudge;com.webos.service.nudgeSync\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "5d73484f8addacbf69dd33d96c48d01ce7b53815da3a61763510d5d4de2ebf5e"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.pushclient.service": {
      "action": "preserve",
      "executable": "/usr/sbin/com.webos.service.pushclient",
      "original_sha256": "2408174e560d5f4090832fdbd0afd2e9639f78582d7662ba3adf2932def21c66",
      "reason": "Shared service deliberately retained"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.trigger.alexa.service": {
      "action": "block",
      "asset": "activation/57657e1b2b9f1d6fad07.service",
      "executable": "/usr/sbin/trigger_alexa",
      "original_sha256": "596333ed490644c103301f442439a9d037e5685320dc7079afeb4f9a39b7735d",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.trigger.alexa;com.webos.service.trigger.alexa.sync;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "5560a5fd2fc427736b929bb1f0c26a21aca933aa3ef4931e637569a8cf87e85c"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.trigger.thinq.service": {
      "action": "block",
      "asset": "activation/e09872b0b3f1f6a13f87.service",
      "executable": "/usr/sbin/trigger_thinq",
      "original_sha256": "1ff960d25d7ea05029737902f82c1bf16107b043ac589503bc71491afff45366",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.trigger.thinq;com.webos.service.trigger.thinq.sync;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "ef2751b10891aa53539b5cbe8e9a514e9af665d0f3355815c81a1e46b717539b"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.usercontextmanager.service": {
      "action": "block",
      "asset": "activation/927ac1bb5c6ef09ccda6.service",
      "executable": "/usr/sbin/user-context-manager",
      "original_sha256": "47856c9f1cd2e41e581998b356210a5b12fc6b411ad74e4f379996b86e260253",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.usercontextmanager\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "a6239f9c5c6d679e363fd088ecde735eab36afd73aef34fc46c3157b716563f5"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.userintentmanager.service": {
      "action": "block",
      "asset": "activation/317d2c3c9c8230fd3d0b.service",
      "executable": "/usr/sbin/user-intent-manager",
      "original_sha256": "29e6eec1e53f4616f5823099e0d5be33c83d5858e671f09ff01e59da4d446899",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.userintentmanager\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "3bf6eb85e9c15ebf46e3aba17eaf4325d564d0483c557de782622bb1ed1b3451"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voice.performer.plugin.service": {
      "action": "block",
      "asset": "activation/95d27729ff3eaa550d43.service",
      "executable": "/usr/sbin/performer",
      "original_sha256": "54bb309cf61159983a61c0f8bf3c30e3ddc172244294ab6a5e46b8a383346086",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voice.performer.plugin\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "8e474b223b79167b4969250708ec2257e3c0bfe68d8fce35f6e45e4e08559006"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceclick.service": {
      "action": "block",
      "asset": "activation/ca29bb433936856022cb.service",
      "executable": "/usr/sbin/voiceclick",
      "original_sha256": "74b217c546e07780e75993236bd32cfdeb7695ada9380d3e4ae4c48467d0a68e",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceclick\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "8132d0a4ce403f46f6ff8e0310dfda8f46344806c8cc36b13cbe058434670417"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceconductor.service": {
      "action": "block",
      "asset": "activation/ae865614f34606adb8d2.service",
      "executable": "/usr/sbin/voiceconductor",
      "original_sha256": "09efded96ed33b09e40af9e308d216be24adf3f162ba19af038db4fc06d197b5",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceconductor\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "83409ff7afebffdafe7eb7ba41c009cfbad596bc66d4b37e8d226c594cec5212"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceinput.hidraw.service": {
      "action": "block",
      "asset": "activation/787daa6004e0d8405094.service",
      "executable": "/usr/sbin/voiceinput_hidraw",
      "original_sha256": "e4eaff7d5dce1618ad34e68565284d6f5627953adb3ce601853f33aef06edc57",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceinput.hidraw\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "9d6064b6d18bb751c2b206da2e60577b04a4fc8519a0d134bd51c6e32530b094"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceinput.network.service": {
      "action": "block",
      "asset": "activation/b2ccd12502f2a8f1e0b1.service",
      "executable": "/usr/sbin/voiceinput_network",
      "original_sha256": "41739e8c99e64a21f7aff9b767b213262204bc41d2f492a475ac67625e04735e",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceinput.network\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "6996314a9c951d2d92b19284eea8728a79636d79d42bc605c30a3090a7f1dcec"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceinput.preprocessor.service": {
      "action": "block",
      "asset": "activation/7a15bc21bb7c5a3f33fe.service",
      "executable": "/usr/sbin/voiceinput_preprocessor",
      "original_sha256": "e5d2b7988b60bb0b6e331e1b316586546ad898ef83c34216b1ece65a4e4d70fd",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceinput.preprocessor;com.webos.service.voiceinput.preprocessor.sync;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "7f89fd0b2aae6628fa8e31e5ae9ae87707681343938b276d7bcdb0e4aaa9f956"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceinput.service": {
      "action": "block",
      "asset": "activation/645a5555fbb2446291c5.service",
      "executable": "/usr/sbin/voiceinput",
      "original_sha256": "737a64bec17ce8f83b2d15e4be7dde6fcfb45a846884c7b13545cfb5f6a92ebc",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceinput;com.webos.service.voiceinput.sync;\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=static\n",
      "replacement_sha256": "d92a79e33b07a3f860bb811e7cede024579dbfed67f3de59593d93e4ce7de332"
    },
    "/usr/share/luna-service2/services.d/com.webos.service.voiceinput.sound.service": {
      "action": "block",
      "asset": "activation/f7adb48a1591baf651e7.service",
      "executable": "/usr/sbin/voiceinput_sound",
      "original_sha256": "307e49a63735225bb415144074c6f1fa1322fc1656929eaa69db7cc792103c7d",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=com.webos.service.voiceinput.sound\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "86b119c1047f09a77179c3958a44ac0f64fc00ffb0752d2774d52459c0ef20fb"
    },
    "/usr/share/luna-service2/services.d/com.webos.statisticsmanager.service": {
      "action": "absent",
      "executable": "/usr/bin/webos-statistics-manager",
      "original_sha256": "7abe9427ddfbad56d94021f1c9f5ed8d47cbbdd8270c7afe31c31a9d7e9544a0",
      "reason": "Executable absent; fail verification if it appears"
    },
    "/usr/share/luna-service2/services.d/dangbei.adapter.plugin.service": {
      "action": "block",
      "asset": "activation/5f8a7d62f7698baa6b01.service",
      "executable": "/usr/sbin/dangbei-adapter",
      "original_sha256": "569c96d3a4f86c5fe8e109e102da83a0a505eede3c0badc62c766ea9e2e9bf1f",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=dangbei.adapter.plugin\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "25c93e00017b7c8f4d9cb5d0154d46b8bde974943e65496e2ec2dc99ef4bb984"
    },
    "/usr/share/luna-service2/services.d/lg.thinqai.adapter.service": {
      "action": "block",
      "asset": "activation/033bceaf0a59edb62cd1.service",
      "executable": "/usr/sbin/lg.thinqai.adapter",
      "original_sha256": "01f4405011fbae068722f485875a8c1ec3a20f3ab2440f94b952a0ee0a7a063e",
      "reason": "Matches an already blocked executable; shared services excluded",
      "replacement": "[D-BUS Service]\nName=lg.thinqai.adapter\nExec=/var/lib/webosbrew/dangbro-privacy/blocked-executable\nType=dynamic\n",
      "replacement_sha256": "0b1fe13d587e03416dc5e71994ebb2895055f4537bce405c5697a3e0b96e9f07"
    }
  },
  "blocked_hosts": [
    "ad.lgappstv.com",
    "adsdtvc.com",
    "alphonso.tv",
    "cdpbeacon.lgtvcommon.com",
    "eic.cdpbeacon.lgtvcommon.com",
    "eic.privacy-blocked.invalid",
    "eic.rdl.lgtvcommon.com",
    "es.ibsstat.nextlgsdp.com",
    "es.info.lgsmartad.com",
    "es.privacy-blocked.invalid",
    "es.rdx2.nextlgsdp.com",
    "eu.info.lgsmartad.com",
    "eu7.ibsstat.nextlgsdp.com",
    "eu7.privacy-blocked.invalid",
    "eu7.rdx2.nextlgsdp.com",
    "ibsstat.nextlgsdp.com",
    "info.lgsmartad.com",
    "privacy-blocked.invalid",
    "rdl.lgtvcommon.com",
    "rdx2.nextlgsdp.com",
    "smart.adtvc.app"
  ],
  "blocked_sdx_services": [
    "sdp_logging",
    "ibis_stat_secure",
    "rdx_secure",
    "nudge_log_secure",
    "cdpbeacon_secure",
    "rdxdev_secure"
  ],
  "executables": [
    "/usr/bin/com.webos.app.voice",
    "/usr/sbin/acr2",
    "/usr/sbin/admanager",
    "/usr/sbin/adoverlay-service",
    "/usr/sbin/amazon-alexa-adapter",
    "/usr/sbin/com.webos.service.microphone",
    "/usr/sbin/contentminer",
    "/usr/sbin/dangbei-adapter",
    "/usr/sbin/lg.thinqai.adapter",
    "/usr/sbin/nlpmanager",
    "/usr/sbin/nudge",
    "/usr/sbin/performer",
    "/usr/sbin/rdxd",
    "/usr/sbin/service-logger",
    "/usr/sbin/trigger_alexa",
    "/usr/sbin/trigger_thinq",
    "/usr/sbin/update",
    "/usr/sbin/uploadd",
    "/usr/sbin/user-context-manager",
    "/usr/sbin/user-intent-manager",
    "/usr/sbin/voiceclick",
    "/usr/sbin/voiceconductor",
    "/usr/sbin/voiceinput",
    "/usr/sbin/voiceinput_hidraw",
    "/usr/sbin/voiceinput_network",
    "/usr/sbin/voiceinput_preprocessor",
    "/usr/sbin/voiceinput_sound"
  ],
  "mic_devices": [
    "/dev/snd/pcmC1D0c"
  ],
  "preserve_units": [
    "audiod.service",
    "audiooutputd.service",
    "pulseaudio.service",
    "videooutputd.service",
    "pqcontroller.service",
    "panelcontroller.service",
    "arccontroller.service"
  ],
  "profile_id": "lg-g5-webos-10.2.1-aarch64",
  "sdx_maps": [
    "/usr/palm/sdx/server_addr_version.conf",
    "/mnt/lg/cmn_data/sdp/sdx/server_addr_version.conf"
  ],
  "settings": {
    "general": {
      "adCookie": "off",
      "aiNudge": "off",
      "aiSettingsNudge": "off",
      "customizedAd": "off",
      "homePromotion": "off",
      "screenSaverAd": "off",
      "voiceLongDistance": "off"
    },
    "option": {
      "dbgLogUpload": false,
      "faultLogUpload": false,
      "hbbTV": "offByUser",
      "hbbTvDeviceId": "off",
      "hbbTvDnt": "on",
      "thirdPartyCookie": "offByUser",
      "turnOnByVoice": "off",
      "usageCare": false,
      "watchedListCollection": "off"
    },
    "other": {
      "contentRecommendation": "off"
    }
  },
  "units": [
    "/etc/systemd/system/com.webos.service.microphone.service",
    "/etc/systemd/system/contentminer.service",
    "/etc/systemd/system/nudge.service",
    "/etc/systemd/system/rdxd.service",
    "/etc/systemd/system/service-logger.service",
    "/etc/systemd/system/update-remote-config.service",
    "/etc/systemd/system/update.service",
    "/etc/systemd/system/uploadd.service",
    "/etc/systemd/system/user-context-manager.service",
    "/etc/systemd/system/voiceconductor.service",
    "/etc/systemd/system/voiceinput.service"
  ]
}''')


def report(command, findings, **extra):
    states = {item['status'] for item in findings}
    status = 'fail' if 'fail' in states else ('unknown' if states & {'unknown', 'not-tested'} or not states else 'pass')
    return dict(schema_version=1, version=VERSION, command=command,
                profile=POLICY.get('profile_id'), timestamp=time.time(),
                monotonic=time.monotonic(), status=status, findings=findings,
                scope={'tv': 'local observations, not trusted attestation',
                       'pi': 'not-tested', 'upstream_filtering': 'unknown'}, **extra)


def finding(name, status, detail, source):
    return {'name': name, 'status': status, 'detail': detail, 'source': source}


def proc_address(value):
    host, port = value.split(':')
    raw = bytes.fromhex(host)
    if len(raw) not in (4, 16):
        raise ValueError('Invalid proc address length')
    if sys.byteorder == 'little':
        raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return {'address': str(ipaddress.ip_address(raw)), 'port': int(port, 16)}


def socket_rows(text, protocol, family):
    rows, errors = [], []
    for number, line in enumerate(text.splitlines()[1:], 2):
        try:
            fields = line.split()
            local, remote = proc_address(fields[1]), proc_address(fields[2])
            inode = str(int(fields[9]))
            if not re.fullmatch(r'[0-9A-Fa-f]{2}', fields[3]) or any(ipaddress.ip_address(item['address']).version != family for item in (local, remote)):
                raise ValueError('Invalid socket state/address family')
            address = ipaddress.ip_address(remote['address'])
            rows.append({'protocol': protocol, 'family': family, 'local': local,
                         'remote': remote, 'state': fields[3], 'inode': inode,
                         'remote_scope': ('unspecified' if address.is_unspecified else
                                          'global' if address.is_global else 'non-global'),
                         'owners': [], 'attribution': 'unknown'})
        except (ValueError, IndexError):
            errors.append('Malformed socket row ' + str(number))
    return rows, errors


def process_inventory(proc=Path('/proc')):
    owners, handles, errors = {}, {}, []
    for directory in sorted(proc.glob('[0-9]*')):
        pending_owners, pending_handles = [], []
        try:
            stat = (directory / 'stat').read_text()
            start = stat[stat.rfind(')') + 2:].split()[19]
            identity = {'pid': int(directory.name), 'comm': (directory / 'comm').read_text().strip(),
                        'start_ticks': start}
            try:
                identity['executable'] = os.readlink(directory / 'exe')
            except OSError:
                identity['executable'] = None
            # An unreadable fd directory is incomplete evidence, not an empty one.
            descriptors = list((directory / 'fd').iterdir())
            for fd in descriptors:
                try:
                    target = os.readlink(fd)
                    if target.startswith('socket:[') and target.endswith(']'):
                        pending_owners.append(target[8:-1])
                    elif target.startswith('/dev/snd/') or target.removesuffix(' (deleted)') == '/tmp/capture.rgb':
                        mode = None
                        try:
                            info = (directory / 'fdinfo' / fd.name).read_text()
                            match = re.search(r'^flags:\s+([0-7]+)', info, re.M)
                            mode = int(match[1], 8) & os.O_ACCMODE if match else None
                        except OSError:
                            pass
                        pending_handles.append((target.removesuffix(' (deleted)'), dict(identity, access_mode=mode)))
                except FileNotFoundError:
                    continue
                except OSError:
                    errors.append('Unreadable descriptor for PID ' + directory.name)
            final_stat = (directory / 'stat').read_text()
            if final_stat[final_stat.rfind(')') + 2:].split()[19] != start:
                errors.append('PID reused during sampling: ' + directory.name)
                continue
            for inode in pending_owners:
                owners.setdefault(inode, []).append(identity)
            for target, owner in pending_handles:
                handles.setdefault(target, []).append(owner)
        except FileNotFoundError:
            continue
        except (OSError, ValueError, IndexError):
            errors.append('Incomplete process metadata for PID ' + directory.name)
    return owners, handles, errors


def connection_snapshot(proc=Path('/proc')):
    rows, errors = [], []
    for protocol in ('tcp', 'udp'):
        for suffix, family in (('', 4), ('6', 6)):
            path = proc / 'net' / (protocol + suffix)
            try:
                parsed, malformed = socket_rows(path.read_text(), protocol, family)
                rows.extend(parsed)
                errors.extend(str(path) + ': ' + item for item in malformed)
            except OSError:
                errors.append('Socket table unavailable: ' + str(path))
    owners, _, failures = process_inventory(proc)
    errors.extend(failures)
    for row in rows:
        row['owners'] = owners.get(row['inode'], [])
        if row['owners']:
            row['attribution'] = 'observed'
    return {'timestamp': time.time(), 'monotonic': time.monotonic(),
            'sockets': rows, 'errors': errors}


def connections(seconds=0, interval=1):
    deadline = time.monotonic() + seconds
    samples = []
    while True:
        samples.append(connection_snapshot())
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))
    incomplete = any(s['errors'] or any(not r['owners'] for r in s['sockets']) for s in samples)
    return report('connections', [finding('process attribution', 'unknown' if incomplete else 'pass',
                  'Snapshots can miss short-lived connections; unconnected UDP has no remote peer.',
                  '/proc/net/{tcp,tcp6,udp,udp6} and /proc/PID/fd')], samples=samples)


def capture_inventory(root=Path('/')):
    nodes, errors = {}, []
    proc = root / 'proc/asound/pcm'
    try:
        for line in proc.read_text().splitlines():
            match = re.match(r'\s*(\d+)-(\d+):.*:\s*.*capture\s+\d+', line)
            if match:
                node = '/dev/snd/pcmC%dD%dc' % (int(match[1]), int(match[2]))
                nodes[node] = {'kernel_description': line.strip(), 'device_present': False}
    except OSError:
        errors.append('ALSA kernel inventory unavailable')
    for path in (root / 'dev/snd').glob('pcmC*D*c'):
        if re.fullmatch(r'pcmC\d+D\d+c', path.name):
            nodes.setdefault('/dev/snd/' + path.name, {'kernel_description': None})['device_present'] = True
    _, handles, failures = process_inventory(root / 'proc')
    errors.extend(failures)
    for name, node in nodes.items():
        node.update(path=name, consumers=handles.get(name, []),
                    classification='reviewed WoV microphone' if name in POLICY['mic_devices'] else 'unknown capture purpose',
                    automatic_block=name in POLICY['mic_devices'])
    screen = {'path': '/tmp/capture.rgb', 'status': 'not-tested', 'contents_read': False,
              'handles': handles.get('/tmp/capture.rgb', [])}
    try:
        st = (root / 'tmp/capture.rgb').stat()
        screen.update(status='unknown', mode=oct(st.st_mode & 0o7777), size=st.st_size,
                      world_readable=bool(st.st_mode & 0o004))
    except FileNotFoundError:
        screen['detail'] = 'Absent now; on-demand generation remains untested'
    except OSError:
        errors.append('Screen-capture metadata unavailable')
    return {'nodes': list(nodes.values()), 'screen': screen, 'errors': errors,
            'voice_pipeline': [{'path': p, 'present': (root / p.lstrip('/')).exists()}
                               for p in POLICY['executables'] if 'voiceinput' in p or 'voiceconductor' in p]}


def audit(root=Path('/')):
    findings = []
    def read(name):
        return (root / name.lstrip('/')).read_text()
    try:
        fields = dict(line.split('=', 1) for line in read('/etc/os-release').splitlines() if '=' in line)
        supported = fields.get('ID', '').strip('"') == 'starfish' and fields.get('VERSION_ID', '').strip('"') == '10.2.1'
        findings.append(finding('firmware', 'pass' if supported else 'fail', fields, '/etc/os-release'))
    except (OSError, ValueError):
        findings.append(finding('firmware', 'unknown', 'Unavailable', '/etc/os-release'))
    findings.append(finding('model', 'not-tested', 'Passive audit does not activate TV system-property service; check validates exact model.', 'profile'))
    try:
        mounts = {}
        for line in read('/proc/self/mountinfo').splitlines():
            f = line.split(); mounts[f[4]] = f
        state_path = root / str(BASE / 'state.json').lstrip('/')
        state = json.loads(state_path.read_text()) if state_path.exists() else None
        if state:
            for record in state['mounts']:
                source = root / record['source'].lstrip('/')
                target = root / record['target'].lstrip('/')
                entry = mounts.get(record['target'])
                good = entry and 'ro' in entry[5].split(',') and same_file(source, target)
                findings.append(finding(record['target'], 'pass' if good else 'fail', 'Owned read-only overlay' if good else 'Missing, writable or foreign overlay', '/proc/self/mountinfo + stat'))
        else:
            findings.append(finding('installation', 'unknown', 'No packaged installation journal; inspect legacy deployment.', str(BASE)))
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        findings.append(finding('mounts', 'unknown', 'Unavailable or malformed journal/mount evidence', '/proc/self/mountinfo'))
    for category, settings in POLICY['settings'].items():
        try:
            data = json.loads(read('/var/luna/preferences/' + category))
            for key, expected in settings.items():
                status = 'unknown' if key not in data else ('pass' if data[key] == expected else 'fail')
                findings.append(finding(category + '.' + key, status, {'expected': expected, 'actual': data.get(key)}, 'persisted preferences'))
        except (OSError, ValueError, TypeError):
            findings.append(finding(category, 'unknown', 'Persisted settings unavailable', 'persisted preferences'))
    try:
        consent = json.loads(read('/var/luna/preferences/eula'))
        if not isinstance(consent.get('eulaStatus'), dict) or not OPTIONAL_FLAGS.intersection(consent['eulaStatus']):
            raise ValueError('Unknown schema')
        findings.append(finding('optional consents', 'pass' if opt_out(consent) == consent else 'fail',
                                'Selective persisted-state check; firmware behavior unproven', 'persisted preferences'))
    except (OSError, ValueError, TypeError, AttributeError):
        findings.append(finding('optional consents', 'unknown', 'Missing or malformed evidence', 'persisted preferences'))
    inventory = capture_inventory(root)
    findings.append(finding('capture coverage', 'unknown', 'Only reviewed WoV node enforced; other paths require investigation.', '/dev/snd + /proc/asound + fd metadata'))
    network = {}
    for path in ('/etc/resolv.conf', '/proc/net/route', '/proc/net/ipv6_route', '/proc/net/dev'):
        try:
            network[path] = read(path)
        except OSError:
            network[path] = None
    hooks = [str(p.relative_to(root)) for p in (root / 'var/lib/webosbrew/init.d').glob('*')]
    findings.append(finding('boot hooks', 'unknown' if any('lg-privacy' in p for p in hooks) else 'not-tested', hooks, 'init.d inventory'))
    for name in ('native IPv6 enforcement', 'streaming/store/casting/ThinQ acceptance', 'cold boot and restore lifecycle'):
        findings.append(finding(name, 'not-tested', 'Requires a separate live experiment', 'acceptance gate'))
    return report('audit', findings, capture=inventory, network=network)


def emit_report(data, as_json=False):
    if as_json:
        print(json.dumps(data, indent=2))
    else:
        print(data['command'].upper(), data['status'].upper(), '(local observations only)')
        for item in data['findings']:
            print(item['status'].upper(), item['name'], json.dumps(item['detail']))
        if 'samples' in data:
            for sample in data['samples']:
                for row in sample['sockets']:
                    print(sample['timestamp'], row['protocol'], row['local'], '->', row['remote'], row['attribution'], row['owners'])
        if 'capture' in data:
            print('CAPTURE INVENTORY', json.dumps(data['capture']))


def run(args, check=True, input_text=None):
    result = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(args) + '\n' + result.stdout)
    return result


def luna(method, payload):
    # A controlling terminal is needed by luna-send on the tested firmware.
    pid, fd = pty.fork()
    if pid == 0:
        os.execv('/usr/bin/luna-send', ['luna-send', '-w', '10000', '-n', '1',
                   'luna://' + method, json.dumps(payload, separators=(',', ':'))])
    output = bytearray()
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.25)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
        else:
            raise RuntimeError('Luna request timed out: ' + method)
    finally:
        os.close(fd)
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
    for line in output.decode(errors='replace').splitlines():
        try:
            result = json.loads(line)
        except ValueError:
            continue
        if result.get('returnValue') is True:
            return result
        if 'returnValue' in result:
            raise RuntimeError('Luna rejected ' + method + ': ' + line)
    raise RuntimeError('No successful Luna response: ' + method)


def atomic(path, data, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    with temporary.open('w') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    temporary.replace(path)


def save(state):
    atomic(BASE / 'state.json', json.dumps(state, indent=2) + '\n')


def get_settings(category, keys):
    return luna('com.webos.settingsservice/getSystemSettings',
                {'category': category, 'keys': list(keys)})['settings']


def set_settings(category, settings):
    luna('com.webos.settingsservice/setSystemSettings', {'category': category, 'settings': settings})


def opt_out(eula):
    result = copy.deepcopy(eula)
    for key in OPTIONAL_FLAGS & result.get('eulaStatus', {}).keys():
        result['eulaStatus'][key] = False
    for category in ('eulaInfo', 'eulaInfoNetwork'):
        for item in result.get(category, {}).get('eulaList', []):
            if item.get('id') in OPTIONAL_DOCS:
                item['accepted'] = False
    return result


def filtered_map(data):
    result = copy.deepcopy(data)
    versions = result.get('severDomain')
    if not isinstance(versions, dict) or not versions:
        raise RuntimeError('Unknown SDX map schema')
    found = set()
    for routes in versions.values():
        if not isinstance(routes, list):
            raise RuntimeError('Unknown SDX route schema')
        for route in routes:
            if route.get('serviceName') in POLICY['blocked_sdx_services']:
                found.add(route['serviceName'])
                route['domain'] = 'privacy-blocked.invalid'
    if found != set(POLICY['blocked_sdx_services']):
        raise RuntimeError('SDX map does not contain all six reviewed logging routes')
    return result


def mountpoints():
    return {line.split()[4] for line in Path('/proc/self/mountinfo').read_text().splitlines()}


def same_file(source, target):
    try:
        return os.path.samefile(source, target)
    except OSError:
        return False


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def readonly_mount(target):
    entries = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()
               if len(line.split()) > 5 and line.split()[4] == target]
    return bool(entries and 'ro' in entries[-1][5].split(','))


def hosts_underlay_digest():
    # Homebrew adds these exact OTA records when the update-block marker changes.
    generated = {'# This file is dynamically regenerated on boot by webosbrew startup script',
                 '127.0.0.1 snu.lge.com su-dev.lge.com su.lge.com su-ssl.lge.com',
                 '::1 snu.lge.com su-dev.lge.com su.lge.com su-ssl.lge.com'}
    text = '\n'.join(line for line in Path('/etc/hosts').read_text().splitlines() if line.strip() and line not in generated)
    return hashlib.sha256(text.encode()).hexdigest()


def known_hosts_underlay(state):
    if '/etc/hosts' in mountpoints() and not same_file('/tmp/hosts', '/etc/hosts'):
        return False
    return hosts_underlay_digest() == state.get('hosts_underlay_sha256')


def activation_sources():
    return {target: BASE / decision['asset'] for target, decision in POLICY.get('activation_decisions', {}).items()
            if decision['action'] == 'block'}


def activation_issues():
    issues = []
    for target, decision in POLICY.get('activation_decisions', {}).items():
        try:
            if decision['action'] == 'block':
                if decision['executable'] not in POLICY['executables']:
                    raise ValueError('Activation targets a preserved executable')
                source = BASE / decision['asset']
                if source.parent != BASE / 'activation':
                    raise ValueError('Invalid activation asset')
                if target in mountpoints():
                    if not same_file(source, target):
                        issues.append('Foreign activation mount: ' + target)
                elif sha256(target) != decision['original_sha256']:
                    issues.append('Activation firmware bytes changed: ' + target)
            elif decision['action'] in ('preserve', 'absent'):
                if sha256(target) != decision['original_sha256']:
                    issues.append('Preserved activation changed: ' + target)
                if decision['action'] == 'absent' and Path(decision['executable']).exists():
                    issues.append('Previously absent executable appeared: ' + decision['executable'])
            else:
                raise ValueError('Unknown activation action')
        except (OSError, ValueError) as error:
            issues.append(target + ': ' + str(error))
    return issues


def runtime_issues(state):
    issues = []
    if state.get('version') != 2 or not state.get('integrity'):
        return ['Installation predates integrity journal; reviewed migration required.']
    for name, expected in state['integrity'].items():
        try:
            if sha256(name) != expected:
                issues.append('Integrity changed: ' + name)
        except OSError:
            issues.append('Integrity file missing: ' + name)
    for record in state['mounts']:
        if record['target'] in mountpoints() and not same_file(record['source'], record['target']):
            if record['target'] != '/etc/hosts' or not known_hosts_underlay(state):
                issues.append('Foreign mount: ' + record['target'])
    if '/etc/hosts' not in {r['target'] for r in state['mounts']} or not same_file(BASE / 'hosts.filtered', '/etc/hosts'):
        try:
            if not known_hosts_underlay(state):
                issues.append('Hosts underlay changed; review before layering')
        except (OSError, KeyError):
            issues.append('Hosts underlay unavailable')
    return issues


def prepare_runtime(state):
    (BASE / 'activation').mkdir(exist_ok=True)
    for target, decision in POLICY.get('activation_decisions', {}).items():
        if decision['action'] == 'block':
            atomic(BASE / decision['asset'], decision['replacement'])
    service = '[Unit]\nDescription=PWN-your-glass control maintenance\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 ' + str(BASE / 'privacy.py') + ' health\nTimeoutStartSec=240\n'
    timer = '[Unit]\nDescription=Check configured TV privacy controls every five minutes\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=5min\nUnit=' + HEALTH_NAME + '.service\n'
    atomic(BASE / (HEALTH_NAME + '.service'), service)
    atomic(BASE / (HEALTH_NAME + '.timer'), timer)
    names = [BASE / 'privacy.py', BASE / 'blocked-executable', BASE / 'empty-unit', HOOK]
    names += list(activation_sources().values())
    names += [BASE / ('sdx-' + str(i) + '.json') for i in range(len(POLICY['sdx_maps']))]
    names += [BASE / (HEALTH_NAME + suffix) for suffix in ('.service', '.timer')]
    names += [p for p in STARTUPS if p.exists()]
    state['integrity'] = {str(p): sha256(p) for p in names}
    state['hosts_underlay_sha256'] = hosts_underlay_digest()
    save(state)


def maintenance_units(state, remove=False):
    for suffix in ('.timer', '.service'):
        source = BASE / (HEALTH_NAME + suffix)
        target = UNIT_DIR / source.name
        if target.exists() and sha256(target) != state['integrity'].get(str(source)):
            raise RuntimeError('Foreign maintenance unit: ' + str(target))
    if remove:
        run(['systemctl', 'stop', HEALTH_NAME + '.timer', HEALTH_NAME + '.service'], False)
        for suffix in ('.timer', '.service'):
            (UNIT_DIR / (HEALTH_NAME + suffix)).unlink(missing_ok=True)
    else:
        for suffix in ('.timer', '.service'):
            source = BASE / (HEALTH_NAME + suffix)
            atomic(UNIT_DIR / source.name, source.read_text(), 0o644)
    run(['systemctl', 'daemon-reload'])
    if not remove:
        run(['systemctl', 'start', HEALTH_NAME + '.timer'])


def health(state):
    if state['status'] in ('restored', 'restore-incomplete'):
        return ['Maintenance disabled after restore']
    repaired = False
    try:
        issues = runtime_issues(state) + compatible()
        if not issues:
            issues = verify(state)
            if issues:
                apply(state)
                maintenance_units(state)
                repaired = True
                issues = verify(state)
    except Exception as error:
        issues = [type(error).__name__ + ': ' + str(error)]
    data = report('health', [finding('configured controls', 'fail' if issues else 'pass', [item[:1000] for item in issues[:50]], 'local verification')], repaired=repaired)
    atomic(Path('/run/pwn-glass-health.json'), json.dumps(data))
    return issues


def compatible():
    errors = []
    if platform.system() != 'Linux' or platform.machine() != 'aarch64':
        return ['This profile requires Linux aarch64 on the tested LG G5.']
    release = Path('/etc/os-release').read_text()
    fields = dict(line.split('=', 1) for line in release.splitlines() if '=' in line)
    if fields.get('ID', '').strip('"') != 'starfish' or fields.get('VERSION_ID', '').strip('"') != '10.2.1':
        errors.append('Only webOS TV 10.2.1 is reviewed.')
    if not MIC_INFO.exists() or 'WoV PDM Mic snd-soc-dummy-dai-0' not in MIC_INFO.read_text():
        errors.append('The capture node is not the reviewed WoV PDM microphone.')
    if Path('/var/lib/webosbrew/init.d/05-lg-privacy').exists():
        errors.append('Existing manual privacy installation detected; migration is not automatic.')
    for command in ('mount', 'umount', 'unshare', 'systemctl', 'iptables', 'iptables-restore', 'luna-send'):
        if not shutil.which(command):
            errors.append('Missing required command: ' + command)
    for path in POLICY['executables'] + POLICY['units'] + POLICY['mic_devices'] + POLICY['sdx_maps']:
        if not Path(path).exists():
            errors.append('Missing reviewed path: ' + path)
    if not Path('/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service/startup.sh').exists():
        errors.append('Rooted Homebrew Channel must be installed first.')
    if errors:
        return errors
    errors.extend(activation_issues())
    model = luna('com.webos.service.tv.systemproperty/getSystemInfo', {'keys': ['modelName']}).get('modelName', '')
    if model != 'OLED65G56LS':
        errors.append('Untested model: ' + repr(model) + '; expected OLED65G56LS.')
    for path in POLICY['sdx_maps']:
        filtered_map(json.loads(Path(path).read_text()))
    for category, settings in POLICY['settings'].items():
        current = get_settings(category, settings)
        if set(settings) - current.keys():
            errors.append('Missing privacy settings in ' + category)
    eula = get_settings('eula', ['eulaStatus', 'eulaInfo', 'eulaInfoNetwork'])
    if not isinstance(eula.get('eulaStatus'), dict) or not (OPTIONAL_FLAGS & eula['eulaStatus'].keys()):
        errors.append('Missing reviewed EULA consent status schema.')
    return errors


def check_telnet_safety():
    keys = Path('/home/root/.ssh/authorized_keys')
    if not (PREFS / 'webosbrew_sshd_enabled').exists() or not keys.exists() or not keys.read_text().strip():
        raise RuntimeError('Enable Homebrew SSH and install your own authorized key before disabling Telnet.')
    if not os.environ.get('SSH_CONNECTION'):
        raise RuntimeError('Run --disable-telnet from a working SSH login to confirm alternate access.')


def bind(state, source, target, layered=False):
    source = str(source)
    mounted = target in mountpoints()
    if mounted and same_file(source, target):
        if not readonly_mount(target):
            run(['mount', '-o', 'remount,bind,ro', target])
        return
    if mounted and not layered:
        raise RuntimeError('Conflicting mount; refusing to replace: ' + target)
    record = {'source': source, 'target': target}
    if record not in state['mounts']:
        state['mounts'].append(record)
        save(state)  # Record before mutation so an interrupted install remains recoverable.
    run(['mount', '--bind', source, target])
    run(['mount', '-o', 'remount,bind,ro', target])


def stop_processes(paths):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for entry in glob.glob('/proc/[0-9]*/exe'):
            try:
                if os.readlink(entry).removesuffix(' (deleted)') in paths:
                    os.kill(int(entry.split('/')[2]), sig)
            except (FileNotFoundError, ProcessLookupError):
                pass
        if sig == signal.SIGTERM:
            time.sleep(1)


def firewall(remove=False):
    ipt = shutil.which('iptables')
    current = run([ipt, '-S', CHAIN], False)
    expected = '-A ' + CHAIN + ' -d 156.147.69.32/32 -p tcp -m tcp --dport 8080 -j REJECT --reject-with icmp-port-unreachable'
    if current.returncode == 0 and [line for line in current.stdout.splitlines() if line.startswith('-A ')] not in ([], [expected]):
        raise RuntimeError('Unexpected firewall chain contents; refusing to replace')
    exists = current.returncode == 0
    if remove:
        while run([ipt, '-C', 'OUTPUT', '-j', CHAIN], False).returncode == 0:
            run([ipt, '-D', 'OUTPUT', '-j', CHAIN])
        if exists:
            run([ipt, '-F', CHAIN])
            run([ipt, '-X', CHAIN])
        return
    if not exists:
        run([ipt, '-N', CHAIN])
    if not exists or expected not in current.stdout.splitlines():
        run([shutil.which('iptables-restore'), '--noflush', '--wait', '5'],
            input_text='*filter\n-F ' + CHAIN + '\n' + expected + '\nCOMMIT\n')
    if run([ipt, '-C', 'OUTPUT', '-j', CHAIN], False).returncode:
        run([ipt, '-I', 'OUTPUT', '1', '-j', CHAIN])


def quarantine():
    # Internal action must be in a separate mount namespace; never unmount Homebrew queues globally.
    if os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise RuntimeError('Quarantine requires a private mount namespace')
    run(['mount', '--make-rprivate', '/'])
    destination = BASE / 'quarantine' / str(uuid.uuid4())
    count = 0
    for name in QUEUES:
        if name in mountpoints():
            run(['umount', name])
        directory = Path(name)
        if directory.is_symlink():
            raise RuntimeError('Unexpected symlink queue: ' + name)
        if not directory.is_dir():
            continue
        for entry in list(directory.iterdir()):
            target = destination / name.lstrip('/')
            target.mkdir(parents=True, exist_ok=True)
            shutil.move(str(entry), str(target / entry.name))
            count += 1
    print('Quarantined', count, 'diagnostic queue entries; no upload or deletion.')


def apply(state):
    issues = runtime_issues(state) + activation_issues()
    if issues:
        raise RuntimeError('; '.join(issues))
    for target in POLICY['executables']:
        bind(state, BASE / 'blocked-executable', target)
    for target in POLICY['units']:
        bind(state, BASE / 'empty-unit', target)
    for target in POLICY['mic_devices']:
        bind(state, '/dev/null', target)
    for target, source in activation_sources().items():
        bind(state, source, target)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'stop', '--no-block'] + [Path(p).name for p in POLICY['units']])
    stop_processes(set(POLICY['executables']))
    for index, target in enumerate(POLICY['sdx_maps']):
        bind(state, BASE / ('sdx-' + str(index) + '.json'), target)
    # Replace only our hosts layer, preserving Homebrew OTA entries underneath.
    hosts = BASE / 'hosts.filtered'
    if not ('/etc/hosts' in mountpoints() and same_file(hosts, '/etc/hosts')):
        original = Path('/etc/hosts').read_text()
        if HOST_MARKER in original:
            raise RuntimeError('Unexpected existing DangBro hosts block')
        lines = original.rstrip() + '\n\n' + HOST_MARKER + '\n'
        for host in POLICY['blocked_hosts']:
            lines += '0.0.0.0 ' + host + '\n:: ' + host + '\n'
        atomic(hosts, lines)
        state['integrity'][str(hosts)] = sha256(hosts)
        save(state)
        bind(state, hosts, '/etc/hosts', layered=True)
    elif not readonly_mount('/etc/hosts'):
        run(['mount', '-o', 'remount,bind,ro', '/etc/hosts'])
    firewall()
    # Existing SDX processes may have read their route map before the boot hook.
    stop_processes({'/usr/sbin/sdx'})
    for category, settings in POLICY['settings'].items():
        set_settings(category, settings)
    eula = get_settings('eula', ['eulaStatus', 'eulaInfo', 'eulaInfoNetwork'])
    set_settings('eula', opt_out(eula))
    acr = Path('/mnt/lg/cmn_data/acr/data')
    if acr.is_dir():
        (acr / 'eula_allowed').unlink(missing_ok=True)
        (acr / 'eula_disallowed_rebooted').touch()
    run(['unshare', '-m', sys.executable, str(BASE / 'privacy.py'), '_quarantine'])
    if state['disable_telnet']:
        (PREFS / 'webosbrew_telnet_disabled').touch()
    (PREFS / 'webosbrew_block_updates').touch()
    state['status'] = 'applied'
    save(state)
    run(['sync'])


def install(disable_telnet, recovery=None):
    errors = compatible()
    if errors:
        raise RuntimeError('\n'.join(errors))
    if disable_telnet:
        check_telnet_safety()
    if (BASE / 'state.json').exists():
        state = json.loads((BASE / 'state.json').read_text())
        if state['status'] in ('restored', 'restore-incomplete'):
            raise RuntimeError('Previous install restored. Archive its backup directory before reinstalling.')
        if disable_telnet:
            state['disable_telnet'] = True
            save(state)
        apply(state)
        return verify(state)
    if BASE.exists() or HOOK.exists():
        raise RuntimeError('Unrecognized existing installation; refusing to overwrite.')
    if run([shutil.which('iptables'), '-S', CHAIN], False).returncode == 0:
        raise RuntimeError('Firewall chain name already in use.')
    mounts = mountpoints()
    if '/etc/hosts' in mounts and not same_file('/tmp/hosts', '/etc/hosts'):
        raise RuntimeError('Unknown hosts overlay; refusing to layer over another installer')
    for target in POLICY['executables'] + POLICY['units'] + POLICY['mic_devices'] + POLICY['sdx_maps']:
        if target in mounts:
            raise RuntimeError('Existing overlay requires manual review: ' + target)
    # Gather all inputs before creating the backup or changing the TV.
    settings = recovery['settings'] if recovery else {c: get_settings(c, s) for c, s in POLICY['settings'].items()}
    maps = recovery['maps'] if recovery else [Path(path).read_text() for path in POLICY['sdx_maps']]
    filtered = [filtered_map(json.loads(value)) for value in maps]
    BASE.mkdir(mode=0o700)
    hook_text = '#!/bin/sh\n/usr/bin/python3 /var/lib/webosbrew/dangbro-privacy/privacy.py boot >>/tmp/dangbro-privacy.log 2>&1\n'
    state = {'version': 2, 'status': 'installing', 'mounts': [], 'settings': settings,
             'integrity': {str(HOOK): hashlib.sha256(hook_text.encode()).hexdigest()},
             'disable_telnet': disable_telnet,
             'telnet_was_disabled': (PREFS / 'webosbrew_telnet_disabled').exists(),
             'updates_were_blocked': (PREFS / 'webosbrew_block_updates').exists()}
    if recovery:
        state.update(telnet_was_disabled=recovery['telnet_was_disabled'],
                     updates_were_blocked=recovery['updates_were_blocked'],
                     recovery_provenance=recovery['provenance'])
    save(state)
    for index, data in enumerate(maps):
        atomic(BASE / ('sdx-original-' + str(index) + '.json'), data)
        atomic(BASE / ('sdx-' + str(index) + '.json'), json.dumps(filtered[index]))
    atomic(BASE / 'blocked-executable', '#!/bin/sh\n# DangBro privacy block\nexit 1\n', 0o755)
    atomic(BASE / 'empty-unit', '')
    atomic(BASE / 'privacy.py', Path(__file__).read_text(), 0o700)
    acr = Path('/mnt/lg/cmn_data/acr/data/eula_allowed')
    if acr.is_file():
        shutil.copy2(acr, BASE / 'original-eula-allowed')
    HOOK.parent.mkdir(exist_ok=True)
    atomic(HOOK, hook_text, 0o755)
    prepare_runtime(state)
    apply(state)
    maintenance_units(state)
    return verify(state)


def verify(state):
    issues = runtime_issues(state) + activation_issues()
    if state['status'] == 'restored':
        return ['Installer has been restored; protections are no longer applied.']
    expected = set(POLICY['executables'] + POLICY['units'] + POLICY['mic_devices'] + POLICY['sdx_maps'] + ['/etc/hosts'] + list(activation_sources()))
    recorded = {record['target'] for record in state['mounts']}
    for target in sorted(expected - recorded):
        issues.append('Installation incomplete, missing overlay: ' + target)
    for record in state['mounts']:
        if record['target'] not in mountpoints() or not same_file(record['source'], record['target']) or not readonly_mount(record['target']):
            issues.append('Overlay absent: ' + record['target'])
    for category, settings in POLICY['settings'].items():
        actual = get_settings(category, settings)
        for key, value in settings.items():
            if actual.get(key) != value:
                issues.append('Setting mismatch: ' + category + '.' + key)
    eula = get_settings('eula', ['eulaStatus', 'eulaInfo', 'eulaInfoNetwork'])
    if eula != opt_out(eula):
        issues.append('Optional consent enabled')
    for name in POLICY['blocked_sdx_services']:
        result = luna('com.webos.service.sdx/getServerUrl', {'serviceName': name})
        from urllib.parse import urlsplit
        host = urlsplit(result.get('baseUrl', '')).hostname or ''
        if host != 'privacy-blocked.invalid' and not host.endswith('.privacy-blocked.invalid'):
            issues.append('SDX route not blocked: ' + name)
    for entry in glob.glob('/proc/[0-9]*/exe'):
        try:
            if os.readlink(entry).removesuffix(' (deleted)') in POLICY['executables']:
                issues.append('Collector still running: ' + entry)
        except FileNotFoundError:
            pass
    for unit in POLICY['preserve_units']:
        if run(['systemctl', 'is-active', unit], False).returncode:
            issues.append('Preserved AV service inactive: ' + unit)
    if run([shutil.which('iptables'), '-C', 'OUTPUT', '-j', CHAIN], False).returncode:
        issues.append('OTA fallback firewall missing')
    rules = run([shutil.which('iptables'), '-S', CHAIN], False)
    expected_rule = '-A ' + CHAIN + ' -d 156.147.69.32/32 -p tcp -m tcp --dport 8080 -j REJECT --reject-with icmp-port-unreachable'
    if [line for line in rules.stdout.splitlines() if line.startswith('-A ')] != [expected_rule]:
        issues.append('OTA firewall rule missing or unexpected scope')
    hosts = Path('/etc/hosts').read_text()
    for host in POLICY['blocked_hosts']:
        if '0.0.0.0 ' + host + '\n' not in hosts or ':: ' + host + '\n' not in hosts:
            issues.append('Host block missing: ' + host)
    if not (PREFS / 'webosbrew_block_updates').exists():
        issues.append('Homebrew update-block preference missing')
    if state['disable_telnet'] and not (PREFS / 'webosbrew_telnet_disabled').exists():
        issues.append('Telnet boot-disable marker missing')
    if not HOOK.exists():
        issues.append('Boot hook missing')
    if run(['systemctl', 'is-active', HEALTH_NAME + '.timer'], False).returncode:
        issues.append('Maintenance timer inactive')
    return issues


def restore(state):
    # First prevent reapplication. Leave backup/queue data private and never reaccept consent.
    if state.get('version') == 2:
        maintenance_units(state, remove=True)
        if HOOK.exists() and sha256(HOOK) != state['integrity'].get(str(HOOK)):
            raise RuntimeError('Foreign startup hook; refusing to remove')
    HOOK.unlink(missing_ok=True)
    failures = []
    for record in reversed(state['mounts']):
        target = record['target']
        if target in mountpoints():
            if same_file(record['source'], target):
                run(['umount', target])
            else:
                failures.append('Foreign mount left untouched: ' + target)
    firewall(remove=True)
    for category, settings in state['settings'].items():
        set_settings(category, settings)
    for name, existed in [('webosbrew_telnet_disabled', state['telnet_was_disabled']),
                          ('webosbrew_block_updates', state['updates_were_blocked'])]:
        if existed:
            (PREFS / name).touch()
        else:
            (PREFS / name).unlink(missing_ok=True)
    run(['systemctl', 'daemon-reload'])
    state['status'] = 'restore-incomplete' if failures else 'restored'
    save(state)
    print('Reboot manually to restart services. Backups and quarantined queues are retained.')
    print('Optional legal consents remain declined; quarantined uploads are not requeued.')
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['check', 'install', 'verify', 'restore', 'boot', 'health', 'audit', 'connections', '_quarantine'])
    parser.add_argument('--json', action='store_true', help='Structured output for audit, connections, check and verify')
    parser.add_argument('--seconds', type=float, default=0, help='Connections sampling duration, 0..300')
    parser.add_argument('--interval', type=float, default=1, help='Connections sampling interval, 0.2..60 seconds')
    parser.add_argument('--disable-telnet', action='store_true', help='Disable normal-boot Telnet after a working SSH login; no immediate disconnect')
    args = parser.parse_args()
    if not 0 <= args.seconds <= 300 or not 0.2 <= args.interval <= 60:
        parser.error('Sampling requires 0 <= seconds <= 300 and 0.2 <= interval <= 60')
    if args.json and args.command not in ('audit', 'connections', 'check', 'verify'):
        parser.error('--json is supported only for read-only reports')
    if args.disable_telnet and args.command != 'install':
        parser.error('--disable-telnet is only valid with install')
    if args.command in ('audit', 'connections'):
        data = audit() if args.command == 'audit' else connections(args.seconds, args.interval)
        emit_report(data, args.json)
        return 1 if data['status'] == 'fail' else 2 if data['status'] == 'unknown' else 0
    if args.command == 'check':
        errors = compatible()
        if args.json:
            emit_report(report('check', [finding('compatibility', 'fail' if errors else 'pass', errors, 'profile preflight')]), True)
            return bool(errors)
        for error in errors:
            print('UNSUPPORTED:', error)
        if not errors:
            print('Compatible reviewed profile. No changes made. Installation disables ACR, voice, ads, diagnostics and firmware updates.')
        return bool(errors)
    if os.geteuid() != 0:
        raise RuntimeError('Run as root on the TV.')
    if args.command == 'verify':
        try:
            state = json.loads((BASE / 'state.json').read_text())
            issues = verify(state)
            status = 'fail' if issues else 'pass'
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            issues, status = [str(error)], 'unknown'
        emit_report(report('verify', [finding('configured controls', status, issues, 'local verification')]), args.json)
        return bool(issues)
    os.umask(0o077)
    if args.command == '_quarantine':
        quarantine()
        return 0
    # Lock outside BASE so check/install never mistake our own lock for an existing install.
    with open('/var/lib/webosbrew/.dangbro-privacy.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'install':
            issues = install(args.disable_telnet)
        else:
            state = json.loads((BASE / 'state.json').read_text())
            if args.command == 'boot':
                if state['status'] in ('restored', 'restore-incomplete'):
                    return 0
                errors = compatible()
                if errors:
                    raise RuntimeError('Boot profile mismatch: ' + '; '.join(errors))
                apply(state)
                maintenance_units(state)
                issues = verify(state)
            elif args.command == 'health':
                issues = health(state)
            elif args.command == 'restore':
                issues = restore(state)
            else:
                issues = verify(state)
        for issue in issues:
            print('FAIL:', issue)
        print(args.command.upper(), 'FAILED' if issues else 'PASS')
        if args.command == 'install':
            print('Leave the physical mic switch Off. Reboot with Quick Start+ Off, then run verify again.')
            print('Telnet is unchanged now; --disable-telnet affects the next normal boot. Homebrew failsafe may reopen it.')
        return bool(issues)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('ERROR:', error, file=sys.stderr)
        print('If installation partly applied, keep WAN blocked, inspect the local backup, and use restore if needed.', file=sys.stderr)
        sys.exit(1)
