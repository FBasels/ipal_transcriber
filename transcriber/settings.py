import logging

# Gzip options
compresslevel = 9  # 0 no compress, 1 large/fast, 9 small/slow

# Pyshark options
MBTCP_PORT = 502  # Default Modbus Port
ENIP_PORT = 44818
MQTT_PORT = 1883
MQTT_TLS_PORT = 8883

pyshark_options = [
    "-o",
    "udp.check_checksum:TRUE",
    "-o",
    "tcp.check_checksum:TRUE",
    "-o",
    "mbtcp.tcp.port:{}".format(MBTCP_PORT),
]

pyshark_decode_as = {}

# Transcriber default settings
mode = None  # 'pcap' or 'interface'
source = None  # path to pcap or interface name
protocols = []  # protocol names to transcribe
rules = None
rulesin = None  # path to rule file
crc = "and"  # application, transport, and, or
timeout = 0.250  # 250 ms
maliciousdefault = None
malicious = None
maliciousin = None

# Output settings
ipalout = None
ipaloutfd = None
evalout = None
evaloutfd = None

# Logging settings
logger = logging.getLogger("Transcriber")
log = logging.WARNING
logformat = "%(levelname)s:%(name)s:%(message)s"
logfile = None

# State output
ipalin = None
ipalinfd = None
state_extractor = None
stateout = None
stateoutfd = None
filter = None
completeonly = False
stateinmessage = False


def settings_to_dict():
    return {
        "compresslevel": compresslevel,
        "pyshark_options": pyshark_options,
        "source": source,
        "protocols": protocols,
        "rules": rulesin,
        "crc": crc,
        "timeout": timeout,
        "maliciousdefault": maliciousdefault,
        "malicious": maliciousin,
        "ipalout": ipalout,
        "log": log,
        "logformat": logformat,
        "logfile": logfile,
    }
