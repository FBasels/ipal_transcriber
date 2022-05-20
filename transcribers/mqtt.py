from transcriber.messages import IpalMessage, Activity
from transcribers.transcriber import Transcriber
import transcriber.settings as settings


class MQTTTranscriber(Transcriber):

    _name = "mqtt"
    _msgtype_to_act_mapping = {
        1: Activity.COMMAND,
        2: Activity.ACTION,
        3: Activity.INFORM,
        4: Activity.ACTION,
        5: Activity.ACTION,
        6: Activity.ACTION,
        7: Activity.COMMAND,
        8: Activity.INTERROGATE,
        9: Activity.INFORM,
        10: Activity.COMMAND,
        11: Activity.ACTION,
        12: Activity.INTERROGATE,
        13: Activity.INFORM,
        14: Activity.COMMAND
    }

    # dict mapping message identifier (key) to topic (value)
    msg_topic = {}

    # TODO: implement
    def state_identifier(cls, msg, key):
        # Used to identify a single variable for the state. Since e.g.
        # in Modbus a specific coil.1 depends on the IP address and unitID,
        # whereas in NMEA 0183 a GLL measurement does not necessarily
        # depend on the source address.
        # Default is source and variable name separated by ':'.

        # INFO Same ip+port+key for different protocols unlikely
        return "{}:{}".format(msg.src, key)

    def matches_protocol(self, pkt):

        return "MQTT" in pkt

    # TODO: add responds_to entry in IpalMessage
    def parse_packet(self, pkt):
        res = []

        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
        mqtt_layer = pkt.get_multiple_layers("MQTT")
        # print(mqtt_layer)
        for i in range(0, len(mqtt_layer)):
            mqtt = mqtt_layer[i]
            type = int(mqtt.msgtype)
            # print(mqtt.field_names)
            # print(mqtt)
            msg_len = 2 + int(mqtt.len)

            m = IpalMessage(
                id=self._id_counter.get_next_id(),
                src=src,
                dest=dest,
                timestamp=float(pkt.sniff_time.timestamp()),
                protocol="mqtt",
                length=msg_len,
                type=type,
                activity=self._msgtype_to_act_mapping[type]
            )

            if type == 3:
                # decode binary data to ascii
                m.data = {mqtt.topic: bytes.fromhex(str(mqtt.msg).replace(':', '')).decode('ascii')}
            elif type == 8:
                m.data = {mqtt.topic: None}
                self.msg_topic[mqtt.msgid] = mqtt.topic
            elif type == 9:
                # maybe avoid pop if the entry in the dict is needed for linking messages
                m.data = {self.msg_topic.pop(mqtt.msgid): None}

            res.append(m)

        return res

    # TODO: implement
    def match_response(self, requests, response):
        # Modifies a response by information derived from the corresponding request(s). This method may alter the requests in the request array but not the request array! It may return a list of requests to delete from the queue
        return []