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

    # dict storing mqtt message identifier (key) and mapping them to topic (value)
    _msg_topic = {}
    # dict mapping ipal message id (key) to mqtt message identifier (value) for messages with QoS >= 1
    _ipal_id_msg_id = {}

    @classmethod
    def state_identifier(cls, msg, key):
        return key

    def matches_protocol(self, pkt):
        return "MQTT" in pkt

    def parse_packet(self, pkt):
        res = []

        src = "{}:{}".format(pkt["IP"].src, pkt["TCP"].srcport)
        dest = "{}:{}".format(pkt["IP"].dst, pkt["TCP"].dstport)
        mqtt_layer = pkt.get_multiple_layers("MQTT")
        for i in range(0, len(mqtt_layer)):
            mqtt = mqtt_layer[i]
            msg_type = int(mqtt.msgtype)

            msg_len = 2 + int(mqtt.len)

            m = IpalMessage(
                id=self._id_counter.get_next_id(),
                src=src,
                dest=dest,
                timestamp=float(pkt.sniff_time.timestamp()),
                protocol="mqtt",
                length=msg_len,
                type=msg_type,
                activity=self._msgtype_to_act_mapping[msg_type]
            )

            if msg_type == 3:     # PUBLISH
                m.data = {mqtt.topic: bytes.fromhex(str(mqtt.msg).replace(':', '')).decode('ascii')}
                if int(mqtt.qos) >= 1:
                    self._msg_topic[mqtt.msgid] = mqtt.topic
            elif msg_type in [4, 5, 6, 7]:  # PUBACK, PUBREC, PUBREL, PUBCOMP
                self._ipal_id_msg_id[m.id] = mqtt.msgid
            elif msg_type == 8:     # SUBSCRIBE
                m.data = {mqtt.topic: None}
                if int(mqtt.qos) >= 1:
                    self._msg_topic[mqtt.msgid] = mqtt.topic
                    self._ipal_id_msg_id[m.id] = mqtt.msgid
            elif msg_type == 9:     # SUBACK
                m.data = {self._msg_topic.pop(mqtt.msgid): None}
                self._ipal_id_msg_id[m.id] = mqtt.msgid
            elif msg_type == 10:    # UNSUBSCRIBE
                # commented parts here because of the definition of the data field in the exercise. Could be combined with SUBSCRIBE
                # m.data = {mqtt.topic: None}
                if int(mqtt.qos) >= 1:
                    # self.msg_topic[mqtt.msgid] = mqtt.topic
                    self._ipal_id_msg_id[m.id] = mqtt.msgid
            elif msg_type == 11:    # UNSUBACK
                # commented parts here because of the definition of the data field in the exercise. Could be combined with SUBACK
                # m.data = {self.msg_topic.pop(mqtt.msgid): None}
                self._ipal_id_msg_id[m.id] = mqtt.msgid

            if msg_type == 14:
                # Packet type 14 is disconnect and will not trigger a response
                pass
            elif msg_type == 5:
                # Packet type 5 is PUBREC. It will be responded by PUBREL and should be handled the same as a request
                m._match_to_requests = True
                m._add_to_request_queue = True
            elif int(pkt["TCP"].dstport) == settings.MQTT_PORT or int(pkt["TCP"].dstport) == settings.MQTT_TLS_PORT:    # request
                m._add_to_request_queue = True
            elif int(pkt["TCP"].srcport) == settings.MQTT_PORT or int(pkt["TCP"].srcport) == settings.MQTT_TLS_PORT:    # response
                m._match_to_requests = True
            else:
                settings.logger.info("src and dst port not mqtt standard")

            res.append(m)

        return res

    def match_response(self, requests, response):
        rmv = []
        if response.type in [4, 5, 6, 7, 9, 11]:   # cases for responses to requests with QoS >=1
            if response.type == 5:    # special case for PUBREC due to packet type number
                key = (response.dest, 3, self._ipal_id_msg_id[response.id])
            else:
                key = (response.dest, int(response.type) - 1, self._ipal_id_msg_id.pop(response.id))

            for req in requests:
                if (req.src, int(req.type), self._ipal_id_msg_id[req.id]) == key:
                    response.responds_to.append(req.id)
                    self._ipal_id_msg_id.pop(req.id)

        else:   # cases for all other responses without mqtt message id
            key = (response.dest, int(response.type) - 1)
            for req in requests:
                if (req.src, int(req.type)) == key:
                    response.responds_to.append(req.id)
                    rmv.append(req)
                # special case when authentication is used. Connect ACK responds to both
                elif req.src.split(":")[0] == response.dest.split(":")[0] and req.type == 15 and response.type == 2:
                    response.responds_to.append(req.id)
                    rmv.append(req)

        return rmv
