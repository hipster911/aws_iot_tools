__author__ = 'SuicidalLabRat'
__version__ = '0.0.1'


from getmac import get_mac_address
import paho.mqtt.client as paho
import ssl
from time import sleep
import logging
logging.basicConfig(filename='./pubsub.log', level=logging.DEBUG)


class PubSub(object):

    def __init__(self, listener=False, topic="default", mqtt_client_id=""):
        self.mqttc = paho.Client(client_id=mqtt_client_id)
        self.connect = False
        self.listener = listener
        self.topic = topic
        self.logger = logging.getLogger(repr(self))

    def __on_connect(self, client, userdata, flags, rc):
        self.connect = True
        if self.listener:
            try:
                self.mqttc.subscribe(self.topic, 1)
                self.logger.debug("Subscribed to: {0}".format(self.topic))
            except Exception as e:
                self.logger.debug("Subscribe Failed:\n{0}".format(e))

        self.logger.debug("Con Log: {0}".format(rc))

    def __on_subscribe(self, client, obj, mid, granted_qos):
        print("Subscribed to Topic: {0} with QoS: {1}\n{2} {3} {4}".format(
            self.topic, str(granted_qos), client, obj[0], mid))

    def __on_message(self, client, userdata, msg):
        self.logger.info("Message: {0}, {1} - {2}".format(userdata, msg.topic, msg.payload))
        print('message received: {0} '.format(str(msg.payload.decode('utf-8'))))
        print('message topic={0}'.format(msg.topic))
        print('message qos={0}'.format(msg.qos))
        print('message retain flag={0}'.format(msg.retain))

    def __on_log(self, client, userdata, level, buf):
        self.logger.debug("On Log: {0}, {1}, {2}, {3}".format(client, userdata, level, buf))

    def bootstrap_mqtt(self):
        self.mqttc.on_connect = self.__on_connect
        self.mqttc.on_subscribe = self.__on_subscribe
        self.mqttc.on_message = self.__on_message
        self.mqttc.on_log = self.__on_log

        # awshost = "a37prab8rk99q2-ats.iot.us-east-2.amazonaws.com"  # prod
        awshost = "a372uklyvnvbpu-ats.iot.us-east-2.amazonaws.com"  # dev
        awsport = 8883
        keepalive_interval = 60

        ca_path = "./certs/rootCa.crt"
        cert_path = "./certs/dev/client.crt"
        key_path = "./certs/dev/client.key"

        self.mqttc.tls_set(ca_path,
                           certfile=cert_path,
                           keyfile=key_path,
                           cert_reqs=ssl.CERT_REQUIRED,
                           tls_version=ssl.PROTOCOL_TLSv1_2,
                           ciphers=None)

        result_of_connection = self.mqttc.connect(awshost, awsport, keepalive=keepalive_interval)

        if result_of_connection == 0:
            self.logger.info('Connected to {0}'.format(awshost))
            self.connect = True

        return self

    def start(self):
        self.mqttc.loop_start()
        # self.mqttc.subscribe('#', 1)

        while True:
            sleep(2)
            if self.connect:
                self.mqttc.publish(self.topic, mqtt_msg, qos=1)
            else:
                self.logger.debug("Attempting to connect.")


if __name__ == '__main__':
    thing_name = ""
    try:
        thing_name = get_mac_address(interface="en0").replace(':', '')
    except Exception as ex:
        print('Failed to get MAC address!\n{0}'.format(ex))

    mqtt_topic = '$aws/things/{0}/publish'.format(thing_name)
    mqtt_msg = 'Test Publish: {0}'.format(thing_name)
    print("Running...")
    PubSub(listener=True, topic=mqtt_topic, mqtt_client_id=thing_name).bootstrap_mqtt().start()
