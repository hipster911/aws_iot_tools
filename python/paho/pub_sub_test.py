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

    def ssl_alpn(self, ca='rootCa', cert='client.crt', key='client.key'):
        iot_protocol_name = "x-amzn-mqtt-ca"
        try:
            # debug print opnessl version
            self.logger.info("open ssl version:{}".format(ssl.OPENSSL_VERSION))
            ssl_context = ssl.create_default_context()
            ssl_context.set_alpn_protocols([iot_protocol_name])
            ssl_context.load_verify_locations(cafile=ca)
            ssl_context.load_cert_chain(certfile=cert, keyfile=key)
            return ssl_context
        except Exception as e:
            print("exception ssl_alpn()")
            raise e

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

    def bootstrap_mqtt(self, config):
        self.mqttc.on_connect = self.__on_connect
        self.mqttc.on_subscribe = self.__on_subscribe
        self.mqttc.on_message = self.__on_message
        self.mqttc.on_log = self.__on_log

        if config['awsport'] == 443:
            ssl_context = self.ssl_alpn(ca=config['ca'], cert=config['cert'], key=config['key'])
            self.mqttc.tls_set_context(context=ssl_context)
        else:
            self.mqttc.tls_set(config['ca'],
                               certfile=config['cert'],
                               keyfile=config['key'],
                               cert_reqs=ssl.CERT_REQUIRED,
                               tls_version=ssl.PROTOCOL_TLSv1_2,
                               ciphers=None)

        result_of_connection = self.mqttc.connect(config['awshost'], config['awsport'], keepalive=config['keepalive'])

        if result_of_connection == 0:
            self.logger.info('Connected to {0}'.format(config['awshost']))
            self.connect = True

        return self

    def start(self, msg):
        self.mqttc.loop_start()
        # self.mqttc.subscribe('#', 1)

        while True:
            sleep(2)
            if self.connect:
                self.mqttc.publish(self.topic, msg, qos=1)
            else:
                self.logger.debug("Attempting to connect.")


if __name__ == '__main__':
    thing_name = ""
    try:
        thing_name = get_mac_address(interface="en0").replace(':', '')
    except Exception as ex:
        print('Failed to get MAC address!\n{0}'.format(ex))
        thing_name = '000000000000'
        #raise

    dev_env = {
        'awshost': 'a372uklyvnvbpu-ats.iot.us-east-2.amazonaws.com',
        'awsport': 443,
        'keepalive': 60,
        'ca': 'certs/dev/rootCa.crt',
        'cert': 'certs/dev/client.crt',
        'key': 'certs/dev/client.key'
    }

    prod_env = {
        'awshost': 'a37prab8rk99q2-ats.iot.us-east-2.amazonaws.com',
        'awsport': 8883,
        'keepalive': 60,
        'ca': 'certs/prod/rootCa.crt',
        'cert': 'certs/prod/client.crt',
        'key': 'certs/prod/client.key'
    }

    mqtt_topic = '$aws/things/{0}/publish'.format(thing_name)
    mqtt_msg = 'Test Publish: {0}'.format(thing_name)

    print("Running...")
    PubSub(listener=True, topic=mqtt_topic, mqtt_client_id=thing_name).bootstrap_mqtt(dev_env).start(mqtt_msg)
