__author__ = 'SuicidalLabRat'
__version__ = '0.0.1'


import platform
import sys
import os
import re
import subprocess
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


def get_active_mac(iface=''):
    print(platform.system())
    print(sys.platform)
    if sys.platform == 'win32':
        command = 'Get-NetRoute'
        power_shell_path = r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe'
        try:
            p = subprocess.Popen([power_shell_path, '-ExecutionPolicy', 'Unrestricted', command,
                                  '|', 'Where-Object -FilterScript {$_.NextHop -Ne "::"}',
                                  '|', 'Where-Object -FilterScript { $_.NextHop -Ne "0.0.0.0" }',
                                  '|', 'Where-Object -FilterScript { ($_.NextHop.SubString(0,6) -Ne "fe80::") }',
                                  '|', 'Get-NetAdapter']
                                 , stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            rc = p.returncode
        except IOError:
            print('Requires Windows 10 or later. Requires PowerShell: {0}'.format(power_shell_path))
            raise
        except Exception:
            raise

        if rc == 0:
            output = output.decode('utf-8').split('\r\n')
            if_desc = re.split(r'\s{2,}', str(output[3]))
            if_mac = if_desc[3].split()
            return if_mac[0].replace('-', '').lower()
        else:
            print('Failed to get MAC address.\n{0} returned {1}.'.format(power_shell_path, rc))
            return None

    elif sys.platform == 'darwin':
        route_default_result = subprocess.check_output(["route", "get", "default"])
        # gw = re.search(b"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", route_default_result).group(0)
        default_iface = re.search(b"(?:interface:.)(.*)", route_default_result).group(1).decode('utf-8')
        """
        Returns currently-set MAC address of given interface. This is
        distinct from the interface's hardware MAC address.
        """

        try:
            result = subprocess.check_output([
                'ifconfig',
                default_iface],
                stderr=subprocess.STDOUT,
                universal_newlines=True)
        except subprocess.CalledProcessError:
            return None

        address = MAC_ADDRESS_R.search(result.lower().replace(':', ''))
        if address:
            address = address.group(0)

        return address

    elif sys.platform().startswith('linux'):
        route_default_result = re.findall(b"([\w.][\w.]*'?\w?)", subprocess.check_output(["ip", "route"]))
        # gw = route_default_result[2]
        default_iface = route_default_result[4].decode('utf-8')
        if 'redaptive' in platform.uname().node:
            default_iface = 'eth0'
        if route_default_result:
            # return gw, default_iface
            return default_iface
        else:
            print("(x) Could not read default routes.")


# Regex to validate a MAC address, as 00-00-00-00-00-00 or
# 00:00:00:00:00:00 or 000000000000.
MAC_ADDRESS_R = re.compile(r"""
   ([0-9A-F]{1,2})[:-]?
   ([0-9A-F]{1,2})[:-]?
   ([0-9A-F]{1,2})[:-]?
   ([0-9A-F]{1,2})[:-]?
   ([0-9A-F]{1,2})[:-]?
   ([0-9A-F]{1,2})
   """,
       re.I | re.VERBOSE
)

if __name__ == '__main__':
    thing_name = ""
    try:
        thing_name = get_active_mac()
    except Exception as ex:
        print('Failed to get MAC address!\n{0}'.format(ex))
        raise

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

    if thing_name:
        print("Running...")
        PubSub(listener=True, topic=mqtt_topic, mqtt_client_id=thing_name).bootstrap_mqtt(dev_env).start(mqtt_msg)
