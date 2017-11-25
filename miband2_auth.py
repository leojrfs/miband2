#!/usr/bin/env python2
import struct
import time
import sys
import argparse
from Crypto.Cipher import AES
from bluepy.btle import Peripheral, DefaultDelegate, ADDR_TYPE_RANDOM


class MiBand2(Peripheral):
    _KEY = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x40\x41\x42\x43\x44\x45'
    _send_key_cmd = struct.pack('<18s', b'\x01\x08' + _KEY)
    _send_rnd_cmd = struct.pack('<2s', b'\x02\x08')
    _send_enc_key = struct.pack('<2s', b'\x03\x08')

    def __init__(self, addr):
        Peripheral.__init__(self, addr, addrType=ADDR_TYPE_RANDOM)
        print("Connected")
        self.handle = 0
        self.raw_data = b'0'
        self.timeout = 5.0
        self.auth = False
        # Enable auth service notifications on startup
        self.auth_notif(True)

    def encrypt(self, message):
        aes = AES.new(self._KEY, AES.MODE_ECB)
        return aes.encrypt(message)

    def auth_notif(self, status):
        if status:
            print("Enabling Auth Service notifications status...")
            self.writeCharacteristic(0x51, struct.pack('<2s', b'\x01\x00'), True)
        elif not status:
            print("Disabling Auth Service notifications status...")
            self.writeCharacteristic(0x51, struct.pack('<2s', b'\x00\x00'), True)
        else:
            print("Something went wrong while changing the Auth Service notifications status...")

    def send_key(self):
        print("Sending Key...")
        self.writeCharacteristic(0x50, self._send_key_cmd)
        self.waitForNotifications(self.timeout)

    def req_rdn(self):
        print("Requesting random number...")
        self.writeCharacteristic(0x50, self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)

    def send_enc_rdn(self, data):
        print("Sending encrypted random number")
        cmd = self._send_enc_key + self.encrypt(data)
        send_cmd = struct.pack('<18s', cmd)
        self.writeCharacteristic(0x50, send_cmd)
        self.waitForNotifications(self.timeout)

    def authenticate(self):
        self.setDelegate(AuthenticationDelegate(self))
        print("Requesting random number...")
        self.writeCharacteristic(0x50, self._send_rnd_cmd)
        self.waitForNotifications(self.timeout)
        while True:
            if self.auth:
                return True
            elif self.auth == -1:
                return False


class AuthenticationDelegate(DefaultDelegate):

    """This Class inherits DefaultDelegate to handle the authentication process."""
    def __init__(self, device):
        DefaultDelegate.__init__(self)
        self.device = device

    def handleNotification(self, hnd, data):
        # Debug purposes
        # print("HANDLE: " + str(hex(hnd)))
        # print("DATA: " + str(data.encode("hex")))
        if hnd == int('0x50', 16):
            if data[:3] == b'\x10\x01\x01':
                self.device.req_rdn()
            elif data[:3] == b'\x10\x01\x04':
                print("Something went wrong while sending the key!")
                print("Response: " + str(data.encode("hex")))
                self.device.auth = -1
            elif data[:3] == b'\x10\x02\x01':
                random_nr = data[3:]
                self.device.send_enc_rdn(random_nr)
            elif data[:3] == b'\x10\x02\x04':
                print("Authention failed! Something wrong when requesting the random number...")
                print("Response: " + str(data.encode("hex")))
                self.device.auth = -1
            elif data[:3] == b'\x10\x03\x01':
                print("Authenticated!")
                self.device.auth = True
            elif data[:3] == b'\x10\x03\x04':
                print("Encryption Key Auth Fail, sending new Key...")
                self.device.send_key()
            else:
                print("Auth error, cant help! Response: " + str(data.encode("hex")))
                self.device.auth = -1


def main():
    """ main func """
    parser = argparse.ArgumentParser()
    parser.add_argument('host', action='store', help='MAC of BT device')
    parser.add_argument('-t', action='store', type=float, default=3.0,
                        help='duration of each notification')
    parser.add_argument('-a', '--authenticate', action='store_true', default=False)
    parser.add_argument('-n', '--notify', action='store_true', default=False)
    arg = parser.parse_args(sys.argv[1:])

    print('Connecting to ' + arg.host)
    band = MiBand2(arg.host)
    band.setSecurityLevel(level="medium")

    if arg.authenticate:
        if band.authenticate():
            if arg.notify:
                print("Sending message notification...")
                band.writeCharacteristic(0x25, struct.pack('<b', 0x01))
                time.sleep(arg.t)
                print("Sending phone notification...")
                band.writeCharacteristic(0x25, struct.pack('<b', 0x02))
                time.sleep(arg.t)
                print("Turning off notifications...")
                band.writeCharacteristic(0x25, struct.pack('<b', 0x00))
    print("Disconnecting...")
    band.disconnect()
    del band


if __name__ == "__main__":
    main()
