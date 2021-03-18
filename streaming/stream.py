import serial
import struct
import sys
import logging
import time
from collections import defaultdict

log = logging.getLogger(__name__)


def bytes_to_int(b):
    return struct.unpack("I", b)[0]

def bytes_to_long_long(b):
    return struct.unpack("Q", b)[0]


class MessageType:
    ONLINE = 0
    SEND_STRING = 1
    CHUNK_REQUEST = 2
    BENCHMARK = 3
    RESULT = 4
    BYTES = 5

class RequestType:
    PK = 0
    SM = 1

class StreamData:
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def __str__(self):
        return f"{self.name} [length: {len(self.data)}]"


class Stream:

    def __init__(self, sm, pk, pk_hash_function):
        self.streams = {
            RequestType.PK: StreamData("PK", pk),
            RequestType.SM: StreamData("SM", sm)
        }
        self.pk_hash_function = pk_hash_function
        self.ser = serial.Serial("/dev/ttyACM0")
        self.ser.baudrate = 57600
        self.msg_subscribers = defaultdict(list)
        self.str_subscribers = defaultdict(list)

    def subscribe_message_type(self, msg_type, f):
        """
        Add subscriber that will be called once a message is received.
        :param msg_type: MessageType to subscribe to
        :param f: Callable that will be called back when msg is received. f will be called with msg payload as argument.
        :return: None
        """
        self.msg_subscribers[msg_type].append(f)

    def recv_pkg(self):
        try:
            pkg_typ = self.ser.read(1)[0]
        except IndexError:
            raise ValueError("Timeout: No data was returned.")
        log.debug("Received package of type %d.", pkg_typ)

        msg = ""

        if pkg_typ == MessageType.ONLINE:
            sm_len = len(self.streams[RequestType.SM].data)
            log.info("Device is online.")
            log.info("Sending sm length %d.", sm_len)
            self.ser.write(struct.pack("I", sm_len))
            # don't know why this is needed
            time.sleep(0.1)
            pk_hash = self.pk_hash_function(self.streams[RequestType.PK].data)
            log.info("Sending pk hash %s.", str(pk_hash.hex().encode()))
            self.ser.write(pk_hash)
        elif pkg_typ == MessageType.SEND_STRING:
            str_len = bytes_to_int(self.ser.read(4))
            log.debug("Receiving string of length %d.", str_len)
            msg = self.ser.read(str_len)
            log.info("DEVICE sent string: %s.", msg.decode())
        elif pkg_typ == MessageType.BENCHMARK:
            str_len = bytes_to_int(self.ser.read(4))
            log.debug("Receiving benchmark name of length %d.", str_len)
            name = self.ser.read(str_len).decode()
            log.debug("Received benchmark name %s.", name)
            cycles = bytes_to_long_long(self.ser.read(8))
            log.debug("Received benchmark %s with value %d.", name, cycles)
            msg = (name, cycles)
        elif pkg_typ == MessageType.CHUNK_REQUEST:
            req_type = self.ser.read(1)[0]
            pos = bytes_to_int(self.ser.read(4))
            req = bytes_to_int(self.ser.read(4))
            msg = (req_type, req)
            try:
                stream = self.streams[req_type]
                log.debug("Device requested %d byte chunk of %s at pos %d.", req, stream, pos)
                self.ser.write(stream.data[pos:pos+req])
            except KeyError:
                log.error("Device requested %d bytes of chunk type %d, which doesn't exist.", req, req_type)
        elif pkg_typ == MessageType.BYTES:
            str_len = bytes_to_int(self.ser.read(4))
            log.debug("Receiving BYTES name of length %d.", str_len)
            name = self.ser.read(str_len).decode()
            log.debug("Received BYTES name %s.", name)
            bytes_len = bytes_to_int(self.ser.read(4))
            bytes_msg = self.ser.read(bytes_len)
            log.debug("Received BYTES %s with content %s.", name, bytes_msg.hex())
            msg = (name, bytes_msg)
        elif pkg_typ == MessageType.RESULT:
            msg = bytes_to_int(self.ser.read(4))
            log.debug("Received result: %s", bool(msg))
        else:
            log.error("Received unknown pkg_type %d.", pkg_typ)

        for sub in self.msg_subscribers[pkg_typ]:
            sub(msg)

        return pkg_typ, msg

    def stream(self):
        log.debug("Starting streaming.")

        # Wait till device wakes up
        self.ser.timeout = 1
        for _ in range(100):
            self.ser.write(b"A")
            try:
                self.recv_pkg()
            except ValueError:
                log.debug("Device is not up yet.")
            else:
                break
        else:
            log.error("Device did not get up. Stopping.")
            return None
        
        self.ser.timeout = None

        while True:
            pkg_typ, msg = self.recv_pkg()
            if pkg_typ == MessageType.RESULT:
                break

        self.ser.close()
        return msg

