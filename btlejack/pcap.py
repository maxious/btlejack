"""
Quick'n'dirty Pcap module

This module only provides a specific class able to write
PCAP files with Bluetooth Low Energy Link Layer.
"""
import os
import sys
from io import BytesIO
from struct import pack
# https://wiki.wireshark.org/CaptureSetup/Pipes#Way_3:_Python_on_Windows
IS_WINDOWS = False
if sys.platform.startswith('win'):
    import win32pipe, win32file
    IS_WINDOWS = True

class FifoError(Exception):
    def __init__(self):
        super().__init__()


class PcapBleWriter(object):
    """
    PCAP BLE Link-layer writer.
    """

    DLT =  251  # DLT_BLUETOOTH_LE_LL

    def __init__(self, output=None, fifo=None):
        # open stream
        if output is None:
            self.output = BytesIO()
        else:
            self.output = open(output,'wb')

        # open fifo if required
        if fifo is None:
            self.fifo = None
        else:

            try:
                if IS_WINDOWS:
                    # check if fifo already exists
                    print("opening fifo, run: C:\Program Files\Wireshark\Wireshark.exe -k -i\\\\.\\pipe\\"+ fifo)
                    self.fifo = win32pipe.CreateNamedPipe(
                        r'\\.\pipe\{}'.format(fifo),
                        win32pipe.PIPE_ACCESS_OUTBOUND,
                        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                        1, 65536, 65536,
                        300,
                        None)

                    #connect to pipe
                    print('[i] Waiting for wireshark to connect ...')
                    win32pipe.ConnectNamedPipe(self.fifo, None)

                else:
                    # check if fifo already exists
                    print("opening fifo, run: wireshark -k -i",os.path.abspath(fifo))
                    if not os.path.exists(fifo):
                        os.mkfifo(fifo)
                    print('[i] Waiting for wireshark to connect ...')
                    self.fifo = open(fifo, 'wb')
            except IOError as fifo_err:
                raise FifoError()

        # write headers
        self.write_header()

    def write_fifo(self, data):
        """
        Write data to fifo, if a fifo has been specified.
        """
        if self.fifo is not None:
            if IS_WINDOWS:
                win32file.WriteFile(self.fifo, data)
            else:
                self.fifo.write(data)

    def flush_fifo(self):
        """
        Flush fifo if a fifo has been specified.
        """
        if self.fifo is not None and not IS_WINDOWS:
            self.fifo.flush()

    def write_header(self):
        """
        Write PCAP header.
        """
        header = pack(
            '<IHHIIII',
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            self.DLT
        )
        self.output.write(header)
        self.write_fifo(header)

    def write_packet_header(self, ts_sec, ts_usec, packet_size):
        """
        Write packet header
        """
        pkt_header = pack(
            '<IIII',
            ts_sec,
            ts_usec,
            packet_size,
            packet_size
        )
        self.output.write(pkt_header)
        self.write_fifo(pkt_header)

    def payload(self, aa, packet):
        """
        Generates Bluetooth LE LL packet format.
        You must override this method for every inherited
        writer classes.
        """
        return pack('<I', aa) + packet[10:]+ pack('<BBB',0,0,0) # fake CRC for now

    def write_packet(self, ts_sec, ts_usec, aa, packet):
        """
        Add packet to PCAP output.

        Basically, generates payload and encapsulates in a header.
        """
        payload = self.payload(aa, packet)
        self.write_packet_header(ts_sec, ts_usec, len(payload))
        self.output.write(payload)
        self.write_fifo(payload)
        self.flush_fifo()

    def close(self):
        """
        Close PCAP.
        """
        if not isinstance(self.output, BytesIO):
            self.output.close()
        if self.fifo is not None:
            self.fifo.close()

class PcapBlePHDRWriter(PcapBleWriter):
    """
    PCAP BLE Link-layer with PHDR.
    """
    DLT = 256 # DLT_BLUETOOTH_LE_LL_WITH_PHDR

    def __init__(self, output=None, fifo=None):
        super().__init__(output=output, fifo=fifo)

    def payload(self, aa, packet):
        """
        Generate payload with specific header.
        """
        payload_header = pack(
            '<BbbBIH',
            packet[2],
            -packet[3],
            -100,
            0,
            aa,
            0x813
        )
        payload_data = pack('<I', aa) + packet[10:] + pack('<BBB', 0, 0, 0)
        return payload_header + payload_data


class PcapNordicTapWriter(PcapBleWriter):
    """
    PCAP BLE Link-layer writer.
    """

    DLT = 272 # DLT_NORDIC_BLE
    BTLEJACK_ID = 0xDC

    def __init__(self, output=None, fifo=None):
        super().__init__(output=output, fifo=fifo)
        self.pkt_counter = 0

    def payload(self, aa, packet):
        """
        Create payload with Nordic Tap header.
        """
        payload_data = packet[:10] + pack('<I', aa) + packet[10:]
        payload_data += pack('<BBB', 0, 0, 0)
        pkt_size = len(payload_data)
        if pkt_size > 256:
            pkt_size = 256

        payload_header = pack(
            '<BBBBHB',
            self.BTLEJACK_ID,
            6,
            pkt_size,
            1,
            self.pkt_counter,
            0x06 # EVENT_PACKET
        )

        return payload_header + payload_data[:pkt_size]
