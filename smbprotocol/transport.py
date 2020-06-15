# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import asyncio
import logging
import select
import socket
import struct

from collections import (
    OrderedDict,
)

from smbprotocol.structure import (
    BytesField,
    IntField,
    Structure,
)

try:
    from queue import Queue
except ImportError:  # pragma: no cover
    from Queue import Queue

log = logging.getLogger(__name__)


class DirectTCPPacket(Structure):
    """
    [MS-SMB2] v53.0 2017-09-15

    2.1 Transport
    The Directory TCP transport packet header MUST have the following
    structure.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('stream_protocol_length', IntField(
                size=4,
                little_endian=False,
                default=lambda s: len(s['smb2_message']),
            )),
            ('smb2_message', BytesField(
                size=lambda s: s['stream_protocol_length'].get_value(),
            )),
        ])
        super(DirectTCPPacket, self).__init__()


class Tcp(object):

    MAX_SIZE = 16777215

    def __init__(self, server, port, recv_queue, timeout=None):
        self.server = server
        self.port = port
        self.timeout = timeout
        self._connected = False
        self._sock = None
        self._recv_queue = recv_queue
        self._t_recv = None

    async def connect(self):
        def wrap_err_msg(err):
            return "Failed to connect to '%s:%s': %s" % (self.server, self.port, str(err))

        if not self._connected:
            log.info("Connecting to DirectTcp socket")
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self.server, self.port),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError as err:
                raise asyncio.TimeoutError(wrap_err_msg(err))
            except OSError as err:
                err.strerror = wrap_err_msg(err.strerror)
                raise err
            self._t_recv = asyncio.create_task(
                self._recv_task(),
                # name="recv-%s:%s" % (self.server, self.port),  # requires python3.8
            )
            self._connected = True

    async def disconnect(self):
        if self._connected:
            log.info("Disconnecting DirectTcp socket")
            # Send a shutdown to the socket so the select returns and wait until the thread is closed before actually
            # closing the socket.
            await self._writer.drain()
            self._connected = False
            if self._writer.can_write_eof():
                self._writer.write_eof()
                await self._writer.drain()
            self._writer.close()
            await self._writer.wait_closed()
            try:
                # give receive task 1 second to quit
                await asyncio.wait_for(self._t_recv, timeout=1)
            except asyncio.TimeoutError:
                self._t_recv.cancel()

    def close(self):
        if self._connected:
            log.info("Closing DirectTcp socket")
            self._connected = False
            if self._writer.can_write_eof():
                self._writer.write_eof()
            self._t_recv.cancel()
            self._writer.close()

    async def send(self, header):
        b_msg = header
        data_length = len(b_msg)
        if data_length > self.MAX_SIZE:
            raise ValueError("Data to be sent over Direct TCP size %d exceeds the max length allowed %d"
                             % (data_length, self.MAX_SIZE))

        tcp_packet = DirectTCPPacket()
        tcp_packet['smb2_message'] = b_msg

        self._writer.write(tcp_packet.pack())
        await self._writer.drain()

    async def _recv_task(self):
        try:
            while True:
                b_packet_size = await self._reader.readexactly(4)
                message_type = b_packet_size[0]
                assert message_type == 0, "Unexpected NetBIOS message type 0x%02x" % message_type
                packet_size = (b_packet_size[1] << 16) + (b_packet_size[2] << 8) + b_packet_size[3]
                await self._recv_queue.put(await self._reader.readexactly(packet_size))
        except asyncio.CancelledError:
            raise
        except asyncio.IncompleteReadError as e:
            if len(e.partial) == 0: return
            if self._connected:
                await self._recv_queue.put(e)
        except Exception as e:
            if self._connected:
                await self._recv_queue.put(e)
        finally:
            # Make sure we close the message processing task in connection.py
            await self._recv_queue.put(None)
