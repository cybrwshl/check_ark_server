#!/usr/bin/env python3

"""
Copyright 2016 Manuel Knodel

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import socket
import collections
import struct
import re
import nagiosplugin
import argparse


class ArkSourceQuery(object):
  """Query (UDP) an Ark Surival server (based on Source Query)
  
  Very handy to retrieve game version, name, etc of a running server.
  
  Documentation:
      http://ark.gamepedia.com/Server_Browser
      https://developer.valvesoftware.com/wiki/Server_queries
      https://docs.python.org/3/library/struct.html
  
  Code Samples:
      https://github.com/Dasister/Source-Query-Class-Python/blob/master/QueryClass.py
  """

  socket = None

  @staticmethod
  def query_info(host, port, quiet=False):
    """UDP Query Source Server (Ark Survival) for standard data

    Args:
      host, port of Ark Survival server.

    Returns:
      OrderedDict: Key Value ordered dict of parsed data according to http://ark.gamepedia.com/Server_Browser
    """
    packet = SourcePacket("A2S_INFO")

    ArkSourceQuery.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ArkSourceQuery.socket.settimeout(2)
    try:
      ArkSourceQuery.socket.sendto(packet.encoded,(host, port))
      raw = ArkSourceQuery.socket.recvfrom(1400)[0]
    except socket.error as msg:
      raise ConnectionError('SteamQuery: Unable to connect to {}:{} [{}]'.format(host, port, msg))
      return False

    decoded = packet.decode(raw)
    return decoded

class SourcePacket(object):
  """Packet for query to Source Server
  
  Object remembers how to decode response based on packet type in transmission.
  Upon __init__() creates variable "encoded" ready for transmission.
  
  Use decode(raw_data) to parse incoming transmission.
  
  Arg packet_type:
        A2S_INFO
            Basic information about the server.
        A2S_PLAYER
            Details about each player on the server.
        A2S_RULES
            The rules the server is using.
        A2A_PING
            Ping the server. (DEPRECATED)
        A2S_SERVERQUERY_GETCHALLENGE
            Returns a challenge number for use in the player and rules query. (DEPRECATED)
  """
  
  def __init__(self, packet_type):
    self.packet_type = packet_type
    self.encoded = self._encode()
      
  @staticmethod
  def _write(datatype, val):
    """Pack values based on source doc data types
    
    Args:
      datatype: byte, short, long, float, long long, string
      val: Value to be prepared
    Returns:
      binary data
        
    From Source Doc:
      Name	Description
      byte	8 bit character or unsigned integer
      short	16 bit signed integer
      long	32 bit signed integer
      float	32 bit floating point
      long long	64 bit unsigned integer
      string	variable-length byte field, encoded in UTF-8, terminated by 0x00
      
      https://developer.valvesoftware.com/wiki/Server_queries
      https://docs.python.org/3/library/struct.html
    """
    
    if datatype == "byte":
      return struct.pack("<B", val)
    elif datatype == "short":
      return struct.pack("<i", val)
    elif datatype == "long":
      return struct.pack("<i", val)
    elif datatype == "float":
      return struct.pack("<f", val)
    elif datatype == "long long":
      return struct.pack("<I", val)
    elif datatype == "string":
      return bytes(val + "\x00", "utf-8")
    else:
      raise TypeError("Unknown data type for source packet")
  
  def _encode(self):
    """Prepare transmission based on self.packet_type
    
    Returns:
      binary data
    """
    
    if self.packet_type == "A2S_INFO":
      encoded = self._write("long", -1)
      encoded += self._write("byte", 0x54)
      encoded += self._write("string", "Source Engine Query")
      return encoded
    else:
      raise TypeError("Unknown packet_type")
 
 
  def decode(self, raw):
    """Decode data from transmission
    
    Name	Description
    byte	8 bit character or unsigned integer
    short	16 bit signed integer
    long	32 bit signed integer
    float	32 bit floating point
    long long	64 bit unsigned integer
    string	variable-length byte field, encoded in UTF-8, terminated by 0x00

    """

    if self.packet_type == "A2S_INFO":
      return self._decode_A2S_INFO(raw) 

 
  def _decode_A2S_INFO(self, raw):
    """Decode A2S_INFO Source Query for Ark Survival
    
    Args:
      raw: Raw transmission data (byte string)
        
    Returns
      OrderedDict: Key Value ordered dict of parsed data according to http://ark.gamepedia.com/Server_Browser
        
    Docs and code samples:
      https://developer.valvesoftware.com/wiki/Server_queries
      http://ark.gamepedia.com/Server_Browser
      https://github.com/Dasister/Source-Query-Class-Python/blob/master/QueryClass.py
    """

    parsed = collections.OrderedDict()

    ignore_wrapper, raw = self._read("long", raw)
    ignore_header, raw = self._read("byte", raw)

    parsed['protocol'], raw = self._read("byte", raw)
    parsed['name'], raw = self._read("string", raw)

    regex = re.compile("\(v(?P<version>[\d.]+)\)")
    search_result = regex.search(parsed['name'])
    if search_result:
      parsed['game_version'] = search_result.group('version')
    else:
      #If the server name is too long the name gets truncated and version may not work.
      parsed['game_version'] = None

    parsed['map'], raw = self._read("string", raw)
    parsed['folder'], raw = self._read("string", raw)
    parsed['game'], raw = self._read("string", raw)
    parsed['id'], raw = self._read("short", raw)
    parsed['players'], raw = self._read("byte", raw)
    parsed['max_players'], raw = self._read("byte", raw)
    parsed['bots'], raw = self._read("byte", raw)
    parsed['server_type'], raw = self._read("byte", raw)
    parsed['platform'], raw = self._read("byte", raw)
    parsed['private'], raw = self._read("byte", raw)
    parsed['vac'], raw = self._read("byte", raw)
    parsed['version'], raw = self._read("string", raw)

    #Bitfield
    edf, raw = self._read("byte", raw)

    if edf & 0x80:
      parsed['game_port'], raw = self._read("short", raw)

    if edf & 0x10:    
      parsed['owner_steam_id'], raw = self._read("long long", raw)

    if edf & 0x40:
      parsed['source_tv_port'], raw = self._read("short", raw)
      parsed['source_tv_host'], raw = self._read("string", raw)

    if edf & 0x20:    
      """
      Key	Type	Value
      OWNINGID	Integer	Actual owner of the server, used in the Steam Socket API.
      OWNINGNAME	Integer	Displayed owner of the server, used in the Steam Socket API.
      NUMOPENPUBCONN	Integer	Number of public player slots available.
      P2PADDR	Integer	Address to connect to using the Steam Socket API.
      P2PPORT	Integer	Port number to connect to using the Steam Socket API.
      SESSIONFLAGS	Integer	Unknown??
      ModId_l	Integer	Unknown? When given, always seems to be equal to zero, even if there are mods installed.
      """

      tmp,raw = self._read("string", raw)
      lines = tmp.split(",")

      server_vars = {}
      for l in lines:
        if len(l) < 1:
          continue
        kv = l.split(":")
        server_vars[kv[0]] = kv[1]
      parsed['server_vars'] = server_vars

      if edf & 0x01:
        parsed['game_id'],raw = self._read("long", raw)

      #print("END:")
      #print("\n",raw)
      #Undocumented ending of 0x00 times 4
      return parsed

  @staticmethod
  def _read(datatype,raw):
    """Read raw transmission data
    
    Removes the data read
    
    Args:
      datatype: byte, short, long, float, long long, string
      raw: Raw data
    Returns:
      value, remaining raw data
        
    From Source Doc:
      Name	Description
      byte	8 bit character or unsigned integer
      short	16 bit signed integer
      long	32 bit signed integer
      float	32 bit floating point
      long long	64 bit unsigned integer
      string	variable-length byte field, encoded in UTF-8, terminated by 0x00
      
      https://developer.valvesoftware.com/wiki/Server_queries
      https://docs.python.org/3/library/struct.html
    """
    # try:
    if datatype == 'byte':
      val = struct.unpack("<B", raw[0:1])[0]
      raw = raw[1:]

    elif datatype == 'short':
      val = struct.unpack("<h", raw[0:2])[0]
      raw = raw[2:]
    elif datatype == 'long':
      val = struct.unpack("<i", raw[0:4])[0]
      raw = raw[4:]
    elif datatype == 'float':
      val = struct.unpack("<f", raw[0:4])[0]
      raw = raw[4:]
    elif datatype == 'long long':
      val = struct.unpack("<Q", raw[0:8])[0]
      raw = raw[8:]
    elif datatype == 'string':
      eos = raw.find(0x00)
      val = raw[0:eos].decode('utf-8')
      raw = raw[eos+1:]
    else:
      raise TypeError("Unknown data type: " + datatype)

    return val, raw


class ArkServerStatus(nagiosplugin.Resource):
  def __init__(self, address, port):
    self.address = address
    self.port = port

  def probe(self):
    try:
      q = ArkSourceQuery.query_info(self.address, self.port)
    except ConnectionError as e:
      raise nagiosplugin.CheckError(e)
    except TypeError as e:
      raise nagiosplugin.CheckError(e)

    yield nagiosplugin.Metric('info', (q['name'], q['game_version'], q['map'], q['server_type'], q['platform']))
    yield nagiosplugin.Metric('players', q['players'], min=0, max=q['max_players'])


class ArkServerContext(nagiosplugin.Context):
  def __init__(self, context):
    super(ArkServerContext, self).__init__(context)

  def evaluate(self, metric, resource):
    if metric.value is None:
      return self.result_cls(nagiosplugin.Critical)
    else:
      name, version, game_map, server_type, platform = metric.value
      name = re.search('(.*) - \([v\.0-9]+\)$', name).group(1)

      if server_type is 100:
        server_type = 'dedicated'
      elif server_type is 108:
        server_type = 'non-dedicated'

      if platform is 108:
        platform = 'linux'
      elif platform is 111:
        platform = 'mac'
      elif platform is 119:
        platform = 'windows'

      output = 'server \'{}\' is online\n  version: {}\n  map: {}\n  type: {}\n  platform: {}'.format(name, version, game_map, server_type, platform)
      return self.result_cls(nagiosplugin.Ok, metric=metric, hint=output)


def main():
  argp = argparse.ArgumentParser()
  required = argp.add_argument_group('required named arguments')
  required.add_argument('-a', '--address', help='which server to check', required=True, metavar='IP')
  required.add_argument('-p', '--port', help='server port', required=True, type=int)
  args = argp.parse_args()

  check = nagiosplugin.Check(
    ArkServerStatus(args.address, args.port),
    ArkServerContext('info'),
    nagiosplugin.ScalarContext('players', fmt_metric='{value} players gaming on this server')
  )
  check.main()


if __name__ == '__main__':
  main()
