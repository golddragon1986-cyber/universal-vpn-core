"""Bounded local DNS forwarder implementing ordered upstream failover."""
import socketserver
import struct
import threading
import time
import logging
import http.client
import dns_response_cache

from dns_panel import read_settings, bootstrap_servers, exchange, read_name, receive

_STARTED = False
_SLOTS = threading.BoundedSemaphore(24)


def failure(packet):
    try:
        _, end = read_name(packet, 12)
        question = packet[12:end + 4]
        ident, flags = struct.unpack_from('!HH', packet)
        return struct.pack('!6H', ident, 0x8082 | (flags & 0x0110), 1, 0, 0, 0) + question
    except (ValueError, struct.error):
        return b''


def resolve(packet, route=None):
    try:
        if len(packet) < 12 or struct.unpack_from('!H', packet, 4)[0] != 1:
            return failure(packet)
        name, offset = read_name(packet, 12)
        qtype, qclass = struct.unpack_from('!HH', packet, offset)
        if qclass != 1: return failure(packet)
        values = read_settings()
        from local_dns_zones import match
        zone=match(name)
        servers = ([{'name':zone['name'],'address':server,'route':'DIRECT'} for server in zone['servers']]
                   if zone else [r for r in values['servers'] if r['enabled']])
        if zone:route=None
        cache_key = None if zone else (route, packet[2:], repr(values))
        if cache_key is not None:
            cached = dns_response_cache.get(cache_key, packet)
            if cached is not None: return cached
        bootstrap = bootstrap_servers(values)
        deadline = time.monotonic() + 4.0
        for index, row in enumerate(servers):
            remaining = deadline - time.monotonic()
            if remaining <= 0: break
            timeout = min(1.5, remaining / (len(servers) - index))
            try:
                answer = exchange(row['address'], name.lower(), qtype, bootstrap=bootstrap,
                                  routed=route if route else False if row['route'] == 'DIRECT' else row['route'],
                                  raw=True, request=packet, timeout=timeout)
                # Negative answers are final; transient/protocol failures try the next DNS.
                if answer[3] & 15 in (0, 3):
                    if cache_key is not None: dns_response_cache.put(cache_key, answer)
                    return answer
            except (OSError, ValueError, struct.error, http.client.HTTPException) as error:
                logging.debug('DNS upstream %s failed: %s', row['name'], error)
        return failure(packet)
    except (OSError, ValueError, struct.error, KeyError):
        return failure(packet)


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    def verify_request(self, request, client_address):
        return _SLOTS.acquire(blocking=False)
    def process_request_thread(self, request, client_address):
        try: super().process_request_thread(request, client_address)
        finally: _SLOTS.release()


class UDP(BoundedThreads, socketserver.UDPServer):
    allow_reuse_address = True


class TCP(BoundedThreads, socketserver.TCPServer):
    allow_reuse_address = True


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        answer = resolve(packet)
        if answer: sock.sendto(answer, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(6)
        try:
            for _ in range(100):
                size = struct.unpack('!H', receive(self.request, 2))[0]
                if size < 12: return
                answer = resolve(receive(self.request, size))
                if not answer: return
                self.request.sendall(struct.pack('!H', len(answer)) + answer)
        except (OSError, ValueError, struct.error):
            pass


def client_route(address):
    import client_policy, ipaddress
    host=ipaddress.IPv4Address(address)
    for net,row in client_policy.effective(client_policy.read()):
        if host in net:return row.get('route','RULES')
    return 'RULES'


class ClientUDPHandler(UDPHandler):
    def handle(self):
        packet,sock=self.request
        route=client_route(self.client_address[0])
        answer=resolve(packet,route) if route not in {'RULES','BYPASS'} else failure(packet)
        if answer:sock.sendto(answer,self.client_address)


class ClientTCPHandler(TCPHandler):
    def handle(self):
        self.request.settimeout(6)
        route=client_route(self.client_address[0])
        if route in {'RULES','BYPASS'}:return
        try:
            for _ in range(100):
                size=struct.unpack('!H',receive(self.request,2))[0]
                if size<12:return
                answer=resolve(receive(self.request,size),route)
                self.request.sendall(struct.pack('!H',len(answer))+answer)
        except (OSError,ValueError,struct.error):pass


def start():
    global _STARTED
    if _STARTED: return
    from local_dns_zones import start as start_zones
    start_zones()
    udp = UDP(('127.0.0.1', 1054), UDPHandler)
    try: tcp = TCP(('127.0.0.1', 1054), TCPHandler)
    except Exception:
        udp.server_close(); raise
    client_udp=UDP(('0.0.0.0',1055),ClientUDPHandler)
    try:client_tcp=TCP(('0.0.0.0',1055),ClientTCPHandler)
    except Exception:
        client_udp.server_close();udp.server_close();tcp.server_close();raise
    for server in (udp, tcp, client_udp, client_tcp):
        threading.Thread(target=server.serve_forever, name='ordered-dns', daemon=True).start()
    _STARTED = True
