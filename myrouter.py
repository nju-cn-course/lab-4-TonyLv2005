#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import os
import switchyard

from switchyard.lib.userlib import *
from switchyard.lib.address import *
from switchyard.lib.packet import *

class Arptable:
    
    def __init__(self):
        self.dict = {}
    
    def add(self, ip , mac):
        self.dict[ip] = mac
    
    def print(self):
        print(" ")
        print("IP    --    MAC" )
        for ip,mac in self.dict.items():
            print(f"{ip} -- {mac}")
    
    def search(self,target_ip):
        result = None
        for ip,mac in self.dict.items():
            if ip == target_ip:
                result = mac
                break
        
        return result


class ForwardingTable:
    def __init__(self):
        self.list_dic = []
    
    def initialize(self, file_path, net):
        #initialize each interface's entry
        for intf in net.interfaces():
            net_netmask = IPv4Address(intf.netmask) #here the mask and ip is string
            net_addr = IPv4Address(int(intf.ipaddr) & int(net_netmask)) #we need the uint32 to bit compare
            #print(net_addr)
            self.add(net_addr,net_netmask,"0.0.0.0",intf.name)

        #open and reading the table (read only)
        if os.path.exists(file_path):
             with open(file_path,"r") as file:
                for line in file:
                    line_list = line.strip().split()
                    self.add(IPv4Address(line_list[0]),IPv4Address(line_list[1]),IPv4Address(line_list[2]),line_list[3])

    def match(self, target_ip):
        #longest prefix match
        result = {}
        length = 0
        for entry in self.list_dic:
            concatenate_addr = IPv4Network(f"{entry['network address']}/{entry['netmask']}")
            #assert target_ip is an object of IPv4Address here
            if(target_ip in concatenate_addr):
                #print(f"ca:{concatenate_addr} ip: {target_ip}")
                if(length < concatenate_addr.prefixlen):
                    length = concatenate_addr.prefixlen #find longest prefix
                    result = entry
                
        return result
            
    
    def print(self):
        print("                     Forwarding Table        ")
        print(" network address  --  netmask  --  next_hop  --  interface_name")
        for entry in self.list_dic:
            print(entry)
    
    def add(self,dest,mask,nxt,intf_name):
        entry = {
            "network address" : dest,
            "netmask" : mask,
            "next_hop" : nxt,
            "interface_name" : intf_name
        }
        self.list_dic.append(entry)

class PacketWaitingForMac:
    def __init__(self, packet, target_ip, interface):
        self.packet = packet
        self.target_ip = target_ip
        self.interface = interface
    
class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arp_table = Arptable() # arp table
        #initialize forwarding table
        self.table_file_path = "forwarding_table.txt"
        self.forward_table = ForwardingTable()
        self.forward_table.initialize(self.table_file_path , self.net)
        #create arp waiting list
        self.waiting_ip = {}
        # other initialization stuff here

        #special drop packet
        self.ip_list = [intf.ipaddr for intf in self.net.interfaces()]
        

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        #get possible header
        arp = packet.get_header(Arp) # if is Arp Frame, it doesn't has ip header
        eth = packet.get_header(Ethernet)
        ip = packet.get_header(IPv4)
        in_intf = self.net.interface_by_name(ifaceName)
        
        mac_target_intf = None
        for intf in self.net.interfaces():
            if intf.ethaddr == eth.dst:
                mac_target_intf = intf
                break

        if(eth.dst != SpecialEthAddr.ETHER_BROADCAST.value and mac_target_intf != in_intf):
            log_info(f"Packet get in wrong interface or has illegal eth.dst , discard")
            return
        
        if eth.ethertype == EtherType.VLAN:
            log_info(f'Get a VLAN packet, discard')
            return


        #if is arp frame
        if arp:
            #initialize
            arp_ip_dest = arp.targetprotoaddr
            arp_ip_src = arp.senderprotoaddr
            arp_eth_src = arp.senderhwaddr
            arp_eth_dest = arp.targethwaddr

            
            to_me = False
            for intf in self.net.interfaces():
                if arp_ip_dest == intf.ipaddr:
                    to_me = True
                    break

            if not to_me:
                log_info(f'get Arp packet not to any interface, discard')
                #return      
            else:
                target_intf = self.net.interface_by_ipaddr(arp_ip_dest)
                # Case 1: get arp request
                if(arp.operation == ArpOperation.Request):
                    #handle arp request
                    self.arp_table.add(arp_ip_src,arp_eth_src)
                    # here must be target_intf but not in_intf, why??
                    arp_reply = create_ip_arp_reply(target_intf.ethaddr,arp_eth_src,target_intf.ipaddr,arp_ip_src)
                    self.net.send_packet(ifaceName,arp_reply)
                # Case 2: get arp reply
                #handle arp reply and our send queue
                else:
                    if arp_eth_src == SpecialEthAddr.ETHER_BROADCAST.value:
                        log_info("get Arp Reply with BroadCast source")
                    else:
                        #update arp table
                        self.arp_table.add(arp_ip_src,arp_eth_src)
            

        #if is ip datagram
        if ip:
            if ip.dst in self.ip_list:
                log_info(f'get ip packet to {self.net.interface_by_ipaddr(ip.dst).name}, discard')
            else:
                entry =  self.forward_table.match(ip.dst)
                #if forward_table doesn't has ,drop it
                if entry:
                    intf_name = entry['interface_name']
                    intf = self.net.interface_by_name(intf_name)
                    intf_net_address = IPv4Address(int(intf.ipaddr) & int(IPv4Address(intf.netmask)))
                    concate_addr = IPv4Network(f"{intf_net_address}/{intf.netmask}")
                    match = ip.dst in concate_addr
                    # Case 1: If directly reachable
                    # eth_dest is host's mac
                    if match:
                        waiting_pkt = PacketWaitingForMac(packet,ip.dst,intf)
                        self.waiting_packet_update(waiting_pkt)
                    # Case 2: Not directly reachable
                    else:
                        next_hop = entry['next_hop']
                        waiting_pkt = PacketWaitingForMac(packet,next_hop,intf)
                        self.waiting_packet_update(waiting_pkt)

        self.forward_queue()

    def waiting_ip_print(self):
        for ip,dic in self.waiting_ip.items():
            print(f"ip: {ip} dic: {dic}")

    def waiting_packet_update(self,pkt):
        has = False
        for ip, info_dic in self.waiting_ip.items():
            if ip == pkt.target_ip:
                has = True
                break
        if not has: #yet has packet(with targeted ip) waiting in the list
            dic = {
                "send_cnt" : 0,
                "last_send_time" : time.time(),
                "packets" : [pkt]
            }
            self.waiting_ip[pkt.target_ip] = dic
        else:
            self.waiting_ip[pkt.target_ip]["packets"].append(pkt)

    def forward_queue(self):
        # address the queue in router's main loop
        delete = []

        for ip,dic in self.waiting_ip.items():
            current_time = time.time()
            mac_result = self.arp_table.search(ip)
            if(mac_result): #find ip's accordance
                for waiting_pkt in dic["packets"]:
                    self.forward_ip_packet(waiting_pkt.packet,mac_result,waiting_pkt.interface)
                delete.append(ip)
            elif dic["send_cnt"] < 5:
                if dic["send_cnt"] == 0 or current_time - dic["last_send_time"] > 1.0:
                    #print(f"{ip} send_cnt {dic['send_cnt']}")
                    #send arp request
                    waiting_pkt = dic["packets"][0] #make sure this exist
                    #initialize arguments
                    w_interface = waiting_pkt.interface
                    name = w_interface.name
                    s_mac_addr = w_interface.ethaddr
                    s_ip_addr = w_interface.ipaddr
                    dst_ip_addr = waiting_pkt.target_ip
                    #send arp request
                    arp_request = create_ip_arp_request(s_mac_addr,s_ip_addr,dst_ip_addr)
                    self.net.send_packet(name,arp_request)
                    #update instance
                    dic['last_send_time'] = current_time
                    dic['send_cnt'] += 1
            elif dic["send_cnt"] == 5 and current_time - dic['last_send_time'] > 1.0:
                
                delete.append(ip)
            
        for ip in delete:
            #print(f"delete {ip}")
            del self.waiting_ip[ip]
        
    def forward_ip_packet(self,packet,eth_dest,interface):
        # modify eth header
        eth_header = packet.get_header(Ethernet)
        eth_header.src = interface.ethaddr
        eth_header.dst = eth_dest
        packet[IPv4].ttl -= 1
        #send
        self.net.send_packet(interface.name,packet)



    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.forward_queue()
                continue
            except Shutdown:
                break
            self.handle_packet(recv)
            

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
