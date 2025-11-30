from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Node
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

class MyTopo(Topo):
    def build(self):
        rREM = self.addNode('rREM', cls=Router)
        rISP1 = self.addNode('rISP1', cls=Router)
        rISP2 = self.addNode('rISP2', cls=Router)
        rEDG = self.addNode('rEDG', cls=Router)
        rINT = self.addNode('rINT', cls=Router)

        sREM = self.addSwitch('sREM', failMode='standalone', dpid='0000000000000001')
        sCEN = self.addSwitch('sCEN', failMode='standalone', dpid='0000000000000002')
        sINT = self.addSwitch('sINT', failMode='standalone', dpid='0000000000000003')
        sVP = self.addSwitch('sVP', failMode='standalone', dpid='0000000000000004')
        s2ND = self.addSwitch('s2ND', failMode='standalone', dpid='0000000000000005')
        s1ST = self.addSwitch('s1ST', failMode='standalone', dpid='0000000000000006')

        self.addLink(rREM, sREM, intfName1='rREM-sREM')
        self.addLink(rREM, rISP1, intfName1='rREM-rISP1', intfName2='rISP1-rREM')
        self.addLink(rISP1, rISP2, intfName1='rISP1-rISP2', intfName2='rISP2-rISP1')
        self.addLink(rISP2, rEDG, intfName1='rISP2-rEDG', intfName2='rEDG-rISP2')
        self.addLink(rEDG, sCEN, intfName1='rEDG-sCEN-nDMZ')
        self.addLink(rEDG, sCEN, intfName1='rEDG-sCEN-rINT')
        self.addLink(rINT, sCEN, intfName1='rINT-sCEN')
        self.addLink(rINT, sINT, intfName1='rINT-sINT-nVP')
        self.addLink(rINT, sINT, intfName1='rINT-sINT-n2ND')
        self.addLink(rINT, sINT, intfName1='rINT-sINT-n1ST')
        self.addLink(sINT, sVP)
        self.addLink(sINT, s2ND)
        self.addLink(sINT, s1ST)

        hREM = self.addHost('hREM')
        hVP = self.addHost('hVP')
        h2ND = self.addHost('h2ND')
        h1ST = self.addHost('h1ST')
        hFTPVP = self.addHost('hFTPVP')
        hFTPALL = self.addHost('hFTPALL')
        hINTRANET = self.addHost('hINTRANET')
        hPAYROLL = self.addHost('hPAYROLL')

        self.addLink(hREM, sREM, intfName1='hREM-sREM')
        self.addLink(hVP, sVP, intfName1='hVP-sVP')
        self.addLink(h2ND, s2ND, intfName1='h2ND-s2ND')
        self.addLink(h1ST, s1ST, intfName1='h1ST-s1ST')
        self.addLink(hFTPVP, sCEN, intfName1='hFTPVP-sCEN')
        self.addLink(hFTPALL, sCEN, intfName1='hFTPALL-sCEN')
        self.addLink(hINTRANET, sCEN, intfName1='hINTRANET-sCEN')
        self.addLink(hPAYROLL, sCEN, intfName1='hPAYROLL-sCEN')

        hEXTERNAL = self.addHost('hEXTERNAL')
        self.addLink(hEXTERNAL, rISP1, intfName1='hEXTERNAL-sISP1', intfName2='rISP1-hEXTERNAL')

class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
        self.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
        self.cmd(f'install -d -m 0777 /tmp/{self.name}')
        self.cmd(f'/usr/lib/frr/mgmtd -d --vty_socket /tmp/{self.name} -i /tmp/{self.name}.mgmtd.pid')
        self.cmd(f'/usr/lib/frr/zebra -d --vty_socket /tmp/{self.name} -i /tmp/{self.name}.zebra.pid')
        self.cmd(f'/usr/lib/frr/ripd -d --vty_socket /tmp/{self.name} -i /tmp/{self.name}.ripd.pid')
        self.cmd(f'/usr/lib/frr/ospfd -d --vty_socket /tmp/{self.name} -i /tmp/{self.name}.ospfd.pid')
        self.cmd(f'chmod 777 /tmp/{self.name}* /tmp/{self.name}*.pid')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        self.cmd(f"pkill -9 -f 'mgmtd|zebra|ripd|ospf'")
        self.cmd(f"pkill -x watchfrr ripd ospfd zebra mgmtd 2>/dev/null || true")
        self.cmd(f"rm -f /tmp/{self.name} /tmp/{self.name}.*.pid")
        super(Router, self).terminate()

    def applyRoutingRIPv2(self, networks, interfaces=None):
        self.cmd(f'vtysh -c "configure terminal" '
                 f'-c "router rip" '
                 f'-c "version 2" '
                 f'-c "end"')
        for network in networks:
            self.cmd(f'vtysh --vty_socket /tmp/{self.name} '
                     f'-c "configure terminal" '
                     f'-c "router rip" '
                     f'-c "network {network}" '
                     f'-c "end"')
    
    def applyGRETunnelConfig(self, tunnel_name, local_ip, remote_ip, tunnel_ip):
        self.cmd(f'ip tunnel add {tunnel_name} mode gre remote {remote_ip} local {local_ip} ttl 255')
        self.cmd(f'ip link set {tunnel_name} up')
        self.cmd(f'ip addr add {tunnel_ip} dev {tunnel_name}')

    def applyNAT(self, outside_interface, source_network):
        self.cmd(f'iptables -t nat -A POSTROUTING -o {outside_interface} -s {source_network} -m iprange --dst-range 0.0.0.0-126.255.255.255 -j MASQUERADE')
    
    def applyStaticRoute(self, destination, via, interface=None):
        if interface:
            self.cmd(f'ip route add {destination} via {via} dev {interface}')
        else:
            self.cmd(f'ip route add {destination} via {via} dev {self.name}')

def main():
    net = Mininet(topo=MyTopo(),
                  controller=None,
                  switch=OVSSwitch,
                  link=TCLink,
                  autoSetMacs=True,
                  autoStaticArp=False)
    net.start()
    
    rREM = net.get('rREM')
    rREM.setIP('190.0.0.1/30', intf='rREM-rISP1')
    rREM.setIP('192.168.1.1/23', intf='rREM-sREM')
    rREM.applyStaticRoute(destination='0.0.0.0/0', via='190.0.0.2', interface='rREM-rISP1')

    rISP1 = net.get('rISP1')
    rISP1.setIP('190.0.0.2/30', intf='rISP1-rREM')
    rISP1.setIP('172.16.100.1/30', intf='rISP1-rISP2')
    rISP1.setIP('1.1.1.254/24', intf='rISP1-hEXTERNAL')
    rISP1.applyRoutingRIPv2(networks=['190.0.0.0/30', '172.16.100.0/30', '1.1.1.0/24'])

    rISP2 = net.get('rISP2')
    rISP2.setIP('172.16.100.2/30', intf='rISP2-rISP1')
    rISP2.setIP('190.0.1.2/30', intf='rISP2-rEDG')
    rISP2.applyRoutingRIPv2(networks=['190.0.1.0/30', '172.16.100.0/30'])

    rEDG = net.get('rEDG')
    rEDG.setIP('190.0.1.1/30', intf='rEDG-rISP2')
    rEDG.setIP('172.16.200.1/30', intf='rEDG-sCEN-rINT')
    rEDG.setIP('172.16.50.254/22', intf='rEDG-sCEN-nDMZ')
    rEDG.applyStaticRoute(destination='0.0.0.0/0', via='190.0.1.2', interface='rEDG-rISP2')
    rEDG.applyStaticRoute(destination='10.0.0.0/8', via='172.16.200.2', interface='rEDG-sCEN-rINT')
    rEDG.applyNAT(outside_interface='rEDG-rISP2', source_network='10.0.0.0/8')

    rREM.applyGRETunnelConfig(tunnel_name='rREM-rEDG', local_ip='190.0.0.1', remote_ip='190.0.1.1', tunnel_ip='172.16.210.2/30')
    rEDG.applyGRETunnelConfig(tunnel_name='rEDG-rREM', local_ip='190.0.1.1', remote_ip='190.0.0.1', tunnel_ip='172.16.210.1/30')
    rREM.applyStaticRoute(destination='10.0.0.0/8', via='172.16.210.1', interface='rREM-rEDG')
    rEDG.applyStaticRoute(destination='192.168.1.0/24', via='172.16.210.1', interface='rEDG-rREM')

    rINT = net.get('rINT')
    rINT.setIP('172.16.200.2/30', intf='rINT-sCEN')
    rINT.setIP('10.0.1.1/27', intf='rINT-sINT-nVP')
    rINT.setIP('10.0.2.1/18', intf='rINT-sINT-n2ND')
    rINT.setIP('10.0.3.1/19', intf='rINT-sINT-n1ST')
    rINT.applyStaticRoute(destination='0.0.0.0/0', via='172.16.200.1', interface='rINT-sCEN')

    hREM = net.get('hREM')
    hREM.setIP('192.168.1.10/23', intf='hREM-sREM')
    hREM.setDefaultRoute('via 192.168.1.1')

    hVP = net.get('hVP')
    hVP.setIP('10.0.1.10/27', intf='hVP-sVP')
    hVP.setDefaultRoute('via 10.0.1.1')

    h2ND = net.get('h2ND')
    h2ND.setIP('10.0.2.10/18', intf='h2ND-s2ND')
    h2ND.setDefaultRoute('via 10.0.2.1')

    h1ST = net.get('h1ST')
    h1ST.setIP('10.0.3.10/19', intf='h1ST-s1ST')
    h1ST.setDefaultRoute('via 10.0.3.1')

    hFTPVP = net.get('hFTPVP')
    hFTPVP.setIP('172.16.50.10/22', intf='hFTPVP-sCEN')
    hFTPVP.setDefaultRoute('via 172.16.50.254')

    hFTPALL = net.get('hFTPALL')
    hFTPALL.setIP('172.16.50.11/22', intf='hFTPALL-sCEN')
    hFTPALL.setDefaultRoute('via 172.16.50.254')

    hINTRANET = net.get('hINTRANET')
    hINTRANET.setIP('172.16.50.12/22', intf='hINTRANET-sCEN')
    hINTRANET.setDefaultRoute('via 172.16.50.254')

    hPAYROLL = net.get('hPAYROLL')
    hPAYROLL.setIP('172.16.50.13/22', intf='hPAYROLL-sCEN')
    hPAYROLL.setDefaultRoute('via 172.16.50.254')

    hEXTERNAL = net.get('hEXTERNAL')
    hEXTERNAL.setIP('1.1.1.1/24', intf='hEXTERNAL-sISP1')
    hEXTERNAL.setDefaultRoute('via 1.1.1.254')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()