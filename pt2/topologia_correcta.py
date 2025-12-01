from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Node
from mininet.node import OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

class MyTopo(Topo):
    def build(self):
        # --- Add Routers ---
        # rREM: Corresponds to "Remote Router" in the image
        rREM = self.addNode('rREM', cls=Router)
        # rISP1, rISP2: Corresponds to "ISP" routers in the image
        rISP1 = self.addNode('rISP1', cls=Router)
        rISP2 = self.addNode('rISP2', cls=Router)
        # rEDG: Corresponds to "Edge Router" in the image
        rEDG = self.addNode('rEDG', cls=Router)
        # rINT: Corresponds to "Inside Router" in the image
        rINT = self.addNode('rINT', cls=Router)

        # --- Add Switches ---
        # sREM: Switch in the "Remote Office"
        sREM = self.addSwitch('sREM', failMode='standalone', dpid='0000000000000001')
        # sCEN: Central switch connecting the DMZ and rEDG/rINT
        sCEN = self.addSwitch('sCEN', failMode='standalone', dpid='0000000000000002')
        # sINT: Internal switch distributing to floors
        sINT = self.addSwitch('sINT', failMode='standalone', dpid='0000000000000003')
        # sVP: Switch for the "Vice Presidents' Floor"
        sVP = self.addSwitch('sVP', failMode='standalone', dpid='0000000000000004')
        # s2ND: Switch for the "2nd Floor"
        s2ND = self.addSwitch('s2ND', failMode='standalone', dpid='0000000000000005')
        # s1ST: Switch for the "1st Floor"
        s1ST = self.addSwitch('s1ST', failMode='standalone', dpid='0000000000000006')

        # --- Add Links ---
        # Link: rREM -> sREM. Interface on rREM: rREM-sREM
        self.addLink(rREM, sREM, intfName1='rREM-sREM')
        # Link: rREM -> rISP1. Interfaces: rREM-rISP1, rISP1-rREM
        self.addLink(rREM, rISP1, intfName1='rREM-rISP1', intfName2='rISP1-rREM')
        # Link: rISP1 -> rISP2. Interfaces: rISP1-rISP2, rISP2-rISP1
        self.addLink(rISP1, rISP2, intfName1='rISP1-rISP2', intfName2='rISP2-rISP1')
        # Link: rISP2 -> rEDG. Interfaces: rISP2-rEDG, rEDG-rISP2
        self.addLink(rISP2, rEDG, intfName1='rISP2-rEDG', intfName2='rEDG-rISP2')
        # Link: rEDG -> sCEN for DMZ. Interface on rEDG: rEDG-sCEN-nDMZ
        self.addLink(rEDG, sCEN, intfName1='rEDG-sCEN-nDMZ')
        # Link: rEDG -> sCEN for routing to rINT. Interface on rEDG: rEDG-sCEN-rINT
        self.addLink(rEDG, sCEN, intfName1='rEDG-sCEN-rINT')
        # Link: rINT -> sCEN. Interface on rINT: rINT-sCEN
        self.addLink(rINT, sCEN, intfName1='rINT-sCEN')
        # Link: rINT -> sINT for VP network. Interface on rINT: rINT-sINT-nVP
        self.addLink(rINT, sINT, intfName1='rINT-sINT-nVP')
        # Link: rINT -> sINT for 2nd floor network. Interface on rINT: rINT-sINT-n2ND
        self.addLink(rINT, sINT, intfName1='rINT-sINT-n2ND')
        # Link: rINT -> sINT for 1st floor network. Interface on rINT: rINT-sINT-n1ST
        self.addLink(rINT, sINT, intfName1='rINT-sINT-n1ST')
        # Link: sINT -> sVP. Interfaces will be auto-named (e.g., sINT-ethX, sVP-ethY)
        self.addLink(sINT, sVP)
        # Link: sINT -> s2ND. Interfaces will be auto-named
        self.addLink(sINT, s2ND)
        # Link: sINT -> s1ST. Interfaces will be auto-named
        self.addLink(sINT, s1ST)

        # --- Add Hosts ---
        # hREM: Host in the "Remote Office"
        hREM = self.addHost('hREM')
        # hVP: Host on the "Vice Presidents' Floor"
        hVP = self.addHost('hVP')
        hFVP = self.addHost('hFVP')
        # h2ND: Host on the "2nd Floor"
        h2ND = self.addHost('h2ND')
        # h1ST: Host on the "1st Floor"
        h1ST = self.addHost('h1ST')
        # DMZ Hosts
        hFTPVP = self.addHost('hFTPVP')
        hFTPALL = self.addHost('hFTPALL')
        hINTRANET = self.addHost('hINTRANET')
        hPAYROLL = self.addHost('hPAYROLL')
        # IDS Host (passive, no IP needed)
        ids = self.addHost('ids')

        # --- Add Host Links ---
        # Link: hREM -> sREM. Interface on hREM: hREM-sREM
        self.addLink(hREM, sREM, intfName1='hREM-sREM')
        # Link: hVP -> sVP. Interface on hVP: hVP-sVP
        self.addLink(hVP, sVP, intfName1='hVP-sVP')
        # Link> hFVP -> sVP. INterface on hFVP: hFVP - sVP
        self.addLink(hFVP, sVP, intfName1='hFVP-sVP')
        # Link: h2ND -> s2ND. Interface on h2ND: h2ND-s2ND
        self.addLink(h2ND, s2ND, intfName1='h2ND-s2ND')
        # Link: h1ST -> s1ST. Interface on h1ST: h1ST-s1ST
        self.addLink(h1ST, s1ST, intfName1='h1ST-s1ST')
        # Link: hFTPVP -> sCEN. Interface on hFTPVP: hFTPVP-sCEN
        self.addLink(hFTPVP, sCEN, intfName1='hFTPVP-sCEN')
        # Link: hFTPALL -> sCEN. Interface on hFTPALL: hFTPALL-sCEN
        self.addLink(hFTPALL, sCEN, intfName1='hFTPALL-sCEN')
        # Link: hINTRANET -> sCEN. Interface on hINTRANET: hINTRANET-sCEN
        self.addLink(hINTRANET, sCEN, intfName1='hINTRANET-sCEN')
        # Link: hPAYROLL -> sCEN. Interface on hPAYROLL: hPAYROLL-sCEN
        self.addLink(hPAYROLL, sCEN, intfName1='hPAYROLL-sCEN')
        # Link: ids -> sCEN. Assign predictable interface names.
        self.addLink(ids, sCEN, intfName1='ids-eth0', intfName2='sCEN-ids-port')
        # Add a second link for the IDS to monitor the internal switch sINT
        self.addLink(ids, sINT, intfName1='ids-eth1', intfName2='sINT-ids-port')

        # hEXTERNAL: Host representing the "Internet"
        hEXTERNAL = self.addHost('hEXTERNAL')
        # Link: hEXTERNAL -> rISP1. Interfaces: hEXTERNAL-sISP1, rISP1-hEXTERNAL
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
                 f'-c "redistribute connected" '
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

    def applyFirewall(self):
        # Flush existing rules and set default policies
        self.cmd('iptables -F')
        self.cmd('iptables -P INPUT DROP')  
        self.cmd('iptables -P FORWARD DROP')
        self.cmd('iptables -P OUTPUT ACCEPT')

        # Allow loopback traffic
        self.cmd('iptables -A INPUT -i lo -j ACCEPT')

        # Allow routing protocol traffic (RIP) to be received
        self.cmd('iptables -A INPUT -p udp --dport 520 -j ACCEPT')

        # Allow established and related connections
        self.cmd('iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')
        self.cmd('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')
        self.cmd('iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT')

    def applyRIPAuth(self, interface, key_id, password, keychain_name='rip_auth'):
        """
        Configures RIPv2 MD5 authentication on a specific interface.
        """
        self.cmd(f'vtysh -c "conf t" -c "key chain {keychain_name}" -c "key {key_id}" -c "key-string {password}" -c "exit" -c "exit"')
        self.cmd(f'vtysh -c "conf t" -c "interface {interface}" -c "ip rip authentication mode md5" -c "ip rip authentication key-chain {keychain_name}" -c "exit" -c "exit"')

    def firewallRules(self, source, destination, port, protocol='tcp'):
        """
        Applies a firewall rule to allow NEW connections for a specific service.
        """
        self.cmd(f'iptables -A FORWARD -s {source} -d {destination} -p {protocol} --dport {port} -m conntrack --ctstate NEW -j ACCEPT')


def setup_switch_mirroring(net, switch_name, mirror_to_port):
    """
    Configures port mirroring on a given switch to a specific port.
    """
    switch = net.get(switch_name)
    mirror_cmd = f'ovs-vsctl -- --id=@p get Port {mirror_to_port} -- --id=@m create Mirror name=mir-{switch_name} select_all=true output_port=@p -- set Bridge {switch_name} mirrors=@m'
    switch.cmd(mirror_cmd)
    print(f'*   Port mirroring configured on {switch_name} to port {mirror_to_port}\n')

def setup_switch_mirroring(switch_node, mirror_to_port):
    """
    Configures port mirroring on a given switch node to a specific port.
    """
    switch_name = switch_node.name
    mirror_cmd = f'ovs-vsctl -- --id=@p get Port {mirror_to_port} -- --id=@m create Mirror name=mir-{switch_name} select_all=true output_port=@p -- set Bridge {switch_name} mirrors=@m'
    switch_node.cmd(mirror_cmd)
    print(f'*   Port mirroring configured on {switch_name} to port {mirror_to_port}\n')

def probando_conexiones(net):
    output_file = 'pruebas.txt'
    print(f'*** Realizando pruebas de conectividad, guardando resultados en {output_file}...\n')
    with open(output_file, 'w') as f:
        f.write('*** Resultados de las pruebas de conectividad ***\n\n')
        
        # Get hosts
        h1ST = net.get('h1ST')
        h2ND = net.get('h2ND')
        hFTPALL = net.get('hFTPALL')
        hFTPVP = net.get('hFTPVP')
        hVP = net.get('hVP')
        hEXTERNAL = net.get('hEXTERNAL')
        hREM = net.get('hREM')
        hPAYROLL = net.get('hPAYROLL')

        # Define ports for services
        FTP_PORT = '21'
        PAYROLL_PORT = '80'

        tests = {
            "h1ST -> h2ND (Ping) (Debe funcionar)": (h1ST, f'ping -c 1 {h2ND.IP()}', 'ping'),
            "h1ST -> hFTPALL (FTP) (Debe funcionar)": (h1ST, f'nc -zv -w 1 {hFTPALL.IP()} {FTP_PORT}', 'nc'),
            "h1ST -> hFTPVP (FTP) (Debe fallar por firewall)": (h1ST, f'nc -zv -w 1 {hFTPVP.IP()} {FTP_PORT}', 'nc'),
            "hVP -> hEXTERNAL (Ping) (Debe funcionar)": (hVP, f'ping -c 1 {hEXTERNAL.IP()}', 'ping'),
            "h2ND -> hEXTERNAL (Ping) (Debe fallar por firewall)": (h2ND, f'ping -c 1 {hEXTERNAL.IP()}', 'ping'),
            "hVP -> hFTPVP (FTP) (Debe funcionar)": (hVP, f'nc -zv -w 1 {hFTPVP.IP()} {FTP_PORT}', 'nc'),
            "h2ND -> hREM (Ping) (Debe funcionar)": (h2ND, f'ping -c 1 {hREM.IP()}', 'ping'),
            "h1ST -> hPAYROLL (HTTP) (Debe funcionar)": (h1ST, f'nc -zv -w 1 {hPAYROLL.IP()} {PAYROLL_PORT}', 'nc'),
            "hREM -> hFTPALL (FTP) (Debe funcionar)": (hREM, f'nc -zv -w 1 {hFTPALL.IP()} {FTP_PORT}', 'nc'),
            "hREM -> hFTPVP (FTP) (Debe fallar por firewall)": (hREM, f'nc -zv -w 1 {hFTPVP.IP()} {FTP_PORT}', 'nc')
        }

        for description, (host, command, cmd_type) in tests.items():
            f.write(f'--- Prueba: {description} ---\n')
            result = host.cmd(command)
            f.write(result)
            f.write('\n') # Add a newline for better formatting
            
            # Check pass/fail based on command type
            if cmd_type == 'ping':
                if '100% packet loss' in result or 'unreachable' in result or '100.0% packet loss' in result:
                    f.write('Resultado: FALLO\n\n')
                else:
                    f.write('Resultado: ÉXITO\n\n')
            elif cmd_type == 'nc':
                if 'succeeded!' in result or 'open' in result:
                    f.write('Resultado: ÉXITO\n\n')
                else:
                    f.write('Resultado: FALLO\n\n')
    
    print(f'*** Pruebas completadas. Revisa el archivo {output_file} para ver los detalles.\n')

def main():
    net = Mininet(topo=MyTopo(),
                  controller=None,
                  switch=OVSSwitch,
                  link=TCLink,
                  autoSetMacs=True,
                  autoStaticArp=False)
    net.start()
    
    # --- Router Configurations ---

    # rREM ("Remote Router") Configuration
    rREM = net.get('rREM')
    # Interface rREM-rISP1 connects to rISP1
    rREM.setIP('190.0.0.1/30', intf='rREM-rISP1')
    # Interface rREM-sREM connects to the remote office switch
    rREM.setIP('192.168.1.1/23', intf='rREM-sREM')
    rREM.applyStaticRoute(destination='0.0.0.0/0', via='190.0.0.2', interface='rREM-rISP1')

    # rISP1 ("ISP" Router) Configuration
    rISP1 = net.get('rISP1')
    # Interface rISP1-rREM connects to rREM
    rISP1.setIP('190.0.0.2/30', intf='rISP1-rREM')
    # Interface rISP1-rISP2 connects to rISP2
    rISP1.setIP('172.16.100.1/30', intf='rISP1-rISP2')
    # Interface rISP1-hEXTERNAL connects to the external "Internet" host
    rISP1.setIP('1.1.1.254/24', intf='rISP1-hEXTERNAL')
    rISP1.applyRoutingRIPv2(networks=['190.0.0.0/30', '172.16.100.0/30', '1.1.1.0/24'])

    # rISP2 ("ISP" Router) Configuration
    rISP2 = net.get('rISP2')
    # Interface rISP2-rISP1 connects to rISP1
    rISP2.setIP('172.16.100.2/30', intf='rISP2-rISP1')
    # Interface rISP2-rEDG connects to rEDG
    rISP2.setIP('190.0.1.2/30', intf='rISP2-rEDG')
    rISP2.applyRoutingRIPv2(networks=['190.0.1.0/30', '172.16.100.0/30'])

    # rEDG ("Edge Router") Configuration
    rEDG = net.get('rEDG')
    # Interface rEDG-rISP2 connects to rISP2 (WAN)
    rEDG.setIP('190.0.1.1/30', intf='rEDG-rISP2')
    # Interface rEDG-sCEN-rINT is the transit link to rINT
    rEDG.setIP('172.16.200.1/30', intf='rEDG-sCEN-rINT')
    # Interface rEDG-sCEN-nDMZ connects to the DMZ network
    rEDG.setIP('172.16.50.254/22', intf='rEDG-sCEN-nDMZ')
    # Static route for internet access
    rEDG.applyStaticRoute(destination='0.0.0.0/0', via='190.0.1.2', interface='rEDG-rISP2')
    # Static route to internal networks (10.0.0.0/8) via rINT
    rEDG.applyStaticRoute(destination='10.0.0.0/8', via='172.16.200.2', interface='rEDG-sCEN-rINT')
    # NAT for internal networks to access the internet
    # Modified: Only VP network (10.0.1.0/27) should have internet access.
    rEDG.applyNAT(outside_interface='rEDG-rISP2', source_network='10.0.1.0/27')

    # GRE Tunnel between rREM and rEDG (simulates part of the VPN)
    rREM.applyGRETunnelConfig(tunnel_name='rREM-rEDG', local_ip='190.0.0.1', remote_ip='190.0.1.1', tunnel_ip='172.16.210.2/30')
    rEDG.applyGRETunnelConfig(tunnel_name='rEDG-rREM', local_ip='190.0.1.1', remote_ip='190.0.0.1', tunnel_ip='172.16.210.1/30')
    # Route traffic for internal networks over the tunnel from rREM
    rREM.applyStaticRoute(destination='10.0.0.0/8', via='172.16.210.1', interface='rREM-rEDG')
    # Route traffic for the remote office over the tunnel from rEDG
    rEDG.applyStaticRoute(destination='192.168.1.0/24', via='172.16.210.1', interface='rEDG-rREM')

    # rINT ("Inside Router") Configuration
    rINT = net.get('rINT')
    # Interface rINT-sCEN is the transit link to rEDG
    rINT.setIP('172.16.200.2/30', intf='rINT-sCEN')
    # Interface rINT-sINT-nVP connects to the Vice Presidents' network
    rINT.setIP('10.0.1.1/27', intf='rINT-sINT-nVP')
    # Interface rINT-sINT-n2ND connects to the 2nd Floor network
    rINT.setIP('10.0.2.1/18', intf='rINT-sINT-n2ND')
    # Interface rINT-sINT-n1ST connects to the 1st Floor network
    rINT.setIP('10.0.3.1/19', intf='rINT-sINT-n1ST')
    # Default route for rINT towards the internet via rEDG
    rINT.applyStaticRoute(destination='0.0.0.0/0', via='172.16.200.1', interface='rINT-sCEN')

    # --- Host Configurations ---

    # hREM ("Remote Office" Host)
    hREM = net.get('hREM')
    hREM.setIP('192.168.1.10/23', intf='hREM-sREM')
    hREM.setDefaultRoute('via 192.168.1.1')

    # hVP ("Vice Presidents' Floor" Host)
    hVP = net.get('hVP')
    hVP.setIP('10.0.1.10/27', intf='hVP-sVP')
    hVP.setDefaultRoute('via 10.0.1.1')

    hFVP = net.get('hFVP')
    hFVP.setIP('10.0.1.11/27', intf='hFVP-sVP')
    hFVP.setDefaultRoute('via 10.0.1.1')

    # h2ND ("2nd Floor" Host)
    h2ND = net.get('h2ND')
    h2ND.setIP('10.0.2.10/18', intf='h2ND-s2ND')
    h2ND.setDefaultRoute('via 10.0.2.1')

    # h1ST ("1st Floor" Host)
    h1ST = net.get('h1ST')
    h1ST.setIP('10.0.3.10/19', intf='h1ST-s1ST')
    h1ST.setDefaultRoute('via 10.0.3.1')

    # --- DMZ Host Configurations ---

    # hFTPVP (FTP server for VPs)
    hFTPVP = net.get('hFTPVP')
    hFTPVP.setIP('172.16.50.10/22', intf='hFTPVP-sCEN')
    hFTPVP.setDefaultRoute('via 172.16.50.254')
    # Start a simple Python FTP server for testing connectivity on port 21
    # Note: pyftpdlib may need to be installed (pip install pyftpdlib)
    hFTPVP.cmd('python3 -m pyftpdlib -p 21 &')

    # hFTPALL (FTP server for all employees)
    hFTPALL = net.get('hFTPALL')
    hFTPALL.setIP('172.16.50.11/22', intf='hFTPALL-sCEN')
    hFTPALL.setDefaultRoute('via 172.16.50.254')
    # Start a simple Python FTP server for testing connectivity on port 21
    # Note: pyftpdlib may need to be installed (pip install pyftpdlib)
    hFTPALL.cmd('python3 -m pyftpdlib -p 21 &')
    hFTPVP.cmd('python3 -m http.server 80 &')

    # hINTRANET (Intranet server)
    hINTRANET = net.get('hINTRANET')
    hINTRANET.setIP('172.16.50.12/22', intf='hINTRANET-sCEN')
    hINTRANET.setDefaultRoute('via 172.16.50.254')
    

    # hPAYROLL (Payroll system server)
    hPAYROLL = net.get('hPAYROLL')
    hPAYROLL.setIP('172.16.50.13/22', intf='hPAYROLL-sCEN')
    hPAYROLL.setDefaultRoute('via 172.16.50.254')
    # Start a simple web server for testing connectivity on port 80
    hPAYROLL.cmd('python3 -m http.server 80 &')
    hFTPVP.cmd('python3 -m http.server 80 &')

    # hEXTERNAL ("Internet" Host)
    hEXTERNAL = net.get('hEXTERNAL')
    hEXTERNAL.setIP('1.1.1.1/24', intf='hEXTERNAL-sISP1')
    hEXTERNAL.setDefaultRoute('via 1.1.1.254')

    # --- FIREWALL CONFIGURATIONS ---
    # Apply the base firewall policies to the routers at the boundaries
    rEDG.applyFirewall()
    rINT.applyFirewall()
    rREM.applyFirewall()

    # --- Specific Firewall Rules on rEDG ---
    
    # Rule for VP FTP server
    rEDG.firewallRules(source='10.0.1.0/27', destination='172.16.50.10', port='21', protocol='tcp')
    # Rule for Vice Presidents' Network
    rEDG.firewallRules(source='10.0.1.0/27', destination='172.16.50.11', port='21', protocol='tcp')
    # Rule for 2nd Floor Network
    rEDG.firewallRules(source='10.0.2.0/18', destination='172.16.50.11', port='21', protocol='tcp')
    # Rule for 1st Floor Network
    rEDG.firewallRules(source='10.0.3.0/19', destination='172.16.50.11', port='21', protocol='tcp')
    # Rule for Remote Office Network (Note: 192.168.1.1/23 is the range 192.168.0.0-192.168.1.255)
    rEDG.firewallRules(source='192.168.0.0/23', destination='172.16.50.11', port='21', protocol='tcp')

    # Requirement: "Restrict that payroll system to be accessible only by the accountancy department... and the finance vice president"
    # We will assume h1ST is the accounting host and hFVP is the finance VP host.
    # We will use port 80/tcp as the service port for the payroll system.
    rEDG.firewallRules(source='10.0.3.10/32', destination='172.16.50.13', port='80', protocol='tcp')
    rEDG.firewallRules(source='10.0.1.11/32', destination='172.16.50.13', port='80', protocol='tcp')

    # Requirement: "Only vice presidents should have access to the internet"
    # Allow FORWARD traffic from the VP network (10.0.1.0/27) to the internet (outbound interface).
    rEDG.cmd('iptables -A FORWARD -s 10.0.1.0/27 -o rEDG-rISP2 -j ACCEPT')

    # Allow FORWARD traffic from the main office LAN (10.0.0.0/8) to the remote office LAN (192.168.0.0/23) via the GRE tunnel.
    rEDG.cmd('iptables -A FORWARD -s 10.0.0.0/8 -d 192.168.0.0/23 -o rEDG-rREM -j ACCEPT')

    # --- Specific Firewall Rules on rINT ---
    # Allow internal networks to communicate with each other.
    rINT.cmd('iptables -A FORWARD -s 10.0.0.0/8 -d 10.0.0.0/8 -j ACCEPT')
    # Allow internal networks to forward traffic towards the edge router.
    rINT.cmd('iptables -A FORWARD -s 10.0.0.0/8 -o rINT-sCEN -j ACCEPT')

    # --- Specific Firewall Rules on rREM ---
    # Allow FORWARD traffic from the remote office LAN to the main office LANs (10.x and DMZ) via the GRE tunnel.
    rREM.cmd('iptables -A FORWARD -s 192.168.0.0/23 -d 10.0.0.0/8 -o rREM-rEDG -j ACCEPT')
    rREM.cmd('iptables -A FORWARD -s 192.168.0.0/23 -d 172.16.0.0/12 -o rREM-rEDG -j ACCEPT')

    # --- RIP MD5 Authentication ---
    # This must be configured on both ends of a link with the same credentials.
    # The only link with RIP running on both sides is rISP1 <-> rISP2.
    print('*** Configuring RIP MD5 authentication...\n')
    # Temporarily commenting out MD5 auth to debug internet connectivity issues.
    # rISP1.applyRIPAuth(interface='rISP1-rISP2', key_id='1', password='a_secure_password')
    # rISP2.applyRIPAuth(interface='rISP2-rISP1', key_id='1', password='a_secure_password')

    # --- IDS Configuration ---
    print('*** Configuring IDS...\n')
    # Get node objects
    ids = net.get('ids')
    sCEN = net.get('sCEN')
    sINT = net.get('sINT')
    
    # 1. Enable promiscuous mode on both IDS interfaces
    print('*   Enabling promiscuous mode on ids-eth0 & ids-eth1\n')
    ids.cmd('ip link set ids-eth0 promisc on')
    ids.cmd('ip link set ids-eth1 promisc on')

    # 2. Configure port mirroring on sCEN and sINT to the IDS ports
    setup_switch_mirroring(sCEN, mirror_to_port='sCEN-ids-port')
    setup_switch_mirroring(sINT, mirror_to_port='sINT-ids-port')

    # 3. Start Suricata IDS
    print('*   Starting Suricata in the background (listening on all interfaces defined in YAML)\n')
    # Suricata will read the suricata.yml file and listen on both ids-eth0 and ids-eth1
    ids.cmd('suricata -c suricata.yml -s suricata.rules &')
    print('*** IDS configuration complete.\n')

    # Run automated connectivity tests
    probando_conexiones(net)

    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
