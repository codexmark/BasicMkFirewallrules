

# LIMPA TODAS AS REGRAS EXISTENTES
/ip firewall filter remove [find]
/ip firewall address-list remove [find]

# BLOQUEIA IPs RESERVADOS (BOGONs)
/ip firewall address-list
add list=bogon address=0.0.0.0/8
add list=bogon address=10.0.0.0/8
add list=bogon address=127.0.0.0/8
add list=bogon address=169.254.0.0/16
add list=bogon address=172.16.0.0/12
add list=bogon address=192.168.0.0/16
add list=bogon address=224.0.0.0/4
add list=bogon address=240.0.0.0/4

/ip firewall filter
add chain=input src-address-list=bogon action=drop comment="Drop Bogon IPs"
add chain=forward src-address-list=bogon action=drop

# PERMITE CONEXÕES ESTABELECIDAS E RELACIONADAS
add chain=input connection-state=established,related action=accept comment="Allow established/related"
add chain=forward connection-state=established,related action=accept

# BLOQUEIA CONEXÕES INVÁLIDAS
add chain=input connection-state=invalid action=drop comment="Drop invalid"
add chain=forward connection-state=invalid action=drop

# BLOQUEIA GERENCIAMENTO REMOTO PELA WAN
add chain=input in-interface=ether1 protocol=tcp dst-port=8291 action=drop comment="Block Winbox"
add chain=input in-interface=ether1 protocol=tcp dst-port=22 action=drop comment="Block SSH"
add chain=input in-interface=ether1 protocol=tcp dst-port=23 action=drop comment="Block Telnet"

# PERMITE HTTP E HTTPS (WEB SERVER)
add chain=input in-interface=ether1 protocol=tcp dst-port=80,443 action=accept comment="Allow HTTP/HTTPS"

# LIMITA CONEXÕES POR IP (Anti DDoS)
add chain=input protocol=tcp dst-port=80,443 connection-limit=30,32 action=drop comment="Drop too many connections from same IP"

# DETECTA E BLOQUEIA PORT SCANNERS
/ip firewall address-list
add list=port_scanners address=0.0.0.0 comment="Placeholder"
/ip firewall filter
add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list \
    address-list=port_scanners address-list-timeout=1d comment="Detect Port Scans"
add chain=input src-address-list=port_scanners action=drop comment="Drop Port Scanners"

# BLOQUEIA PACOTES TCP SUSPEITOS
add chain=input protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg action=drop comment="Drop TCP XMAS"
add chain=input protocol=tcp tcp-flags=fin,syn action=drop comment="Drop FIN+SYN"
add chain=input protocol=tcp tcp-flags=fin,urg,psh action=drop comment="Drop FIN+URG+PSH"
add chain=input protocol=tcp tcp-flags=all action=drop comment="Drop TCP All flags"

# PROTEÇÃO CONTRA SYN FLOOD
add chain=input protocol=tcp tcp-flags=syn connection-limit=30,32 action=drop comment="Drop SYN flood"

# LIMITA ICMP (PING)
add chain=input protocol=icmp icmp-options=8:0 limit=5,10 action=accept comment="Limit PING"
add chain=input protocol=icmp action=drop comment="Drop Excessive ICMP"

# BLOQUEIA TUDO O RESTANTE
add chain=input action=drop comment="Drop all other input"
add chain=forward action=drop comment="Drop all other forward"

