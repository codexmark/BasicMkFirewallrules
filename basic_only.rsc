# ==============================================================================
# Arquivo de Regras de Firewall para Mikrotik - Somente Servidor Web (HTTP/HTTPS)
# ------------------------------------------------------------------------------
# Autor:      Mark R. Mesquita
# Codinome:   codexmark
# Email:      mkrayner@windowslive.com
# Data:       03/06/25
#
# Descrição:
# Este script de firewall foi criado para proteger um roteador Mikrotik exposto 
# à internet, com foco em servidores web (portas 80 e 443). Ele cobre as principais 
# ameaças conhecidas como: DDoS, port scan, spoofing, floods e ataques TCP.
# Apenas as portas 80 (HTTP) e 443 (HTTPS) estão liberadas na interface WAN.
# ==============================================================================

# LIMPA TODAS AS REGRAS EXISTENTES
/ip firewall filter remove [find]
/ip firewall address-list remove [find]

# BLOQUEIA INTERVALOS DE IP RESERVADOS (BOGONs)
# Esses endereços não devem aparecer na internet pública
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
add chain=input src-address-list=bogon action=drop comment="Descarta pacotes com IPs reservados (bogons)"
add chain=forward src-address-list=bogon action=drop

# PERMITE CONEXÕES ESTABELECIDAS E RELACIONADAS
# Permite resposta de conexões já iniciadas e conexões auxiliares
add chain=input connection-state=established,related action=accept comment="Permite conexões estabelecidas e relacionadas"
add chain=forward connection-state=established,related action=accept

# BLOQUEIA CONEXÕES INVÁLIDAS
# Conexões com estado inválido são geralmente maliciosas
add chain=input connection-state=invalid action=drop comment="Descarta conexões inválidas"
add chain=forward connection-state=invalid action=drop

# BLOQUEIA GERENCIAMENTO REMOTO NA INTERFACE WAN
# Protege contra tentativas de acesso ao Mikrotik pela internet
add chain=input in-interface=ether1 protocol=tcp dst-port=8291 action=drop comment="Bloqueia Winbox externo"
add chain=input in-interface=ether1 protocol=tcp dst-port=22 action=drop comment="Bloqueia SSH externo"
add chain=input in-interface=ether1 protocol=tcp dst-port=23 action=drop comment="Bloqueia Telnet externo"

# LIMITA CONEXÕES POR IP INDIVIDUAL
# Evita ataques de força bruta ou DDoS simples
add chain=input protocol=tcp dst-port=80,443 connection-limit=30,32 action=drop comment="Limita conexões por IP (/32)"

# DETECTA E BLOQUEIA PORT SCANNERS
# Impede reconhecimento de portas por atacantes
/ip firewall address-list
add list=port_scanners address=0.0.0.0 comment="Reservado para IPs suspeitos"
/ip firewall filter
add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list \
    address-list=port_scanners address-list-timeout=1d comment="Detecta scanner de portas"
add chain=input src-address-list=port_scanners action=drop comment="Bloqueia scanners de portas"

# BLOQUEIA PACOTES TCP COMBINADOS (TIPO XMAS/SCAN)
# Protege contra ataques de fingerprinting e exploits de rede
add chain=input protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg action=drop comment="Bloqueia pacotes XMAS"
add chain=input protocol=tcp tcp-flags=fin,syn action=drop comment="Bloqueia pacotes FIN+SYN"
add chain=input protocol=tcp tcp-flags=fin,urg,psh action=drop comment="Bloqueia FIN+URG+PSH"
add chain=input protocol=tcp tcp-flags=all action=drop comment="Bloqueia pacotes com todas as flags TCP"

# PROTEÇÃO CONTRA ATAQUES SYN FLOOD
add chain=input protocol=tcp tcp-flags=syn connection-limit=30,32 action=drop comment="Bloqueia SYN flood"

# CONTROLE DE ICMP (PING)
# Permite ping moderado, bloqueia excessivo
add chain=input protocol=icmp icmp-options=8:0 limit=5,10 action=accept comment="Permite ping limitado"
add chain=input protocol=icmp action=drop comment="Descarta ICMP excessivo"

# PERMITE APENAS PORTAS HTTP E HTTPS
# Libera acesso web ao servidor
add chain=input in-interface=ether1 protocol=tcp dst-port=80,443 action=accept comment="Permite acesso HTTP/HTTPS"

# BLOQUEIA TODO O RESTO
# Qualquer tráfego que não tenha sido explicitamente permitido será descartado
add chain=input action=drop comment="Descarta todo o resto (INPUT)"
add chain=forward action=drop comment="Descarta todo o resto (FORWARD)"