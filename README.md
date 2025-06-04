Implementação de um conjunto de regras de firewall básico, mas poderoso o bastante para:

Bloquear intervalos de IPs reservados (bogons) que nunca deveriam chegar ao servidor.

Permitir somente portas 80 (HTTP) e 443 (HTTPS), fechando tudo o mais na WAN.

Filtrar pacotes TCP suspeitos (XMAS, FIN+SYN, etc.), típicos de fingerprinting e exploits de rede.

Detectar e bloquear port scans usando a funcionalidade PSD (Port Scan Detection) do RouterOS.

Limitar conexões simultâneas por IP para evitar DDoS básicos e tentativas de força bruta.

Controlar ICMP (ping), permitindo apenas alguns pacotes ao mesmo tempo e descartando o restante.

Descartar pacotes TCP SYN em excesso (proteção contra SYN flood).

Bloquear tentativas de gerenciamento remoto via SSH, Telnet ou Winbox pela interface WAN.

Rejeitar tráfego inválido e manter apenas o estado ESTABLISHED/RELATED, garantindo que conexões legítimas continuem funcionando.

“Drop all” no final, garantindo que qualquer tráfego não explicitamente autorizado seja descartado.



Como importar no Mikrotik

Envie o arquivo basic_only.rsc para o Mikrotik (via Winbox, FTP ou WebFig).

Acesse o terminal do Mikrotik e execute:
/import file-name=basic_only.rsc
