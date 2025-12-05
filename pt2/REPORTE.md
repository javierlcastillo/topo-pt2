# Secure Network part b

## Introducción

Este documento describe las mejoras de seguridad implementadas en una topología de red corporativa simulada con Mininet. El objetivo principal fue fortalecer la red contra amenazas internas y externas mediante la configuración de políticas de firewall, la segmentación de redes (DMZ), la implementación de un Sistema de Detección de Intrusos (IDS) y la protección contra ataques de suplantación de identidad.

## Desarrollo

A continuación, se detallan las configuraciones y políticas de seguridad implementadas para cumplir con los requisitos establecidos.

### Restricciones de la DMZ

Se utilizó `iptables` en el router de borde (`rEDG`) para crear un firewall que segmenta y protege los servicios dentro de la Zona Desmilitarizada (DMZ).

*   **Servicios FTP:**
    *   Se configuró un servidor FTP exclusivo para vicepresidentes (`hFTPVP` en `172.16.50.10`). El acceso a este servicio (puerto 21/tcp) se limitó exclusivamente a la red de vicepresidentes (`10.0.1.0/27`).
    *   Un segundo servidor FTP (`hFTPALL` en `172.16.50.11`) se configuró para ser accesible por todos los empleados, permitiendo el tráfico desde todas las redes internas de la oficina (`10.0.0.0/8`) y la oficina remota (`192.168.0.0/23`).

*   **Sistema de Nóminas (Payroll):**
    *   El acceso al sistema de nóminas (`hPAYROLL` en `172.16.50.13`) se restringió de forma crítica. Solo se permite el acceso desde la dirección IP del host del departamento de contabilidad (`10.0.3.10/32`) y del host del vicepresidente de finanzas (`10.0.1.11/32`) al servicio web (puerto 80/tcp).

*   **Acceso General a la DMZ:**
    *   El enrutamiento permite que todas las redes internas alcancen la DMZ, pero las reglas de firewall en `rEDG` actúan como un filtro, aplicando las restricciones mencionadas anteriormente para cada servicio específico.

### Acceso a Internet

El acceso a internet se gestionó en el router de borde (`rEDG`) para asegurar que solo el personal autorizado pudiera navegar por la red externa.

*   Se implementó NAT (Network Address Translation) usando `iptables -t nat -j MASQUERADE` en la interfaz externa de `rEDG`.
*   La regla de NAT se configuró para que solo aplicara a los paquetes cuyo origen (`-s`) fuera la red de vicepresidentes (`10.0.1.0/27`).
*   Adicionalmente, una regla en la cadena `FORWARD` del firewall permite explícitamente el paso de tráfico desde esta red hacia internet, mientras que el tráfico de otras redes es bloqueado por la política por defecto (`DROP`).

### Nuevos Servicios en la DMZ (IDS)

Para monitorizar el tráfico en busca de actividades sospechosas, se implementó un Sistema de Detección de Intrusos (IDS) basado en Suricata.

*   **Configuración:** Se añadió un nodo dedicado (`ids`) para actuar como sensor del IDS.
*   **Captura de Tráfico:** Se utilizó la funcionalidad de port mirroring (`ovs-vsctl`) en los switches `sCEN` (para el tráfico de la DMZ) y `sINT` (para el tráfico interno, incluyendo el de vicepresidentes). Todo el tráfico que pasa por estos switches es copiado y enviado al host `ids`.
*   **Análisis:** Las interfaces del host `ids` se configuraron en modo promiscuo para capturar todo el tráfico reflejado. Suricata se inicia en segundo plano, utilizando el fichero `suricata.yml` para su configuración y `suricata.rules` para las reglas de detección.

### Autenticación de Protocolos de Enrutamiento

Para prevenir la inyección de rutas falsas, se añadió una capa de seguridad a los protocolos de enrutamiento dinámico.

*   **Mecanismo:** Se configuró la autenticación MD5 para el protocolo RIPv2. Esto asegura que los routers solo acepten actualizaciones de enrutamiento de otros routers que compartan la misma clave secreta.
*   **Implementación:** La autenticación se aplicó en el enlace entre `rISP1` y `rISP2` utilizando una función (`applyRIPAuth`) que configura una cadena de claves (`key chain`) en FRR a través de `vtysh`. *(Nota: Esta configuración se encuentra comentada en la versión final del script para facilitar pruebas de conectividad básica).*

### Switches should include configuration for Dynamic ARP Inspection (DAI)

Como medida de protección contra ataques de suplantación de ARP (ARP Spoofing) dentro de la red local, se implementó una versión de Inspección Dinámica de ARP (DAI) en todos los switches.

*   **Mecanismo:** Se utilizaron reglas de OpenFlow (`ovs-ofctl`) para controlar el tráfico ARP en cada switch.
*   **Implementación:**
    1.  Se añade una regla de baja prioridad (`priority=10`) que descarta (`drop`) todos los paquetes ARP por defecto.
    2.  Se añaden reglas de alta prioridad (`priority=100`) que definen una "lista blanca" de combinaciones IP-MAC legítimas. Solo si un paquete ARP coincide con una de estas combinaciones (ej. `nw_src=10.0.1.10, dl_src=00:..:0a`), se procesa normalmente (`actions=normal`).
*   **Efectividad:** Esta configuración previene eficazmente que un atacante envenene la caché ARP de otras máquinas, ya que sus paquetes ARP falsificados no coincidirán con ninguna regla de la lista blanca y serán descartados. Esto se validó con un caso de prueba automatizado que simula un ataque `arpspoof` y verifica que el IDS no detecta ningún paquete malicioso, probando que fue bloqueado a nivel de switch.
