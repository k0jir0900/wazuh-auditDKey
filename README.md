# Wazuh AuditDKey

Este script actualiza un archivo de configuración `audit.rules` y genera el archivo de llaves necesarios para ser utilizados en Wazuh.

## Requisitos

- Python 3.x

## Instalación

1. Clonar el repositorio:

    ```bash
    git clone https://github.com/k0jir0900/wazuh-auditDKey.git 
    cd wazuh-auditDKey
    ```

## Uso

### Ejecución del script

1. Para ejecutar el script, usa el siguiente comando desde la línea de comandos:

    ```bash
    python wazuh-auditdkey.py -f audit.rules
    ```

2. Se generaran dos archivos

- `wazuh-audit.rules`: Este archivo contendrá las reglas de auditorias y las llaves modificadas.
- `audit-keys`: Este archivo contendrá las llaves unicas existentes en el archivo `wazuh-audit.rules`, donde se les agregará la descripción necesaria para ser utilizadas en Wazuh.