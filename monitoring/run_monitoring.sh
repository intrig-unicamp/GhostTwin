#!/bin/bash

# Uso: ./run_monitoring.sh -rxIntf <interface_recebimento> -txIntf <interface_envio> -file <arquivo_instrucao>

# Parse dos argumentos
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -rxIntf) RX_INTF="$2"; shift ;;
        -txIntf) TX_INTF="$2"; shift ;;
        -file) FILE="$2"; shift ;;
        *) echo "Argumento desconhecido: $1"; exit 1 ;;
    esac
    shift
done

# Verificação dos parâmetros
if [[ -z "$RX_INTF" || -z "$TX_INTF" || -z "$FILE" ]]; then
    echo "Uso: $0 -rxIntf <interface_recebimento> -txIntf <interface_envio> -file <arquivo_instrucao>"
    exit 1
fi

# Função para encerrar processos em caso de Ctrl+C
cleanup() {
    echo -e "\nEncerrando processos..."
    kill $MONITOR_PID 2>/dev/null
    kill $SENDER_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT

# Inicia o script de monitoramento em background
echo "Iniciando monitoramento com interface $RX_INTF..."
python3 showInfo.py --iface "$RX_INTF" &
MONITOR_PID=$!

# Aguarda 3 segundos
sleep 3

# Inicia o script de envio de pacotes em background
echo "Iniciando envio com interface $TX_INTF e arquivo $FILE..."
python3 finalSender.py -i "$TX_INTF" -file "$FILE" &
SENDER_PID=$!

# Espera pelos processos (Ctrl+C acionará cleanup)
wait $MONITOR_PID
wait $SENDER_PID

