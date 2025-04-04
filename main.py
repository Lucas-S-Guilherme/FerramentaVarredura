import sys
from scanner import PortScanner
from utils import validate_ip, parse_ports

def main():
    if len(sys.argv) < 4:
        print("Uso: python main.py <IP> <portas> <protocolo>")
        print("Exemplo: python main.py 192.168.1.1 20-25,80 TCP")
        print("Para todas as portas: python main.py 192.168.1.1 ALL TCP")
        print("Protocolos: TCP, UDP ou BOTH")
        sys.exit(1)

    target = sys.argv[1]
    port_input = sys.argv[2]
    protocol = sys.argv[3].upper()

    if not validate_ip(target):
        print("IP inválido!")
        sys.exit(1)

    # Verifica se o usuário quer varrer todas as portas
    if port_input.upper() == "ALL":
        ports = list(range(1, 65536))  # Todas as portas de 1 a 65535
    else:
        try:
            ports = parse_ports(port_input)
        except ValueError:
            print("Formato de portas inválido!")
            sys.exit(1)

    scanner = PortScanner(target, ports)

    if protocol == "TCP":
        scanner.scan("TCP")
    elif protocol == "UDP":
        scanner.scan("UDP")
    elif protocol == "BOTH":
        scanner.scan("TCP")
        scanner.open_ports = []  # Reseta para UDP
        scanner.scan("UDP")
    else:
        print("Protocolo inválido! Use TCP, UDP ou BOTH")
        sys.exit(1)

if __name__ == "__main__":
    main()