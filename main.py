import sys
from scanner import PortScanner
from utils import validate_ip, parse_ports

def main():
    if len(sys.argv) < 4:
        print("Uso: python main.py <IP> <portas> <protocolo> [timeout] [formato_relatorio]")
        print("Exemplo: python main.py 192.168.1.1 20-25,80 TCP 0.5 csv")
        print("Para todas as portas: python main.py 192.168.1.1 ALL BOTH")
        sys.exit(1)

    target = sys.argv[1]
    port_input = sys.argv[2]
    protocol = sys.argv[3].upper()

    # Argumentos opcionais com valores padrão
    timeout = 1.0
    report_format = "txt"

    # Verifica argumentos adicionais
    if len(sys.argv) > 4:
        try:
            timeout = float(sys.argv[4])  # Tenta converter o quarto argumento para float
        except ValueError:
            print("Timeout inválido! Deve ser um número (ex.: 0.5)")
            sys.exit(1)

    if len(sys.argv) > 5:
        report_format = sys.argv[5].lower()
        if report_format not in ["txt", "csv"]:
            print("Formato de relatório inválido! Use 'txt' ou 'csv'.")
            sys.exit(1)

    if not validate_ip(target):
        print("IP inválido!")
        sys.exit(1)

    if port_input.upper() == "ALL":
        ports = list(range(1, 65536))
    else:
        try:
            ports = parse_ports(port_input)
        except ValueError:
            print("Formato de portas inválido!")
            sys.exit(1)

    scanner = PortScanner(target, ports, timeout)

    if protocol == "TCP":
        scanner.scan("TCP")
    elif protocol == "UDP":
        scanner.scan("UDP")
    elif protocol == "BOTH":
        scanner.scan("TCP")
        scanner.scan("UDP")
    else:
        print("Protocolo inválido! Use TCP, UDP ou BOTH")
        sys.exit(1)

    scanner.display_results()
    scanner.export_results("relatorio_varredura", report_format)

if __name__ == "__main__":
    main()