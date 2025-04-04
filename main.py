import sys
from scanner import PortScanner
from utils import validate_ip, parse_ports

def run_cli():
    """Função para executar o modo linha de comando (CLI)"""
    if len(sys.argv) < 4:
        print("Uso: python main.py <IP> <portas> <protocolo> [timeout] [formato_relatorio]")
        print("   ou python main.py --gui (para interface gráfica)")
        print("Exemplo CLI: python main.py 192.168.1.1 20-25,80 TCP 0.5 csv")
        print("Para todas as portas: python main.py 192.168.1.1 ALL BOTH")
        sys.exit(1)

    # Ignorar o primeiro argumento se for --gui
    args = sys.argv[1:] if sys.argv[1] != "--gui" else sys.argv[2:]
    
    if len(args) < 3:
        print("Argumentos insuficientes para modo CLI!")
        print("Uso: python main.py <IP> <portas> <protocolo> [timeout] [formato_relatorio]")
        sys.exit(1)

    target = args[0]
    port_input = args[1]
    protocol = args[2].upper()

    # Argumentos opcionais com valores padrão
    timeout = 1.0
    report_format = "txt"

    # Verifica argumentos adicionais
    if len(args) > 3:
        try:
            timeout = float(args[3])  # Tenta converter o quarto argumento para float
        except ValueError:
            print("Timeout inválido! Deve ser um número (ex.: 0.5)")
            sys.exit(1)

    if len(args) > 4:
        report_format = args[4].lower()
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

def main():
    """Função principal que decide se executa CLI ou GUI"""
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError as e:
            print("Erro ao carregar interface gráfica:", str(e))
            print("Certifique-se de que todos os arquivos estão presentes.")
            sys.exit(1)
    else:
        run_cli()

if __name__ == "__main__":
    main()