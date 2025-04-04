import socket  # Importação adicionada

def validate_ip(ip):
    """Valida se o IP é válido"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def parse_ports(port_range):
    """Converte string de portas em lista (ex.: '20-25,80' -> [20,21,22,23,24,25,80])"""
    ports = []
    for part in port_range.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports