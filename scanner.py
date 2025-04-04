import socket
import threading
from queue import Queue
import time

class PortScanner:
    def __init__(self, target, ports, timeout=1):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()

    def tcp_scan(self, port):
        """Realiza varredura TCP com pacotes SYN"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target, port))
            with self.lock:
                if result == 0:
                    self.open_ports.append((port, "TCP", "aberta"))
                elif result == 111:  # Connection refused
                    print(f"Porta {port}/TCP fechada")
                else:
                    print(f"Porta {port}/TCP filtrada")
        except socket.error:
            print(f"Erro ao escanear porta {port}/TCP")
        finally:
            sock.close()

    def udp_scan(self, port):
        """Realiza varredura UDP simples"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(b"test", (self.target, port))
            sock.recvfrom(1024)  # Se responder, está aberta
            with self.lock:
                self.open_ports.append((port, "UDP", "aberta"))
        except socket.timeout:
            print(f"Porta {port}/UDP filtrada ou fechada")  # UDP não diferencia bem
        except ConnectionResetError:
            print(f"Porta {port}/UDP fechada")
        finally:
            sock.close()

    def worker(self):
        """Thread worker para processar portas da fila"""
        while True:
            try:
                port, protocol = self.queue.get_nowait()
                if protocol == "TCP":
                    self.tcp_scan(port)
                elif protocol == "UDP":
                    self.udp_scan(port)
                self.queue.task_done()
            except:
                break

    def scan(self, protocol="TCP"):
        """Inicia a varredura nas portas especificadas"""
        print(f"Iniciando varredura {protocol} em {self.target}...")
        start_time = time.time()

        # Preenche a fila com portas e protocolo
        for port in self.ports:
            self.queue.put((port, protocol))

        # Inicia threads
        threads = []
        for _ in range(min(50, len(self.ports))):  # Limita a 50 threads
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Aguarda término
        for t in threads:
            t.join()

        end_time = time.time()
        print(f"\nVarredura concluída em {end_time - start_time:.2f} segundos")
        self.display_results()

    def display_results(self):
        """Exibe os resultados da varredura"""
        if self.open_ports:
            print("\nPortas abertas encontradas:")
            for port, proto, status in sorted(self.open_ports):
                print(f"Porta {port}/{proto}: {status}")
        else:
            print("\nNenhuma porta aberta encontrada.")