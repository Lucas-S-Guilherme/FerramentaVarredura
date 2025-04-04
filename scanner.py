import socket
import threading
from queue import Queue
import time
from datetime import datetime

class PortScanner:
    def __init__(self, target, ports, timeout=1.0):
        self.target = target
        self.ports = ports
        self.timeout = float(timeout)
        self.results = []  # Lista para armazenar todos os resultados
        self.lock = threading.Lock()
        self.queue = Queue()
        self.start_time = None

    def tcp_scan(self, port):
        """Realiza varredura TCP com pacotes SYN."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((self.target, port))
            with self.lock:
                if result == 0:
                    self.results.append((port, "TCP", "aberta"))
                elif result == 111:  # Connection refused
                    self.results.append((port, "TCP", "fechada"))
                else:
                    self.results.append((port, "TCP", "filtrada"))
        except socket.error as e:
            with self.lock:
                self.results.append((port, "TCP", f"erro: {str(e)}"))
        finally:
            sock.close()

    def udp_scan(self, port):
        """Realiza varredura UDP simples."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(b"test", (self.target, port))
            sock.recvfrom(1024)  # Se responder, está aberta
            with self.lock:
                self.results.append((port, "UDP", "aberta"))
        except socket.timeout:
            with self.lock:
                self.results.append((port, "UDP", "filtrada ou fechada"))
        except ConnectionResetError:
            with self.lock:
                self.results.append((port, "UDP", "fechada"))
        finally:
            sock.close()

    def worker(self):
        """Thread worker para processar portas da fila."""
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
        """Inicia a varredura nas portas especificadas."""
        print(f"Iniciando varredura {protocol} em {self.target}...")
        self.start_time = time.time()

        # Preenche a fila com portas e protocolo
        for port in self.ports:
            self.queue.put((port, protocol))

        # Inicia threads
        threads = []
        thread_count = min(100, len(self.ports))  # Aumentado para 100
        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Exibe progresso
        total_ports = len(self.ports)
        while not self.queue.empty():
            scanned = total_ports - self.queue.qsize()
            print(f"\rProgresso: {scanned}/{total_ports} portas escaneadas ({(scanned/total_ports)*100:.1f}%)", end="")
            time.sleep(0.5)

        # Aguarda término
        for t in threads:
            t.join()

        end_time = time.time()
        print(f"\nVarredura {protocol} concluída em {end_time - self.start_time:.2f} segundos")

    def display_results(self):
        """Exibe os resultados da varredura."""
        if self.results:
            print("\nResultados:")
            for port, proto, status in sorted(self.results):
                print(f"Porta {port}/{proto}: {status}")
        else:
            print("\nNenhum resultado encontrado.")

    def export_results(self, filename, format="txt"):
        """Exporta os resultados para um arquivo."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename}_{timestamp}.{format}"
        
        with open(filename, "w") as f:
            if format == "txt":
                f.write(f"Varredura em {self.target} - {datetime.now()}\n")
                f.write(f"Tempo total: {time.time() - self.start_time:.2f} segundos\n\n")
                for port, proto, status in sorted(self.results):
                    f.write(f"Porta {port}/{proto}: {status}\n")
            elif format == "csv":
                f.write("Porta,Protocolo,Status\n")
                for port, proto, status in sorted(self.results):
                    f.write(f"{port},{proto},{status}\n")
        print(f"Relatório salvo em: {filename}")