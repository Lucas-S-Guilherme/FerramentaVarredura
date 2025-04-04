import socket
import threading
from queue import Queue
import time
from datetime import datetime
from colorama import Fore, Style, init

# Inicializa colorama para cores no terminal
init(autoreset=True)

class PortScanner:
    def __init__(self, target, ports, timeout=1.0):
        self.target = target
        self.ports = ports
        self.timeout = float(timeout)
        self.results = []
        self.lock = threading.Lock()
        self.queue = Queue()
        self.start_time = None
        self.scanned_ports = {'TCP': 0, 'UDP': 0}
        self.port_status_counts = {'aberta': 0, 'fechada': 0, 'filtrada': 0, 'erro': 0}
        self.active_sockets = []
        self.should_stop = False


    def tcp_scan(self, port):
        """Realiza varredura TCP com pacotes SYN."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        self.active_sockets.append(sock) 
        try:
            result = sock.connect_ex((self.target, port))
            with self.lock:
                self.scanned_ports['TCP'] += 1
                if result == 0:
                    self.results.append((port, "TCP", "aberta"))
                    self.port_status_counts['aberta'] += 1
                elif result == 111:  # Connection refused
                    self.results.append((port, "TCP", "fechada"))
                    self.port_status_counts['fechada'] += 1
                else:
                    self.results.append((port, "TCP", "filtrada"))
                    self.port_status_counts['filtrada'] += 1
        except socket.error as e:
            with self.lock:
                self.scanned_ports['TCP'] += 1
                self.results.append((port, "TCP", f"erro: {str(e)}"))
                self.port_status_counts['erro'] += 1
        finally:
            sock.close()

    def udp_scan(self, port):
        """Realiza varredura UDP simples."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        self.active_sockets.append(sock)
        try:
            sock.sendto(b"test", (self.target, port))
            sock.recvfrom(1024)  # Se responder, está aberta
            with self.lock:
                self.scanned_ports['UDP'] += 1
                self.results.append((port, "UDP", "aberta"))
                self.port_status_counts['aberta'] += 1
        except socket.timeout:
            with self.lock:
                self.scanned_ports['UDP'] += 1
                self.results.append((port, "UDP", "filtrada ou fechada"))
                self.port_status_counts['filtrada'] += 1
        except ConnectionResetError:
            with self.lock:
                self.scanned_ports['UDP'] += 1
                self.results.append((port, "UDP", "fechada"))
                self.port_status_counts['fechada'] += 1
        except Exception as e:
            with self.lock:
                self.scanned_ports['UDP'] += 1
                self.results.append((port, "UDP", f"erro: {str(e)}"))
                self.port_status_counts['erro'] += 1
        finally:
            sock.close()

    def worker(self):
        """Thread worker para processar portas da fila."""
        while not self.should_stop:
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
        print(f"\n{Fore.CYAN}Iniciando varredura {protocol} em {self.target}...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Portas a serem verificadas: {len(self.ports)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Timeout configurado: {self.timeout}s por porta{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Threads em uso: {min(100, len(self.ports))}{Style.RESET_ALL}\n")
        
        self.start_time = time.time()

        # Preenche a fila com portas e protocolo
        for port in self.ports:
            self.queue.put((port, protocol))

        # Inicia threads
        threads = []
        thread_count = min(100, len(self.ports))
        for _ in range(thread_count):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Exibe progresso
        total_ports = len(self.ports)
        last_update = 0
        while not self.queue.empty():
            scanned = total_ports - self.queue.qsize()
            percentage = (scanned / total_ports) * 100
            
            # Atualiza a cada 0.5s ou quando concluído
            if time.time() - last_update > 0.5 or scanned == total_ports:
                print(f"\r{Fore.MAGENTA}Progresso: {scanned}/{total_ports} portas ({percentage:.1f}%) | "
                      f"Abertas: {self.port_status_counts['aberta']} | "
                      f"Filtradas: {self.port_status_counts['filtrada']} | "
                      f"Fechadas: {self.port_status_counts['fechada']}{Style.RESET_ALL}", end="")
                last_update = time.time()
            time.sleep(0.1)

        # Aguarda término
        for t in threads:
            t.join()

        end_time = time.time()
        print(f"\n{Fore.GREEN}Varredura {protocol} concluída em {end_time - self.start_time:.2f} segundos{Style.RESET_ALL}")

    def display_results(self):
        """Exibe os resultados da varredura com cores."""
        if not self.results:
            print(f"{Fore.RED}Nenhum resultado encontrado.{Style.RESET_ALL}")
            return

        # Ordena resultados: abertas primeiro, depois filtradas, depois outras
        sorted_results = sorted(self.results, key=lambda x: (
            0 if x[2] == "aberta" else 
            1 if "filtrada" in x[2] else 
            2 if x[2] == "fechada" else 3
        ))

        print(f"\n{Fore.CYAN}=== RESULTADOS DETALHADOS ==={Style.RESET_ALL}")
        
        for port, proto, status in sorted_results:
            if status == "aberta":
                color = Fore.GREEN
            elif "filtrada" in status:
                color = Fore.YELLOW
            elif status == "fechada":
                color = Fore.RED
            else:
                color = Fore.WHITE
                
            print(f"Porta {color}{port}/{proto}{Style.RESET_ALL}: {color}{status}{Style.RESET_ALL}")

        # Resumo estatístico
        print(f"\n{Fore.CYAN}=== RESUMO ESTATÍSTICO ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Portas abertas: {self.port_status_counts['aberta']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Portas filtradas: {self.port_status_counts['filtrada']}{Style.RESET_ALL}")
        print(f"{Fore.RED}Portas fechadas: {self.port_status_counts['fechada']}{Style.RESET_ALL}")
        if self.port_status_counts['erro'] > 0:
            print(f"{Fore.WHITE}Erros: {self.port_status_counts['erro']}{Style.RESET_ALL}")
        
        total_scanned = sum(self.scanned_ports.values())
        print(f"\nTotal de portas verificadas: {total_scanned}")
        if 'TCP' in self.scanned_ports:
            print(f"Portas TCP verificadas: {self.scanned_ports['TCP']}")
        if 'UDP' in self.scanned_ports:
            print(f"Portas UDP verificadas: {self.scanned_ports['UDP']}")

    def export_results(self, filename, format="txt"):
        """Exporta os resultados para um arquivo."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename}_{timestamp}.{format}"
        
        with open(filename, "w") as f:
            if format == "txt":
                f.write(f"Varredura em {self.target} - {datetime.now()}\n")
                f.write(f"Tempo total: {time.time() - self.start_time:.2f} segundos\n\n")
                f.write(f"Portas abertas: {self.port_status_counts['aberta']}\n")
                f.write(f"Portas filtradas: {self.port_status_counts['filtrada']}\n")
                f.write(f"Portas fechadas: {self.port_status_counts['fechada']}\n")
                f.write(f"Erros: {self.port_status_counts['erro']}\n\n")
                
                for port, proto, status in sorted(self.results, key=lambda x: x[0]):
                    f.write(f"Porta {port}/{proto}: {status}\n")
            elif format == "csv":
                f.write("Porta,Protocolo,Status\n")
                for port, proto, status in sorted(self.results, key=lambda x: x[0]):
                    f.write(f"{port},{proto},{status}\n")
        
        print(f"\n{Fore.GREEN}Relatório salvo em: {filename}{Style.RESET_ALL}")

    def close_all(self):
        """Fecha todos os sockets abertos"""
        self.should_stop = True
        for sock in self.active_sockets:
            try:
                sock.close()
            except:
                pass
        self.active_sockets = []