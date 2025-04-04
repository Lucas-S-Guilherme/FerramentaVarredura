import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scanner import PortScanner
from utils import validate_ip, parse_ports
import threading
import time
from datetime import datetime

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ferramenta de Varredura de Portas")
        self.root.geometry("800x600")
        
        self.create_widgets()
        self.scanner = None
        self.scan_thread = None
        
    def create_widgets(self):
        # Frame de configuração
        config_frame = ttk.LabelFrame(self.root, text="Configurações", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # IP
        ttk.Label(config_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(config_frame, width=20)
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Portas
        ttk.Label(config_frame, text="Portas (ex: 20-25,80 ou ALL):").grid(row=1, column=0, sticky=tk.W)
        self.ports_entry = ttk.Entry(config_frame, width=20)
        self.ports_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Protocolo
        ttk.Label(config_frame, text="Protocolo:").grid(row=2, column=0, sticky=tk.W)
        self.protocol_var = tk.StringVar(value="TCP")
        ttk.Radiobutton(config_frame, text="TCP", variable=self.protocol_var, value="TCP").grid(row=2, column=1, sticky=tk.W)
        ttk.Radiobutton(config_frame, text="UDP", variable=self.protocol_var, value="UDP").grid(row=2, column=2, sticky=tk.W)
        ttk.Radiobutton(config_frame, text="Ambos", variable=self.protocol_var, value="BOTH").grid(row=2, column=3, sticky=tk.W)
        
        # Timeout
        ttk.Label(config_frame, text="Timeout (s):").grid(row=3, column=0, sticky=tk.W)
        self.timeout_entry = ttk.Entry(config_frame, width=5)
        self.timeout_entry.insert(0, "1.0")
        self.timeout_entry.grid(row=3, column=1, sticky=tk.W, padx=5)
        
        # Formato do relatório
        ttk.Label(config_frame, text="Formato do Relatório:").grid(row=4, column=0, sticky=tk.W)
        self.report_var = tk.StringVar(value="txt")
        ttk.Radiobutton(config_frame, text="TXT", variable=self.report_var, value="txt").grid(row=4, column=1, sticky=tk.W)
        ttk.Radiobutton(config_frame, text="CSV", variable=self.report_var, value="csv").grid(row=4, column=2, sticky=tk.W)
        
        # Botão de varredura
        self.scan_button = ttk.Button(config_frame, text="Iniciar Varredura", command=self.start_scan)
        self.scan_button.grid(row=5, column=0, columnspan=4, pady=10)
        
        # Barra de progresso
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)
        
        # Status
        self.status_var = tk.StringVar(value="Pronto")
        ttk.Label(self.root, textvariable=self.status_var).pack(fill=tk.X, padx=10, pady=5)
        
        # Resultados
        result_frame = ttk.LabelFrame(self.root, text="Resultados", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.tree = ttk.Treeview(result_frame, columns=('Porta', 'Protocolo', 'Status'), show='headings')
        self.tree.heading('Porta', text='Porta')
        self.tree.heading('Protocolo', text='Protocolo')
        self.tree.heading('Status', text='Status')
        self.tree.column('Porta', width=100)
        self.tree.column('Protocolo', width=100)
        self.tree.column('Status', width=200)
        
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Botão de exportação
        self.export_button = ttk.Button(self.root, text="Exportar Resultados", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(pady=5)
    
    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Aviso", "Uma varredura já está em andamento!")
            return
            
        # Obter parâmetros
        target = self.ip_entry.get()
        port_input = self.ports_entry.get()
        protocol = self.protocol_var.get()
        
        try:
            timeout = float(self.timeout_entry.get())
        except ValueError:
            messagebox.showerror("Erro", "Timeout inválido! Deve ser um número.")
            return
            
        if not validate_ip(target):
            messagebox.showerror("Erro", "IP inválido!")
            return
            
        if port_input.upper() == "ALL":
            ports = list(range(1, 65536))
        else:
            try:
                ports = parse_ports(port_input)
            except ValueError:
                messagebox.showerror("Erro", "Formato de portas inválido!")
                return
                
        # Limpar resultados anteriores
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Desabilitar controles durante a varredura
        self.scan_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.DISABLED)
        
        # Criar scanner
        self.scanner = PortScanner(target, ports, timeout)
        
        # Iniciar varredura em thread separada
        self.scan_thread = threading.Thread(target=self.run_scan, args=(protocol,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
        # Iniciar monitoramento do progresso
        self.monitor_progress()
    
    def run_scan(self, protocol):
        try:
            if protocol == "TCP":
                self.scanner.scan("TCP")
            elif protocol == "UDP":
                self.scanner.scan("UDP")
            elif protocol == "BOTH":
                self.scanner.scan("TCP")
                self.scanner.scan("UDP")
                
            # Atualizar interface com resultados
            self.root.after(0, self.update_results)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erro", str(e)))
        finally:
            self.root.after(0, self.scan_complete)
    
    def monitor_progress(self):
        if self.scanner and hasattr(self.scanner, 'queue'):
            total_ports = len(self.scanner.ports)
            scanned = total_ports - self.scanner.queue.qsize()
            
            if total_ports > 0:
                progress = (scanned / total_ports) * 100
                self.progress['value'] = progress
                self.status_var.set(f"Progresso: {scanned}/{total_ports} portas escaneadas ({progress:.1f}%)")
                
            if scanned < total_ports:
                self.root.after(500, self.monitor_progress)
    
    def update_results(self):
        if not self.scanner or not self.scanner.results:
            return
            
        # Ordenar resultados
        sorted_results = sorted(self.scanner.results, key=lambda x: x[0])
        
        # Limpar treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Adicionar novos resultados
        for port, proto, status in sorted_results:
            self.tree.insert('', tk.END, values=(port, proto, status))
    
    def scan_complete(self):
        self.scan_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)
        self.status_var.set("Varredura concluída!")
        
        if self.scanner and self.scanner.results:
            open_ports = [r for r in self.scanner.results if r[2] == "aberta"]
            self.status_var.set(f"Varredura concluída! {len(open_ports)} portas abertas encontradas.")
    
    def export_results(self):
        if not self.scanner or not self.scanner.results:
            messagebox.showwarning("Aviso", "Nenhum resultado para exportar!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{self.report_var.get()}",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")],
            initialfile=f"relatorio_varredura_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                self.scanner.export_results(filename.split('.')[0], self.report_var.get())
                messagebox.showinfo("Sucesso", f"Relatório salvo em:\n{filename}")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao exportar:\n{str(e)}")

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()