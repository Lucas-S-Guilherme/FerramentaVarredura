import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from scanner import PortScanner
from utils import validate_ip, parse_ports
import threading
import time
from datetime import datetime
import webbrowser
from PIL import Image, ImageTk
import io
import base64
try:
    import svgpathtools
    SVG_SUPPORT = True
except ImportError:
    SVG_SUPPORT = False
    print("Aviso: svgpathtools não está instalado - ícones SVG personalizados não estarão disponíveis")

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Ferramenta Avançada de Varredura de Portas")
        self.root.geometry("1000x700")
        self.style = ttk.Style()
        self.configure_styles()
        
        # Ícone base64 (substitua por seu ícone real ou remova)
        def setup_icon(self):
            """Configura o ícone da janela"""
            try:
                # Tenta usar ícone padrão do Tkinter se svgpathtools não estiver disponível
                if SVG_SUPPORT:
                    # Código original com SVG
                    icon_svg = """..."""
                    icon_img = Image.open(io.BytesIO(base64.b64decode(icon_svg)))
                    self.icon = ImageTk.PhotoImage(icon_img)
                    self.root.iconphoto(True, self.icon)
                else:
                    # Fallback para ícone simples
                    self.root.iconbitmap(default='')  # Remove ícone se não puder carregar
            except Exception as e:
                print(f"Aviso: Não foi possível carregar ícone - {str(e)}")
        
        self.create_widgets()
        self.scanner = None
        self.scan_thread = None
        self.dark_mode = False
        self.setup_menu()

    def configure_styles(self):
        """Configura temas e estilos visuais"""
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 10))
        self.style.configure('TButton', font=('Helvetica', 10), padding=5)
        self.style.configure('TEntry', padding=5)
        self.style.configure('Title.TLabel', font=('Helvetica', 14, 'bold'))
        self.style.configure('Status.TLabel', font=('Helvetica', 10, 'bold'))
        self.style.map('TButton',
                      foreground=[('pressed', 'white'), ('active', 'white')],
                      background=[('pressed', '#0052cc'), ('active', '#0066ff')])

    def setup_icon(self):
        """Configura o ícone da janela (substitua por um ícone real se desejar)"""
        try:
            # Ícone SVG simples codificado em base64 (substitua por seu próprio ícone)
            icon_svg = """
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                <path fill="#4682B4" d="M12,2C6.48,2,2,6.48,2,12s4.48,10,10,10s10-4.48,10-10S17.52,2,12,2z M12,20c-4.41,0-8-3.59-8-8s3.59-8,8-8s8,3.59,8,8S16.41,20,12,20z"/>
                <path fill="#4682B4" d="M12,6c-3.31,0-6,2.69-6,6s2.69,6,6,6s6-2.69,6-6S15.31,6,12,6z M12,16c-2.21,0-4-1.79-4-4s1.79-4,4-4s4,1.79,4,4S14.21,16,12,16z"/>
                <path fill="#4682B4" d="M12,10c-1.1,0-2,0.9-2,2s0.9,2,2,2s2-0.9,2-2S13.1,10,12,10z"/>
            </svg>
            """
            icon_img = Image.open(io.BytesIO(base64.b64decode(icon_svg)))
            self.icon = ImageTk.PhotoImage(icon_img)
            self.root.iconphoto(True, self.icon)
        except:
            pass

    def setup_menu(self):
        """Configura a barra de menus"""
        menubar = tk.Menu(self.root)
        
        # Menu Arquivo
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exportar Resultados", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Sair", command=self.root.quit)
        menubar.add_cascade(label="Arquivo", menu=file_menu)
        
        # Menu Visual
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Alternar Modo Escuro", command=self.toggle_dark_mode)
        menubar.add_cascade(label="Visual", menu=view_menu)
        
        # Menu Ajuda
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentação", command=self.open_docs)
        help_menu.add_command(label="Sobre", command=self.show_about)
        menubar.add_cascade(label="Ajuda", menu=help_menu)
        
        self.root.config(menu=menubar)

    def create_widgets(self):
        """Cria todos os widgets da interface"""
        self.create_header()
        self.create_config_frame()
        self.create_progress_frame()
        self.create_results_frame()
        self.create_status_bar()

    def create_header(self):
        """Cria o cabeçalho da aplicação"""
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=10, pady=(10, 5))
        
        title = ttk.Label(header, text="🔍 Ferramenta Avançada de Varredura de Portas", 
                         style='Title.TLabel')
        title.pack(side=tk.LEFT)
        
        self.version_label = ttk.Label(header, text="v1.0", style='TLabel')
        self.version_label.pack(side=tk.RIGHT)

    def create_config_frame(self):
        """Cria o frame de configuração"""
        config_frame = ttk.LabelFrame(self.root, text="Configurações de Varredura", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Linha 1 - IP e Portas
        ttk.Label(config_frame, text="IP Alvo:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.ip_entry = ttk.Entry(config_frame, width=20)
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Portas (ex: 20-25,80 ou ALL):").grid(row=0, column=2, sticky=tk.W, pady=2)
        self.ports_entry = ttk.Entry(config_frame, width=20)
        self.ports_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Linha 2 - Protocolo
        ttk.Label(config_frame, text="Protocolo:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.protocol_var = tk.StringVar(value="TCP")
        
        protocol_frame = ttk.Frame(config_frame)
        protocol_frame.grid(row=1, column=1, columnspan=3, sticky=tk.W)
        
        ttk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_var, 
                       value="TCP").pack(side=tk.LEFT)
        ttk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_var, 
                       value="UDP").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(protocol_frame, text="Ambos", variable=self.protocol_var, 
                       value="BOTH").pack(side=tk.LEFT)
        
        # Linha 3 - Timeout e Relatório
        ttk.Label(config_frame, text="Timeout (s):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.timeout_entry = ttk.Entry(config_frame, width=5)
        self.timeout_entry.insert(0, "1.0")
        self.timeout_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(config_frame, text="Formato do Relatório:").grid(row=2, column=2, sticky=tk.W, pady=2)
        self.report_var = tk.StringVar(value="txt")
        
        report_frame = ttk.Frame(config_frame)
        report_frame.grid(row=2, column=3, sticky=tk.W)
        
        ttk.Radiobutton(report_frame, text="TXT", variable=self.report_var, 
                       value="txt").pack(side=tk.LEFT)
        ttk.Radiobutton(report_frame, text="CSV", variable=self.report_var, 
                       value="csv").pack(side=tk.LEFT, padx=10)
        
        # Linha 4 - Botões
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=3, column=0, columnspan=4, pady=(10, 0))
        
        self.scan_button = ttk.Button(button_frame, text="Iniciar Varredura", 
                                    command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Parar", 
                                    command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = ttk.Button(button_frame, text="Exportar Resultados", 
                                      command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Preencher com valores de teste (remova em produção)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ports_entry.insert(0, "80,443,22")

    def create_progress_frame(self):
        """Cria o frame de progresso"""
        progress_frame = ttk.LabelFrame(self.root, text="Progresso", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Barra de progresso
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, 
                                      mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Estatísticas
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill=tk.X)
        
        self.stats_vars = {
            'total': tk.StringVar(value="Total: 0"),
            'open': tk.StringVar(value="Abertas: 0"),
            'filtered': tk.StringVar(value="Filtradas: 0"),
            'closed': tk.StringVar(value="Fechadas: 0"),
            'errors': tk.StringVar(value="Erros: 0")
        }
        
        for i, (text, var) in enumerate(self.stats_vars.items()):
            label = ttk.Label(stats_frame, textvariable=var)
            label.grid(row=0, column=i, padx=10, sticky=tk.W)
        
        # Tempo decorrido
        self.time_var = tk.StringVar(value="Tempo: 00:00:00")
        ttk.Label(progress_frame, textvariable=self.time_var, 
                 style='Status.TLabel').pack(pady=(5, 0))

    def create_results_frame(self):
        """Cria o frame de resultados"""
        results_frame = ttk.LabelFrame(self.root, text="Resultados", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview com scrollbars
        self.tree = ttk.Treeview(results_frame, columns=('Porta', 'Protocolo', 'Status'), 
                                show='headings', selectmode='extended')
        
        # Configurar colunas
        self.tree.heading('Porta', text='Porta', anchor=tk.W)
        self.tree.heading('Protocolo', text='Protocolo', anchor=tk.W)
        self.tree.heading('Status', text='Status', anchor=tk.W)
        
        self.tree.column('Porta', width=100, anchor=tk.W)
        self.tree.column('Protocolo', width=100, anchor=tk.W)
        self.tree.column('Status', width=150, anchor=tk.W)
        
        # Scrollbars
        yscroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        
        # Layout
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        yscroll.grid(row=0, column=1, sticky=tk.NS)
        xscroll.grid(row=1, column=0, sticky=tk.EW)
        
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        # Context menu
        self.setup_tree_context_menu()

    def setup_tree_context_menu(self):
        """Configura o menu de contexto para a treeview"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copiar Seleção", command=self.copy_selection)
        self.context_menu.add_command(label="Exportar Seleção", command=self.export_selection)
        
        def show_context_menu(event):
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        
        self.tree.bind("<Button-3>", show_context_menu)

    def create_status_bar(self):
        """Cria a barra de status"""
        self.status_var = tk.StringVar(value="Pronto")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, 
                             relief=tk.SUNKEN, anchor=tk.W, style='Status.TLabel')
        status_bar.pack(fill=tk.X, padx=1, pady=(0, 1))

    def toggle_dark_mode(self):
        """Alterna entre modo claro e escuro"""
        self.dark_mode = not self.dark_mode
        
        if self.dark_mode:
            bg = '#2d2d2d'
            fg = '#ffffff'
            self.style.theme_use('alt')
        else:
            bg = '#f0f0f0'
            fg = '#000000'
            self.style.theme_use('clam')
        
        self.style.configure('.', background=bg, foreground=fg)
        self.root.update()

    def open_docs(self):
        """Abre a documentação no navegador"""
        webbrowser.open("https://github.com/seu_usuario/FerramentaVarredura")

    def show_about(self):
        """Mostra a janela 'Sobre'"""
        about = tk.Toplevel(self.root)
        about.title("Sobre")
        about.geometry("400x300")
        about.resizable(False, False)
        
        ttk.Label(about, text="Ferramenta de Varredura de Portas", 
                 style='Title.TLabel').pack(pady=10)
        
        info = """
        Versão: 1.0
        Desenvolvedor: [Seu Nome]
        
        Uma ferramenta avançada para varredura de portas 
        TCP/UDP em redes locais e remotas.
        
        Desenvolvido em Python com:
        - socket para varredura
        - threading para performance
        - Tkinter para interface
        
        Licença: MIT
        """
        
        ttk.Label(about, text=info, justify=tk.LEFT).pack(pady=10)
        ttk.Button(about, text="Fechar", command=about.destroy).pack(pady=10)

    def copy_selection(self):
        """Copia os itens selecionados para a área de transferência"""
        selected = self.tree.selection()
        if not selected:
            return
            
        text = ""
        for item in selected:
            values = self.tree.item(item, 'values')
            text += f"{values[0]}\t{values[1]}\t{values[2]}\n"
            
        self.root.clipboard_clear()
        self.root.clipboard_append(text.strip())
        self.status_var.set("Seleção copiada para a área de transferência")

    def export_selection(self):
        """Exporta os itens selecionados para um arquivo"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Aviso", "Nenhum item selecionado para exportar!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt")],
            title="Exportar Seleção"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write("Porta,Protocolo,Status\n")
                    for item in selected:
                        values = self.tree.item(item, 'values')
                        f.write(f"{values[0]},{values[1]},{values[2]}\n")
                
                messagebox.showinfo("Sucesso", f"Dados exportados para:\n{filename}")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao exportar:\n{str(e)}")

    def start_scan(self):
        """Inicia a varredura de portas"""
        if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.is_alive():
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
        self.tree.delete(*self.tree.get_children())
        
        # Resetar estatísticas
        for var in self.stats_vars.values():
            var.set(var.get().split(":")[0] + ": 0")
            
        # Configurar interface
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.status_var.set(f"Iniciando varredura {protocol} em {target}...")
        
        # Criar scanner e thread
        self.scanner = PortScanner(target, ports, timeout)
        self.scan_start_time = time.time()
        self.scan_thread = threading.Thread(target=self.run_scan, args=(protocol,))
        self.scan_thread.daemon = True
        
        # Iniciar varredura
        self.scan_thread.start()
        self.update_time_elapsed()
        self.monitor_progress()

    def run_scan(self, protocol):
        """Executa a varredura (em thread separada)"""
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

    def stop_scan(self):
        """Interrompe a varredura em andamento"""
        if self.scanner and hasattr(self.scanner, 'queue'):
            while not self.scanner.queue.empty():
                try:
                    self.scanner.queue.get_nowait()
                    self.scanner.queue.task_done()
                except:
                    break
                    
        self.status_var.set("Varredura interrompida pelo usuário")
        self.scan_complete()

    def scan_complete(self):
        """Finaliza a varredura e atualiza a interface"""
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.NORMAL)
        
        if self.scanner and self.scanner.results:
            open_ports = [r for r in self.scanner.results if r[2] == "aberta"]
            self.status_var.set(f"Varredura concluída! {len(open_ports)} portas abertas encontradas.")
        else:
            self.status_var.set("Varredura concluída! Nenhuma porta aberta encontrada.")

    def monitor_progress(self):
        """Atualiza a barra de progresso e estatísticas"""
        if self.scanner and hasattr(self.scanner, 'queue'):
            total_ports = len(self.scanner.ports)
            scanned = total_ports - self.scanner.queue.qsize()
            
            if total_ports > 0:
                progress = (scanned / total_ports) * 100
                self.progress['value'] = progress
                
                # Atualizar estatísticas
                self.stats_vars['total'].set(f"Total: {scanned}/{total_ports}")
                if hasattr(self.scanner, 'port_status_counts'):
                    counts = self.scanner.port_status_counts
                    self.stats_vars['open'].set(f"Abertas: {counts['aberta']}")
                    self.stats_vars['filtered'].set(f"Filtradas: {counts['filtrada']}")
                    self.stats_vars['closed'].set(f"Fechadas: {counts['fechada']}")
                    self.stats_vars['errors'].set(f"Erros: {counts['erro']}")
                
            if scanned < total_ports and hasattr(self.scanner, 'scan_thread') and self.scanner.scan_thread.is_alive():
                self.root.after(500, self.monitor_progress)
            else:
                self.update_time_elapsed(True)

    def update_time_elapsed(self, final=False):
        """Atualiza o tempo decorrido"""
        if not hasattr(self, 'scan_thread') or not self.scan_thread:
            return
            
        try:
            elapsed = time.time() - self.scan_start_time
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.time_var.set(f"Tempo: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
            
            if not final and self.scan_thread.is_alive():
                self.root.after(1000, lambda: self.update_time_elapsed())
        except Exception as e:
            print(f"Erro ao atualizar tempo: {str(e)}")

    def update_results(self):
        """Atualiza a treeview com os resultados"""
        if not self.scanner or not self.scanner.results:
            return
            
        # Ordenar resultados: abertas primeiro, depois filtradas, depois outras
        sorted_results = sorted(self.scanner.results, key=lambda x: (
            0 if x[2] == "aberta" else 
            1 if "filtrada" in x[2] else 
            2 if x[2] == "fechada" else 3
        ))
        
        # Limpar treeview
        self.tree.delete(*self.tree.get_children())
        
        # Adicionar novos resultados com cores
        for port, proto, status in sorted_results:
            tags = ()
            if status == "aberta":
                tags = ('open',)
            elif "filtrada" in status:
                tags = ('filtered',)
            elif status == "fechada":
                tags = ('closed',)
                
            self.tree.insert('', tk.END, values=(port, proto, status), tags=tags)
        
        # Configurar tags para cores
        self.tree.tag_configure('open', foreground='green')
        self.tree.tag_configure('filtered', foreground='orange')
        self.tree.tag_configure('closed', foreground='red')

    def export_results(self):
        """Exporta os resultados para um arquivo"""
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