#!/bin/bash
echo "🐧 Configurando FerramentaVarredura..."
echo "✔ Atualizando pacotes do sistema..."
sudo apt update && sudo apt install -y python3 python3-pip python3-venv python3-tk python3-pil python3-pil.imagetk

echo "🐍 Criando ambiente virtual..."
python3 -m venv .venv && source .venv/bin/activate

echo "📦 Instalando dependências..."
pip install --upgrade pip
pip install -r requirements.txt

# Tenta instalar dependências extras para GUI (opcional)
pip install svgpathtools || echo "⚠ Aviso: Não foi possível instalar svgpathtools (funcionalidades SVG serão limitadas)"

echo -e "\n✅ Tudo pronto! Use:"
echo -e "   source .venv/bin/activate  # Ativar ambiente"
echo -e "   python main.py --help      # Ver opções"
echo -e "   python gui.py              # Interface gráfica"
echo -e "   deactivate                # Sair do ambiente\n"