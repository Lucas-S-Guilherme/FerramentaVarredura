#!/bin/bash
echo "Instalando dependências para FerramentaVarredura..."
echo "Atualizando repositórios e instalando pacotes básicos..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

echo "Criando ambiente virtual Python..."
python3 -m venv venv
echo "Ativando  ambiente virtual Python..."
source venv/bin/activate

echo "Instalando dependências Python no ambiente virtual..."
pip install -r requirements.txt

echo "Instalando colorama para suporte a cores no terminal..."
pip install colorama

echo -e "\nInstalação concluída com sucesso!"
echo "Para usar a ferramenta, primeiro ative o ambiente virtual:"
echo "  source venv/bin/activate"
echo "Modo linha de comando:"
echo "  python3 main.py <IP> <portas> <protocolo> [timeout]"
echo "Modo interface gráfica:"
echo "  python main.py --gui"
echo "Para sair do ambiente virtual, digite: deactivate"