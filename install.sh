#!/bin/bash
echo "Instalando dependências para FerramentaVarredura..."
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt
echo "Instalação concluída! Execute com: sudo python3 main.py <IP> <portas> <protocolo>"