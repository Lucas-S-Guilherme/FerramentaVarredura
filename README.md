# FerramentaVarredura

Ferramenta de varredura de portas TCP e UDP para sistemas Linux, com suporte opcional a Windows e macOS.

## Funcionalidades 
Varredura TCP (SYN) e UDP.

Exportação de relatórios em TXT ou CSV.

Progresso em tempo real durante a varredura.

Suporte a múltiplas threads (100 por padrão).


## Requisitos
- Python 3.8+
- Ubuntu 24 (testado), compatível com outros sistemas Linux
- Permissões de root para portas privilegiadas (< 1024)

## Instalação
1. Clone o repositório:
   ```bash
   $ git clone https://github.com/<seu_usuario>/FerramentaVarredura.git
   $ cd FerramentaVarredura
   $ chmod +x install.sh
   $ ./install.sh
   ```

## Uso

Argumentos

`<IP>`: Endereço IP alvo (ex.: 192.168.1.1).

`<portas>`: Lista ou intervalo de portas (ex.: 20-25,80) ou "ALL" para todas (1-65535).

`<protocolo>`: TCP, UDP ou BOTH.

`[timeout]` (opcional): Tempo limite por porta em segundos (padrão: 1.0).

`[formato_relatorio]` (opcional): "txt" ou "csv" (padrão: txt).

```bash
python3 main.py <IP> <portas> <protocolo> [timeout] [formato_relatorio]
```

> [!NOTE]
> caso queira mudar o formato padrão do relatório, é obrigatório a passagem do argumento timeout, sem ele haverá o retorno do erro: Timeout inválido! Deve ser um número (ex.: 0.5)

## Exemplos

### Varredura Básica:
  
`sudo python3 main.py 192.168.1.1 20-25,80 TCP`

    Varre as portas 20 a 25 e 80 usando TCP.
    
## Varredura Completa:

```bash
sudo python3 main.py 192.168.1.1 ALL BOTH 0.5 csv
```

Varre todas as portas com timeout de 0.5s e salva em CSV.

## Varredura TCP e UDP:

`python main.py 192.168.1.1 20-25,80 BOTH`

Varre as portas especificadas com TCP e UDP.

## Varredura completa TCP e UDP:

`python main.py 192.168.1.1 ALL BOTH`

    Varre todas as portas (1 a 65535) com ambos os protocolos.

`Protocolos`

    TCP: Varredura com pacotes SYN.
    UDP: Sondagem simples.
    BOTH: Executa TCP e UDP sequencialmente.

Observações

    Execute como root para portas privilegiadas (< 1024):
    bash

    sudo python3 main.py IP FUNÇÃP PROTOCOLO

    Ajuste o timeout no código (scanner.py) se necessário (padrão: 1 segundo).
    Varreduras completas com "ALL" podem ser demoradas (aproximadamente 20-30 minutos para 65.535 portas com 50 threads).
    Para acelerar, aumente o número de threads em scanner.py (padrão: 50) ou reduza o timeout.

Estrutura do Projeto

    main.py: Ponto de entrada e lógica de argumentos.
    scanner.py: Implementação da varredura de portas.
    utils.py: Funções auxiliares (validação de IP e parsing de portas).
    


