# FerramentaVarredura

Ferramenta de varredura de portas TCP e UDP para sistemas Linux.

## Requisitos
- Python 3.8+
- Ubuntu 24 (testado)

## Uso
```bash
python main.py <IP> <portas> <protocolo>
```

## Varredura de portas específicas:
  
`python main.py 192.168.1.1 20-25,80 TCP`

    Varre as portas 20 a 25 e 80 usando TCP.
    
## Varredura de todas as portas:

`python main.py 192.168.1.1 ALL TCP`

    Varre todas as portas (1 a 65535) usando TCP.
    
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
    


