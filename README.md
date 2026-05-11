
<div align="center">

```
                          _ _   _                   ____
                         | | | (_)                 / ___|___ _ __  ___  ___ _ __  ___
                    __ _ | | |_ _  ___  _ __       | |   / __| '_ \/ __|/ _ \ '_ \/ __|
                   / _` || | __| |/ _ \| '_ \      | |__| (__| | | \__ \  __/ | | \__ \
                  | (_| || | |_| | (_) | | | |      \____\___|_| |_|___/\___|_| |_|___/
                   \__,_|_|\__|_|\___/|_| |_|
```

# 🔒 Web Security Scanner

### Ferramenta CLI de Análise de Segurança Web

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-00ff88?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/licença-MIT-00ff88?style=flat-square)](LICENSE)
[![Feito com ❤️](https://img.shields.io/badge/feito%20com-%E2%9D%A4%EF%B8%8F-00ff88?style=flat-square)]()

</div>

---

**Web Security Scanner** é uma ferramenta profissional de linha de comando para avaliação de segurança em aplicações web. Realiza verificações de cabeçalhos de segurança, certificados SSL/TLS, XSS refletido, indicadores de injeção de SQL, portas abertas e detecção de formulários HTML.

## Funcionalidades

- **Análise de Cabeçalhos de Segurança** — Verifica X-XSS-Protection, Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options e outros.
- **Validação de Certificado SSL/TLS** — Verifica validade do certificado, emissor e datas de expiração.
- **Detecção de XSS Refletido** — Injeta payloads benignos em parâmetros de URL e verifica se aparecem sem sanitização na resposta.
- **Detecção de Injeção de SQL (Baseada em Erro)** — Injeta payloads SQL comuns e procura mensagens de erro de banco de dados na resposta.
- **Varredura de Portas** — Verifica portas web comuns (80, 443, 8080, 8443) no alvo.
- **Detecção de Formulários** — Analisa respostas HTML e lista todos os elementos `<form>` com suas ações, métodos e campos de entrada.
- **Geração de Relatório HTML** — Produz um relatório HTML estilizado com todos os achados organizados por categoria.
- **Saída Colorida no Terminal** — Saída de console clara e codificada por cores usando colorama.

## Instalação

```bash
# Clone ou copie o projeto
cd web-security-scanner

# Instale as dependências
pip install -r requirements.txt
```

Requer Python 3.7+.

## Como usar

### Varredura completa

```bash
python main.py scan https://example.com
```

### Varredura completa com relatório HTML

```bash
python main.py scan https://example.com --output report.html
```

### Verificação apenas de cabeçalhos

```bash
python main.py headers https://example.com
```

### Ajuda

```bash
python main.py --help
```

### Exemplo de saída

```
[•] Escaneando alvo: https://example.com
[•] Verificando cabeçalhos de segurança...
    [✓] X-XSS-Protection: 1; mode=block
    [✗] Content-Security-Policy: AUSENTE
[•] Verificando certificado SSL/TLS...
    [✓] Certificado válido (expira em 2026-06-01)
[•] Testando vulnerabilidades XSS...
    [✓] Nenhum XSS refletido detectado
...
```

## Aviso Ético

**Esta ferramenta é destinada exclusivamente a avaliações de segurança autorizadas.** Você deve ter permissão explícita do proprietário do alvo antes de escanear qualquer aplicação web. Escaneamentos não autorizados podem violar leis de abuso e fraude computacional, regulamentações de privacidade e os termos de serviço do alvo.

Os autores não se responsabilizam por qualquer uso indevido ou danos causados por esta ferramenta. Use com responsabilidade e por sua conta e risco.

## Licença

Distribuído sob a licença MIT. Veja o arquivo [`LICENSE`](LICENSE) para mais informações.
