# Web Security Scanner

Ferramenta de analise de seguranca para aplicacoes web.
Verificacao de headers HTTP, certificados SSL/TLS, XSS, SQLi e mais.

## Funcionalidades

- Analise de headers de seguranca (CSP, HSTS, X-Frame-Options, etc.)
- Validacao de certificado SSL/TLS
- Deteccao de XSS refletido
- Deteccao de SQL injection (error-based)
- Varredura de portas web (80, 443, 8080, 8443)
- Deteccao de formularios HTML
- Relatorio HTML estilizado
- Saida colorida no terminal

## Instalacao

```
git clone https://github.com/Raphaellopes-dev/web-security-scanner.git
cd web-security-scanner
pip install -r requirements.txt
```

## Como usar

Varredura completa:
```
python main.py scan https://example.com
```

Varredura com relatorio:
```
python main.py scan https://example.com --output report.html
```

Apenas headers:
```
python main.py headers https://example.com
```

## Aviso Etico

Use apenas em sites que voce possui ou tem autorizacao explicita.
Testes de penetracao sem permissao sao ilegais.

---

Feito por Raphael Lopes
