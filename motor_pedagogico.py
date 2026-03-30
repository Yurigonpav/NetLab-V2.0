# motor_pedagogico.py
# Motor pedagógico com Deep Packet Inspection para HTTP, HTTPS, DNS, ARP, TCP, ICMP, etc.
# Exibe explicações em múltiplos níveis (simples, técnico, estruturado, pacote bruto)
# com destaque de segurança, tabelas e dump hexadecimal.

import urllib.parse
import re
from datetime import datetime

# Palavras-chave que identificam campos sensíveis em formulários
CAMPOS_SENSIVEIS = {
    "senha", "password", "pass", "pwd", "secret", "token",
    "auth", "key", "api_key", "apikey", "credential",
    "credit_card", "card_number", "cvv", "cpf", "rg", "pin",
    "ssn", "user", "usuario", "login", "email", "e-mail",
    "username", "nome", "name", "telefone", "phone",
}

# Mapeamento OUI rápido para identificar fabricantes (apenas exemplos comuns)
OUI_VENDORS = {
    "00:14:22": "Dell",
    "00:1A:2B": "Intel",
    "00:1B:63": "Apple",
    "00:1E:C2": "Apple",
    "00:25:00": "Apple",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "Cisco",
    "00:1C:42": "Cisco",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi",
    "00:16:3E": "Xensource",
    "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "Oracle VirtualBox",
    "00:1D:09": "Samsung",
    "70:B3:D5": "TP-Link",
    "94:65:2D": "Intelbras",
    "00:11:22": "Generic",
}

class MotorPedagogico:
    """
    Gera explicações didáticas dinâmicas baseadas nos dados reais
    extraídos de cada pacote capturado.

    Para cada tipo de evento, produz três níveis exibidos:
      nivel1 — explicação simples (linguagem do dia a dia)
      nivel2 — detalhes técnicos do protocolo
      nivel4 — pacote bruto exatamente como trafegou na rede (quando disponível)
    (nivel3 permanece interno para organização dos metadados)
    """

    def __init__(self):
        self._contadores: dict = {}

    #  Interface pública 

    def gerar_explicacao(self, evento: dict) -> dict:
        tipo = evento.get("tipo", "")
        self._contadores[tipo] = self._contadores.get(tipo, 0) + 1

        geradores = {
            "DNS":              self._dns,
            "HTTP":             self._http,
            "HTTPS":            self._https,
            "TCP_SYN":          self._tcp_syn,
            "TCP_FIN":          self._tcp_fin,
            "TCP_RST":          self._tcp_rst,
            "ICMP":             self._icmp,
            "ARP":              self._arp,
            "DHCP":             self._dhcp,
            "SSH":              self._ssh,
            "FTP":              self._ftp,
            "SMB":              self._smb,
            "RDP":              self._rdp,
            "NOVO_DISPOSITIVO": self._novo_dispositivo,
            "HTTP_CREDENTIALS": self._http_credenciais,
            "HTTP_REQUEST":     self._http_request,
        }
        return geradores.get(tipo, self._generico)(evento)

    #  Utilitários internos 

    def _base(self, evento: dict, icone: str, titulo: str, nivel: str,
              n1: str, n2: str, n3: str, n4: str = "",
              fluxo: str = "", alerta: str = "") -> dict:
        tipo = evento.get("tipo", "")
        return {
            "timestamp":        datetime.now().strftime("%H:%M:%S"),
            "tipo":             tipo,
            "icone":            icone,
            "titulo":           titulo,
            "nivel":            nivel,
            "fluxo_visual":     fluxo,
            "nivel1":           n1,
            "nivel2":           n2,
            "nivel3":           n3,
            "nivel4":           n4,
            "alerta_seguranca": alerta,
            "payload_visivel":  "",
            "ip_envolvido":     evento.get("ip_origem", ""),
            "ip_destino":       evento.get("ip_destino", ""),
            "contador":         self._contadores.get(tipo, 1),
        }

    @staticmethod
    def _fluxo(origem: str, protocolo: str, destino: str) -> str:
        return f"{origem}  --[{protocolo}]-->  {destino}"

    @staticmethod
    def _tabela_campos(campos: list) -> str:
        """Gera tabela HTML com os campos reais do pacote."""
        linhas = "".join(
            f"<tr>"
            f"<td style='padding:3px 12px 3px 0;color:#7f8c8d;"
            f"white-space:nowrap;font-size:10px;'>{nome}</td>"
            f"<td style='padding:3px 0;color:#ecf0f1;"
            f"font-family:Consolas;font-size:10px;'>{valor}</td>"
            f"</tr>"
            for nome, valor in campos
            if valor not in (None, "", "None", {})
        )
        if not linhas:
            return "<i style='color:#7f8c8d;'>Campos não disponíveis.</i>"
        return (
            "<table style='border-collapse:collapse;width:100%;'>"
            + linhas + "</table>"
        )

    @staticmethod
    def _eh_sensivel(nome_campo: str) -> bool:
        return any(s in nome_campo.lower() for s in CAMPOS_SENSIVEIS)

    @staticmethod
    def _indicadores_maliciosos(texto: str) -> list:
        suspeitos = [
            r"union\s+select",
            r"or\s+1=1",
            r"sleep\s*\(",
            r"<script",
            r"\.\./",
            r"xp_cmdshell",
            r"load_file\s*\(",
        ]
        encontrados = []
        for pad in suspeitos:
            if re.search(pad, texto or "", flags=re.IGNORECASE):
                encontrados.append(pad)
        return encontrados

    @staticmethod
    def _escape_html(texto: str) -> str:
        return (
            (texto or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    @staticmethod
    def _hexdump_text(texto: str, limite: int = 2048) -> str:
        dados = (texto or "").encode("latin-1", "replace")[:limite]
        linhas = []
        for i in range(0, len(dados), 16):
            chunk = dados[i:i + 16]
            hexes = " ".join(f"{b:02x}" for b in chunk)
            hexes = hexes.ljust(16 * 3 - 1)
            ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            linhas.append(f"{i:04x}  {hexes}  {ascii_}")
        return "\n".join(linhas)

    @staticmethod
    def _headers_inseguros(headers: dict) -> list:
        falta = []
        if not headers:
            return ["Nenhum header HTTP disponível."]
        checks = [
            ("Strict-Transport-Security", "HSTS ausente (HTTPS deveria enviá-lo)"),
            ("Content-Security-Policy",   "CSP ausente — risco de XSS"),
            ("X-Frame-Options",           "X-Frame-Options ausente — clickjacking"),
            ("X-Content-Type-Options",    "X-Content-Type-Options ausente — MIME sniffing"),
            ("Referrer-Policy",           "Referrer-Policy ausente — vazamento de URL"),
        ]
        for chave, msg in checks:
            if chave not in headers:
                falta.append(msg)
        return falta

    @staticmethod
    def _estimar_os(ttl) -> str:
        if ttl is None:
            return ""
        try:
            t = int(ttl)
            if t >= 120:
                return "Windows (TTL padrão 128)"
            if t >= 55:
                return "Linux / macOS (TTL padrão 64)"
            return "Dispositivo embarcado (TTL padrão 32)"
        except Exception:
            return ""

    @staticmethod
    def _obter_fabricante(mac: str) -> str:
        if not mac or len(mac) < 8:
            return ""
        oui = mac[:8].upper()
        return OUI_VENDORS.get(oui, "Fabricante desconhecido")

    #  Gerador HTTP — DPI completo
    def _http(self, e: dict) -> dict:
        origem       = e.get("ip_origem", "?")
        destino      = e.get("ip_destino", "?")
        porta        = e.get("porta_destino") or 80
        porta_origem = e.get("porta_origem", "")
        tamanho      = e.get("tamanho", 0)
        ttl          = e.get("ttl")
        linha_req    = e.get("http_linha_req", "")
        metodo       = e.get("http_metodo", "") or "GET"
        caminho      = e.get("http_caminho", "") or "/"
        versao       = e.get("http_versao", "") or "HTTP/1.1"
        host         = e.get("http_host", "")
        headers      = e.get("http_headers", {}) or {}
        headers_raw  = e.get("http_headers_raw", "") or ""
        corpo        = e.get("http_corpo", "") or ""
        cookie       = e.get("http_cookie", "")
        content_type = e.get("http_content_type", "") or ""
        payload_raw  = e.get("payload_resumo", "") or ""
        metodo_up    = metodo.upper()
        alvo   = host or destino
        titulo = f"HTTP sem criptografia — {metodo} {alvo}{caminho}"
        fluxo  = self._fluxo(origem, "HTTP", f"{alvo}:{porta}")
        query_suspeita = self._indicadores_maliciosos(caminho)
        headers_inseguros = self._headers_inseguros(headers)
        metodos_arriscados = {"TRACE", "OPTIONS", "PUT", "DELETE"}
        metodo_alerta = metodo_up in metodos_arriscados

        # Parsear campos do formulário
        campos_formulario: dict = {}
        if corpo:
            try:
                if "urlencoded" in content_type.lower() or re.search(r'\w+=', corpo):
                    campos_formulario = {
                        k: v[0] if v else ""
                        for k, v in urllib.parse.parse_qs(
                            corpo, keep_blank_values=True
                        ).items()
                    }
            except Exception:
                pass

        campos_sensiveis_encontrados = [
            k for k in campos_formulario if self._eh_sensivel(k)
        ]
        tem_dados_sensiveis = bool(campos_sensiveis_encontrados)

        # NÍVEL 1
        if tem_dados_sensiveis:
            exemplos = " · ".join(
                f"{k} = <b style='color:#E74C3C;'>{campos_formulario[k]}</b>"
                for k in campos_sensiveis_encontrados[:3]
            )
            bloco_dados = (
                f"<br><br>Os dados enviados incluem campos sensíveis "
                f"completamente visíveis na rede:<br>"
                f"<div style='background:#1a0000;border-left:4px solid #E74C3C;"
                f"padding:8px 12px;margin:8px 0;border-radius:4px;"
                f"font-family:Consolas;font-size:11px;color:#ecf0f1;'>"
                f"{exemplos}</div>"
            )
        else:
            bloco_dados = ""

        bloco_injecao = ""
        if query_suspeita:
            blocos = ", ".join(query_suspeita)
            bloco_injecao = (
                f"<br><br><div style='background:#2a0a00;border-left:4px solid #E74C3C;"
                f"padding:8px 12px;margin:8px 0;border-radius:4px;'>"
                f"<b style='color:#E74C3C;'>Possível injeção / payload suspeito:</b> "
                f"{blocos} encontrado na URL ou corpo.</div>"
            )

        bloco_metodo = ""
        if metodo_alerta:
            bloco_metodo = (
                f"<br><div style='background:#2a0a00;border:1px solid #E67E22;"
                f"border-radius:4px;padding:8px 12px;margin-top:8px;'>"
                f"<b style='color:#E67E22;'>Método incomum:</b> {metodo_up}. "
                f"Use apenas quando estritamente necessário e protegido por autenticação.</div>"
            )

        n1 = (
            f"O computador <b>{origem}</b> enviou uma requisição HTTP para "
            f"<b style='color:#E74C3C;'>{alvo}</b>.<br><br>"
            f"HTTP não possui nenhuma criptografia: qualquer pessoa na mesma "
            f"rede Wi-Fi consegue ver exatamente o que foi enviado, como se "
            f"estivesse lendo uma carta sem envelope."
            + bloco_dados +
            bloco_injecao +
            bloco_metodo +
            f"<br><br>Isso demonstra por que o HTTPS é indispensável para "
            f"proteger qualquer informação transmitida pela web."
        )

        # NÍVEL 2
        content_length = headers.get("Content-Length", "")
        user_agent     = headers.get("User-Agent", "")[:70] if headers.get("User-Agent") else ""

        aviso_cookie = (
            f"<br><br><div style='background:#2a1500;border:1px solid #E67E22;"
            f"border-radius:4px;padding:8px 12px;'>"
            f"<b style='color:#E67E22;'>Cookie de sessão detectado!</b><br>"
            f"<span style='color:#ecf0f1;font-size:10px;'>"
            f"Cookies via HTTP permitem sequestrar a conta da vítima sem "
            f"precisar da senha — técnica chamada Session Hijacking.</span></div>"
        ) if cookie else ""

        aviso_injecao = ""
        if query_suspeita:
            aviso_injecao = (
                f"<br><div style='background:#2a0a00;border:1px solid #E74C3C;"
                f"border-radius:4px;padding:8px 12px;margin-top:8px;'>"
                f"<b style='color:#E74C3C;'>Indicador de ataque:</b> "
                f"padrões de injeção detectados ({', '.join(query_suspeita)}). "
                f"Verifique parâmetros e sanitize entradas.</div>"
            )

        aviso_headers = ""
        if headers_inseguros:
            aviso_headers = (
                f"<br><div style='background:#1a2430;border:1px solid #3498DB;"
                f"border-radius:4px;padding:8px 12px;margin-top:8px;'>"
                f"<b style='color:#3498DB;'>Headers de segurança ausentes:</b><br>"
                + "<br>".join(f"• {h}" for h in headers_inseguros)
                + "</div>"
            )

        aviso_metodo = ""
        if metodo_alerta:
            aviso_metodo = (
                f"<br><div style='background:#2a0a00;border:1px solid #E67E22;"
                f"border-radius:4px;padding:6px 10px;margin-top:6px;'>"
                f"<b style='color:#E67E22;'>Método {metodo_up} expõe risco</b> — "
                f"confirme autenticação e autorização.</div>"
            )

        n2 = (
            f"<b>Requisição:</b> <code style='color:#3498DB;'>"
            f"{linha_req or metodo + ' ' + caminho + ' ' + versao}</code>"
            f"<br><b>Destino:</b> {alvo}:{porta} — transmissão em "
            f"<b style='color:#E74C3C;'>texto puro</b>"
            f"<br><b>Tamanho total:</b> {tamanho} bytes"
            + (f"<br><b>Corpo:</b> {content_length} bytes" if content_length else "")
            + (f"<br><b>Navegador:</b> {user_agent}" if user_agent else "")
            + aviso_cookie +
            aviso_injecao +
            aviso_headers +
            aviso_metodo +
            f"<br><br><b>O que qualquer capturador na mesma rede consegue ver:</b>"
            f"<table style='border-collapse:collapse;margin-top:8px;width:100%;'>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>URL completa acessada</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>Todos os headers da requisição</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>Corpo completo: senhas, formulários, dados pessoais</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#E74C3C;'></td>"
            f"<td style='color:#E74C3C;'>Conteúdo completo da resposta do servidor</td></tr>"
            f"<tr><td style='padding:3px 10px;color:#2ECC71;'></td>"
            f"<td style='color:#2ECC71;'>Com HTTPS: tudo isso seria completamente ilegível</td></tr>"
            f"</table>"
        )

        # NÍVEL 3
        meta = [
            ("IP Origem",       origem),
            ("IP Destino",      destino),
            ("Porta origem",    str(porta_origem) if porta_origem else "—"),
            ("Porta destino",   str(porta)),
            ("Protocolo",       "HTTP / TCP"),
            ("Tamanho",         f"{tamanho} bytes"),
            ("TTL",             f"{ttl} — {self._estimar_os(ttl)}" if ttl else "—"),
            ("Timestamp",       datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Criptografado",   " Não — dados em texto puro"),
        ]
        bloco_meta = (
            "<b style='color:#3498DB;font-size:11px;'>1. Metadados do Pacote IP/TCP</b><br>"
            + self._tabela_campos(meta)
        )

        bloco_headers = ""
        if headers:
            linhas_h = "".join(
                f"<tr>"
                f"<td style='padding:4px 14px 4px 0;color:#7f8c8d;"
                f"white-space:nowrap;font-size:10px;'>{k}</td>"
                f"<td style='padding:4px 0;color:#ecf0f1;"
                f"font-family:Consolas;font-size:10px;"
                f"word-break:break-all;'>{v}</td>"
                f"</tr>"
                for k, v in headers.items()
            )
            bloco_headers = (
                f"<br><b style='color:#3498DB;font-size:11px;'>"
                f"2. Headers HTTP Capturados</b>"
                f"<br><span style='color:#7f8c8d;font-size:10px;'>"
                f"Todos os cabeçalhos transmitidos em texto puro:</span>"
                f"<div style='background:#0a0f1a;border:1px solid #1e2d40;"
                f"border-radius:4px;padding:10px;margin-top:6px;'>"
                f"<table style='border-collapse:collapse;width:100%;'>"
                f"{linhas_h}</table></div>"
            )
        elif headers_raw:
            bloco_headers = (
                f"<br><b style='color:#3498DB;font-size:11px;'>"
                f"2. Headers HTTP Capturados</b><br>"
                f"<code style='font-size:10px;color:#ecf0f1;"
                f"white-space:pre-wrap;'>{headers_raw}</code>"
            )

        bloco_corpo = ""
        if campos_formulario:
            linhas_form = []
            for campo, valor in campos_formulario.items():
                eh_s    = self._eh_sensivel(campo)
                cor_c   = "#F39C12" if eh_s else "#3498DB"
                cor_v   = "#E74C3C" if eh_s else "#2ECC71"
                badge   = (
                    " <span style='background:#5a0000;color:#ff6b6b;"
                    "font-size:9px;padding:1px 6px;border-radius:3px;"
                    "font-weight:bold;'>SENSÍVEL</span>"
                ) if eh_s else ""
                icone_c = "" if eh_s else ""

                linhas_form.append(
                    f"<tr>"
                    f"<td style='padding:6px 16px 6px 4px;white-space:nowrap;"
                    f"font-size:11px;'>{icone_c} "
                    f"<span style='color:{cor_c};font-family:Consolas;'>"
                    f"{campo}</span>{badge}</td>"
                    f"<td style='padding:6px 0;font-family:Consolas;"
                    f"font-size:12px;font-weight:bold;color:{cor_v};'>"
                    f"{valor}</td>"
                    f"</tr>"
                )

            bloco_corpo = (
                f"<br><b style='color:#E74C3C;font-size:11px;'>"
                f"3. Campos do Formulário Capturados em Texto Puro</b>"
                f"<div style='background:#1a0a00;border:1px solid #E74C3C;"
                f"border-radius:6px;padding:12px 16px;margin-top:8px;'>"
                f"<table style='border-collapse:collapse;width:100%;'>"
                + "".join(linhas_form) +
                f"</table>"
                f"<br><span style='color:#7f8c8d;font-size:10px;'>"
                f"Estes dados foram transmitidos sem qualquer proteção. "
                f"Qualquer dispositivo na mesma rede Wi-Fi teria acesso "
                f"imediato a estas informações ao executar uma captura "
                f"de pacotes como a realizada por este software.</span>"
                f"</div>"
            )
        elif corpo:
            preview = corpo[:400].replace("<", "&lt;").replace(">", "&gt;")
            bloco_corpo = (
                f"<br><b style='color:#E74C3C;font-size:11px;'>"
                f"3. Corpo da Requisição</b><br>"
                f"<div style='background:#0a0f1a;border:1px solid #E74C3C;"
                f"border-radius:4px;padding:10px;margin-top:6px;'>"
                f"<code style='font-size:10px;color:#ecf0f1;"
                f"white-space:pre-wrap;'>{preview}</code></div>"
            )

        n3 = bloco_meta + bloco_headers + bloco_corpo

        # NÍVEL 4
        if payload_raw:
            if linha_req and headers:
                pacote_reconstruido = linha_req + "\r\n"
                for k, v in headers.items():
                    pacote_reconstruido += f"{k}: {v}\r\n"
                pacote_reconstruido += "\r\n"
                if corpo:
                    pacote_reconstruido += corpo
                conteudo_bruto = pacote_reconstruido
            else:
                conteudo_bruto = payload_raw

            metodo_cor   = "#E74C3C" if metodo_alerta else "#2ECC71"
            req_line = (
                f"<span style='color:{metodo_cor};font-weight:bold'>"
                f"{self._escape_html(metodo_up)}</span> "
                f"{self._escape_html(caminho)} "
                f"<span style='color:#7f8c8d'>{self._escape_html(versao)}</span>"
            )

            headers_destacados = []
            for k, v in headers.items():
                k_lower = k.lower()
                cor_val = "#ecf0f1"
                if k_lower.startswith("authorization") or k_lower == "cookie":
                    cor_val = "#E67E22"
                headers_destacados.append(
                    f"<div><span style='color:#9b59b6'>{self._escape_html(k)}</span>: "
                    f"<span style='color:{cor_val}'>{self._escape_html(str(v))}</span></div>"
                )
            bloco_headers_bruto = "".join(headers_destacados) or (
                "<i style='color:#7f8c8d;'>Sem headers.</i>"
            )

            corpo_preview = (
                f"<pre style='white-space:pre-wrap;margin:6px 0 0 0;"
                f"color:#ecf0f1;font-size:10px;'>{self._escape_html(corpo[:800])}</pre>"
                if corpo else "<i style='color:#7f8c8d;'>Corpo vazio.</i>"
            )

            alertas_brutos = []
            if tem_dados_sensiveis:
                alertas_brutos.append(
                    "Campos sensíveis visíveis (ex.: senha, token, user)."
                )
            if query_suspeita:
                alertas_brutos.append(
                    f"Possível injeção/payload suspeito: {', '.join(query_suspeita)}."
                )
            if metodo_alerta:
                alertas_brutos.append(f"Método incomum: {metodo_up}.")
            if headers_inseguros:
                alertas_brutos.append(
                    "Headers de segurança ausentes: "
                    + ", ".join(headers_inseguros[:4])
                )
            if cookie:
                alertas_brutos.append("Cookie de sessão enviado em HTTP em texto puro.")
            if not alertas_brutos:
                alertas_brutos.append("Nenhum risco crítico detectado neste pacote.")

            hexdump = self._hexdump_text(conteudo_bruto, limite=2048)

            n4 = (
                f"<div style='font-family:Consolas;font-size:10px;line-height:1.6;'>"
                f"<div style='background:#0a0505;border:1px solid #E74C3C;"
                f"border-radius:6px;padding:12px 14px;margin-bottom:10px;'>"
                f"<b style='color:#E74C3C;font-size:11px;'>Visão rápida do pacote HTTP</b><br>"
                f"<div style='margin:6px 0 10px 0;color:#ecf0f1;'>{req_line}</div>"
                f"<div style='color:#bdc3c7;font-size:10px;'>Headers</div>"
                f"{bloco_headers_bruto}"
                f"<div style='color:#bdc3c7;font-size:10px;margin-top:8px;'>Corpo (preview)</div>"
                f"{corpo_preview}"
                f"</div>"
                f"<div style='background:#0d1a2a;border:1px solid #1e3a5f;"
                f"border-radius:6px;padding:12px 14px;margin-bottom:10px;'>"
                f"<b style='color:#3498DB;font-size:11px;'>Riscos detectados</b>"
                f"<ul style='margin:6px 0 0 16px;color:#ecf0f1;font-family:Arial;'>"
                f"{''.join(f'<li>{self._escape_html(a)}</li>' for a in alertas_brutos)}</ul>"
                f"</div>"
                f"<div style='background:#000;border:1px solid #222;"
                f"border-radius:6px;padding:12px 14px;'>"
                f"<b style='color:#2ECC71;font-size:11px;'>Dump hexadecimal + ASCII "
                f"(primeiros 2048 bytes)</b><br><br>"
                f"<pre style='color:#ecf0f1;white-space:pre;font-size:10px;"
                f"margin:0;'>{self._escape_html(hexdump)}</pre>"
                f"</div>"
                f"</div>"
            )
        else:
            n4 = (
                "<i style='color:#7f8c8d;'>"
                "Payload bruto não disponível para este pacote.</i>"
            )

        if campos_sensiveis_encontrados:
            alerta = (
                f"Credenciais capturadas em texto puro: "
                f"{', '.join(campos_sensiveis_encontrados)}. "
                f"Este ataque é trivial em qualquer rede Wi-Fi não protegida."
            )
        elif corpo:
            alerta = (
                "Dados de formulário transmitidos sem criptografia via HTTP. "
                "Todo o conteúdo é visível para qualquer capturador na rede."
            )
        elif cookie:
            alerta = (
                "Cookie de sessão exposto. Permite sequestrar a conta "
                "sem precisar da senha (Session Hijacking)."
            )
        else:
            alerta = (
                "Tráfego HTTP sem criptografia. "
                "Todo o conteúdo é visível para qualquer capturador na rede."
            )

        return self._base(
            e, "", titulo, "AVISO",
            n1, n2, n3, n4, fluxo, alerta
        )

    #  Gerador HTTP_CREDENTIALS (vulnerabilidade crítica)
    def _http_credenciais(self, e: dict) -> dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        creds = e.get("credenciais", [])
        payload = e.get("payload_resumo", "") or e.get("http_corpo", "")

        linhas_creds = "\n".join([f"  • {k} = {v}" for k, v in creds])
        n1 = (
            f"🚨 **VULNERABILIDADE CRÍTICA** – Credenciais enviadas em texto puro!\n\n"
            f"O dispositivo **{origem}** enviou dados de login/senha para **{destino}** "
            f"usando HTTP (sem criptografia).\n\n"
            f"Qualquer pessoa na mesma rede Wi-Fi pode capturar estas informações:\n"
            f"{linhas_creds}\n\n"
            f"Isso permite sequestro de conta, acesso não autorizado e roubo de identidade."
        )
        n2 = (
            f"Requisição HTTP contendo parâmetros sensíveis.\n"
            f"Origem: {origem} → Destino: {destino}\n"
            f"Payload capturado (primeiros 500 caracteres):\n```\n{payload[:500]}\n```\n\n"
            f"❌ O uso de HTTP para envio de credenciais é uma falha grave de segurança. "
            f"A solução é usar HTTPS (TLS), que cifra toda a comunicação."
        )
        n3 = f"Detalhes técnicos:\n- Credenciais: {creds}\n- Payload bruto: {payload[:200]}"
        alerta = f"Credenciais expostas: {', '.join([f'{k}={v}' for k,v in creds])}. Risco imediato de invasão."
        return self._base(e, "🚨", "Credenciais em texto puro (HTTP)", "CRÍTICO",
                          n1, n2, n3, "", f"{origem} --[HTTP]--> {destino}", alerta)

    #  Gerador HTTP_REQUEST (requisição comum)
    def _http_request(self, e: dict) -> dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        metodo = e.get("http_metodo", "GET")
        payload = e.get("payload_resumo", "") or e.get("http_corpo", "")
        n1 = f"🌐 Requisição HTTP {metodo} de **{origem}** para **{destino}** (navegação web sem proteção)."
        n2 = f"O dispositivo acessou um site via HTTP. Todo o conteúdo da requisição é visível na rede.\nPayload: {payload[:100]}"
        n3 = f"Metadados: Origem {origem}, Destino {destino}, Método {metodo}"
        alerta = "Tráfego HTTP não criptografado – qualquer dado enviado pode ser interceptado."
        return self._base(e, "🌐", f"Requisição HTTP {metodo}", "AVISO",
                          n1, n2, n3, "", f"{origem} --[HTTP]--> {destino}", alerta)

    #  DNS
    def _dns(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        dominio = e.get("dns_query", "")
        porta   = e.get("porta_destino") or 53
        tamanho = e.get("tamanho", 0)
        titulo  = f"Consulta DNS — {dominio}" if dominio else "Consulta DNS"
        fluxo   = self._fluxo(origem, "DNS/UDP", destino)
        n1 = (
            f"O computador <b>{origem}</b> está perguntando ao servidor DNS "
            f"qual é o IP de <b style='color:#3498DB;'>{dominio or 'um domínio'}</b>.<br><br>"
            f"O DNS funciona como a lista telefônica da internet: você sabe "
            f"o nome do site, mas precisa do número (IP) para se conectar."
        )
        n2 = (
            f"Consulta DNS de <b>{origem}</b> para <b>{destino}:{porta}</b> "
            f"via UDP — transmitida sem criptografia."
            + (f"<br>Domínio: <code style='color:#3498DB;'>{dominio}</code>" if dominio else "") +
            f"<br><br><b>Alerta Privacidade:</b> consultas DNS padrão são "
            f"visíveis para todos na rede. Solução: DNS over HTTPS (DoH) "
            f"ou DNS over TLS (DoT)."
        )
        campos = [
            ("IP Origem",        origem),
            ("Servidor DNS",     destino),
            ("Domínio",          dominio or "—"),
            ("Porta",            f"UDP/{porta}"),
            ("Tamanho",          f"{tamanho} bytes"),
            ("Criptografado",    " Não"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "Consulta DNS sem criptografia – qualquer um na rede vê os sites que você acessa."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  HTTPS
    def _https(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        sni     = e.get("tls_sni", "")
        porta   = e.get("porta_destino") or 443
        tamanho = e.get("tamanho", 0)
        flags   = e.get("flags_tcp", "")
        alvo    = sni or destino
        titulo  = f"HTTPS protegido — {alvo}"
        fluxo   = self._fluxo(origem, "HTTPS ", f"{alvo}:{porta}")

        fase = ""
        if flags and "S" in flags and "A" not in flags:
            fase = "Início do handshake TCP (SYN) — precede o TLS"
        elif sni:
            fase = "TLS ClientHello — SNI extraído com sucesso"

        n1 = (
            f"O computador <b>{origem}</b> está acessando "
            f"<b style='color:#2ECC71;'>{alvo}</b> com HTTPS.<br><br>"
            f"Mesmo capturando todos os pacotes, o conteúdo é ilegível — "
            f"cifrado com TLS. Senhas e dados pessoais estão protegidos. "
            f"O sniffer só enxerga IPs, porta e o SNI (nome do host no certificado)."
        )
        n2 = (
            f"Conexão HTTPS de <b>{origem}</b> para <b>{alvo}:{porta}</b>."
            + (f"<br>Fase detectada: {fase}" if fase else "")
            + (f"<br>SNI: <code style='color:#2ECC71;'>{sni}</code>" if sni else "") +
            f"<br><br>O TLS Handshake negocia uma chave de sessão única que "
            f"cifra todo o tráfego. Perfect Forward Secrecy garante que sessões "
            f"passadas não possam ser decifradas mesmo com vazamento futuro da chave. "
            f"Se o SNI revelar serviços sensíveis (ex.: admin), considere ESNI/HTTP/3 para "
            f"ocultar o host."
        )
        campos = [
            ("IP Origem",       origem),
            ("Domínio (SNI)",   sni or "não extraído neste pacote"),
            ("IP Destino",      destino),
            ("Porta",           str(porta)),
            ("Flags TCP",       flags or "—"),
            ("Tamanho",         f"{tamanho} bytes"),
            ("Criptografado",   " Sim — AES-256 via TLS"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  TCP SYN
    def _tcp_syn(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino", "?")
        ttl     = e.get("ttl")
        tamanho = e.get("tamanho", 0)
        os_info = self._estimar_os(ttl)
        titulo  = f"Início de conexão TCP → {destino}:{porta}"
        fluxo   = self._fluxo(origem, "TCP SYN", f"{destino}:{porta}")

        n1 = (
            f"<b>{origem}</b> está iniciando uma conexão com "
            f"<b>{destino}:{porta}</b>.<br><br>"
            f"O TCP realiza um 'aperto de mão' em 3 etapas antes de transmitir "
            f"dados, garantindo que ambos os lados estão prontos."
        )
        n2 = (
            f"<b>Passo 1/3 — SYN</b> de <b>{origem}</b> para "
            f"<b>{destino}:{porta}</b>."
            + (f"<br>OS estimado pelo TTL: <b>{os_info}</b>" if os_info else "") +
            f"<br><br>Próximas etapas: SYN-ACK (servidor) → ACK (cliente) "
            f"→ conexão estabelecida e pronta para transmitir dados."
        )
        campos = [
            ("IP Origem",          origem),
            ("IP Destino",         f"{destino}:{porta}"),
            ("Flags TCP",          "SYN"),
            ("TTL",                f"{ttl} — {os_info}" if ttl and os_info else str(ttl) if ttl else "—"),
            ("Tamanho",            f"{tamanho} bytes"),
            ("Fase do handshake",  "1/3 — SYN enviado"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  TCP FIN
    def _tcp_fin(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        tamanho = e.get("tamanho", 0)
        titulo  = f"Encerramento TCP — {origem} → {destino}"
        fluxo   = self._fluxo(origem, "TCP FIN", destino)
        n1 = (
            f"<b>{origem}</b> está encerrando a conexão com <b>{destino}</b>.<br><br>"
            f"A flag FIN encerra a conexão educadamente, garantindo entrega "
            f"de todos os dados pendentes antes do fechamento."
        )
        n2 = (
            "Encerramento TCP em 4 etapas: FIN → ACK → FIN → ACK. "
            "Após o fechamento, o estado TIME_WAIT persiste ~60s para "
            "absorver pacotes atrasados da sessão."
        )
        n3 = self._tabela_campos([
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
        ])
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  TCP RST
    def _tcp_rst(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino", "?")
        titulo  = f"Conexão recusada (RST) — {destino}:{porta}"
        fluxo   = self._fluxo(origem, "TCP RST Alerta", destino)
        n1 = (
            f"A conexão com <b>{destino}:{porta}</b> foi recusada abruptamente.<br><br>"
            f"Indica porta fechada, firewall bloqueando ou serviço indisponível."
        )
        n2 = (
            "Flag RST encerra a conexão imediatamente sem negociação. "
            "Diferente do FIN, nenhum dado pendente é entregue. "
            "RSTs frequentes podem indicar port scanning."
        )
        n3 = self._tabela_campos([
            ("IP Origem",   origem),
            ("IP Destino",  f"{destino}:{porta}"),
            ("Flags TCP",   "RST — reset abrupto"),
        ])
        alerta = f"Conexão recusada na porta {porta} – pode ser firewall ou serviço inexistente."
        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  ICMP
    def _icmp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        ttl     = e.get("ttl")
        tamanho = e.get("tamanho", 0)
        payload = e.get("payload_resumo", "")
        os_info = self._estimar_os(ttl)
        titulo  = f"Ping ICMP — {origem} → {destino}"
        fluxo   = self._fluxo(origem, "ICMP", destino)

        saltos = None
        if ttl:
            try:
                t = int(ttl)
                saltos = (128 - t if t >= 120 else 64 - t if t >= 55 else 32 - t)
            except Exception:
                pass

        n1 = (
            f"<b>{origem}</b> está verificando se <b>{destino}</b> está "
            f"acessível e medindo a latência da conexão."
        )
        n2 = (
            f"ICMP Echo Request de <b>{origem}</b> para <b>{destino}</b>."
            + (f"<br>TTL={ttl} → aprox. <b>{saltos} salto(s)</b> ({os_info})."
               if ttl and saltos is not None else "")
        )
        campos = [
            ("IP Origem",       origem),
            ("IP Destino",      destino),
            ("TTL",             str(ttl) if ttl else "—"),
            ("OS estimado",     os_info),
            ("Saltos",          str(saltos) if saltos is not None else "—"),
            ("Tamanho",         f"{tamanho} bytes"),
            ("Detalhe ICMP",    payload or "—"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  ARP
    def _arp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        mac_src = e.get("mac_origem", "")
        titulo  = f"ARP — {origem} busca MAC de {destino}"
        fluxo   = self._fluxo(origem, "ARP broadcast", "FF:FF:FF:FF:FF:FF")
        n1 = (
            f"<b>{origem}</b> pergunta para a rede: "
            f"'Quem tem o IP <b>{destino}</b>? Me diga seu MAC.'"
        )
        fabricante = self._obter_fabricante(mac_src)
        n2 = (
            f"Broadcast ARP de <b>{origem}</b> (MAC {mac_src} - {fabricante}) "
            f"buscando o MAC de <b>{destino}</b>. "
            f"Sem autenticação — vulnerável a ARP Spoofing (Man-in-the-Middle). "
            f"Verifique a tabela ARP: arp -a"
        )
        campos = [
            ("IP que pergunta",  origem),
            ("MAC que pergunta", f"{mac_src} ({fabricante})" if mac_src else "—"),
            ("IP sendo buscado", destino),
            ("Broadcast",        "FF:FF:FF:FF:FF:FF"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "ARP sem criptografia – permite ataques de interceptação (ARP spoofing)."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  DHCP
    def _dhcp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        tipo    = e.get("dhcp_tipo", "")
        titulo  = f"DHCP {tipo} — {origem}" if tipo else f"DHCP — {origem}"
        fluxo   = self._fluxo(origem, f"DHCP {tipo}", destino)
        descs = {
            "DISCOVER": "procurando servidor DHCP (broadcast)",
            "OFFER":    "recebeu oferta de IP do servidor DHCP",
            "REQUEST":  "solicitando formalmente o IP oferecido",
            "ACK":      "IP concedido com sucesso!",
            "NAK":      "IP recusado pelo servidor DHCP",
            "RELEASE":  "liberando o IP de volta ao servidor",
        }
        n1 = (
            f"<b>{origem}</b> {descs.get(tipo, 'trocou mensagem DHCP')}.<br><br>"
            f"O DHCP distribui IPs automaticamente via processo DORA: "
            f"Discover → Offer → Request → Ack."
        )
        n2 = (
            f"Mensagem DHCP {tipo}. Além do IP, o DHCP entrega: "
            f"máscara de sub-rede, gateway padrão e servidores DNS."
        )
        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tipo DHCP",  tipo or "—"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "DHCP sem autenticação – pode haver servidor DHCP falso (ataque de rogue DHCP)."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  SSH
    def _ssh(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 22
        titulo  = f"SSH — Acesso remoto a {destino}"
        fluxo   = self._fluxo(origem, "SSH ", f"{destino}:{porta}")
        n1 = (
            f"<b>{origem}</b> está acessando o terminal de <b>{destino}</b> "
            f"via SSH — protocolo completamente criptografado."
        )
        n2 = (
            f"Sessão SSH porta {porta}. Todo tráfego cifrado. "
            f"Autenticação por senha ou chave pública/privada."
        )
        campos = [
            ("IP Origem",    origem),
            ("IP Destino",   f"{destino}:{porta}"),
            ("Criptografado"," Sim"),
        ]
        n3 = self._tabela_campos(campos)
        return self._base(e, "️", titulo, "INFO", n1, n2, n3, "", fluxo)

    #  FTP
    def _ftp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta   = e.get("porta_destino") or 21
        titulo  = f"FTP sem criptografia — {destino}"
        fluxo   = self._fluxo(origem, "FTP Alerta", destino)
        n1 = (
            f"<b>{origem}</b> está transferindo arquivos via FTP para "
            f"<b>{destino}</b> — sem criptografia. "
            f"Usuário e senha trafegam em texto puro."
        )
        n2 = (
            f"FTP porta {porta} — credenciais visíveis na rede. "
            f"Use SFTP (porta 22) ou FTPS como alternativa segura."
        )
        campos = [
            ("IP Origem",    origem),
            ("IP Destino",   f"{destino}:{porta}"),
            ("Criptografado"," Não — texto puro"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "FTP transmite credenciais em texto puro – risco alto de captura de senha."
        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  SMB
    def _smb(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        titulo  = f"SMB — Compartilhamento {destino}"
        fluxo   = self._fluxo(origem, "SMB", destino)
        n1 = (
            f"<b>{origem}</b> está acessando arquivos compartilhados em "
            f"<b>{destino}</b> via SMB (porta 445)."
        )
        n2 = (
            "Vulnerabilidade histórica: EternalBlue (MS17-010) no SMBv1 "
            "foi explorado pelo WannaCry em 2017. "
            "Verifique: Get-SmbServerConfiguration | Select EnableSMB1Protocol"
        )
        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      "445"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "Tráfego SMB – verifique permissões de compartilhamento."
        return self._base(e, "", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  RDP
    def _rdp(self, e: dict) -> dict:
        origem  = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        titulo  = f"RDP — Área de Trabalho Remota {destino}"
        fluxo   = self._fluxo(origem, "RDP Alerta", destino)
        n1 = (
            f"<b>{origem}</b> está controlando remotamente a tela de "
            f"<b>{destino}</b> via RDP (porta 3389)."
        )
        n2 = (
            "RDP exposto à internet é vetor crítico. Bots varrem a porta 3389 "
            "continuamente. Use NLA, VPN e monitore eventos 4625."
        )
        campos = [
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Porta",      "3389"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = "RDP exposto – risco de ataque de força bruta e BlueKeep."
        return self._base(e, "️", titulo, "AVISO", n1, n2, n3, "", fluxo, alerta)

    #  NOVO_DISPOSITIVO
    def _novo_dispositivo(self, e: dict) -> dict:
        ip  = e.get("ip_origem", "?")
        mac = e.get("mac_origem", "")
        fabricante = self._obter_fabricante(mac) if mac else ""
        titulo = f"Novo dispositivo — {ip}"
        fluxo  = self._fluxo("Novo dispositivo", "DHCP/ARP", ip)
        n1 = (
            f"Novo dispositivo detectado na rede: IP <b>{ip}</b>.<br><br>"
            f"O DHCP distribuiu o endereço automaticamente via processo "
            f"DORA: Discover → Offer → Request → Ack."
        )
        n2 = (
            f"IP: <b>{ip}</b>"
            + (f" | MAC: <code>{mac}</code> ({fabricante})" if mac else "") +
            f"<br>Os primeiros 3 bytes do MAC identificam o fabricante (OUI). "
            f"Consulte: macvendors.com"
        )
        campos = [
            ("IP detectado", ip),
            ("MAC",          f"{mac} ({fabricante})" if mac else "não identificado"),
        ]
        n3 = self._tabela_campos(campos)
        alerta = f"Novo dispositivo conectado – verifique se é autorizado (MAC {mac})."
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo, alerta)

    #  Genérico
    def _generico(self, e: dict) -> dict:
        protocolo = e.get("protocolo", "Desconhecido")
        origem    = e.get("ip_origem", "?")
        destino   = e.get("ip_destino", "?")
        tamanho   = e.get("tamanho", 0)
        titulo    = f"{protocolo} — {origem} → {destino}"
        fluxo     = self._fluxo(origem, protocolo, destino)
        n1 = f"Atividade de rede: <b>{protocolo}</b> de <b>{origem}</b> para <b>{destino}</b>."
        n2 = f"Protocolo <b>{protocolo}</b> capturado. Tamanho: {tamanho} bytes."
        n3 = self._tabela_campos([
            ("Protocolo",  protocolo),
            ("IP Origem",  origem),
            ("IP Destino", destino),
            ("Tamanho",    f"{tamanho} bytes"),
        ])
        return self._base(e, "", titulo, "INFO", n1, n2, n3, "", fluxo)

    def gerar_resumo_sessao(self, total_pacotes: int, total_bytes: int,
                             protocolos: list, total_dispositivos: int) -> str:
        mb    = total_bytes / (1024 * 1024)
        linhas = [
            " RESUMO DA SESSÃO", "-" * 36,
            f"Pacotes capturados:  {total_pacotes:>10,}",
            f"Volume transmitido:  {mb:>9.2f} MB",
            f"Dispositivos ativos: {total_dispositivos:>10}", "",
            "TOP PROTOCOLOS:",
        ]
        for item in protocolos[:6]:
            kb = item["bytes"] / 1024
            linhas.append(
                f"  {item['protocolo']:<12} {item['pacotes']:>6} pcts "
                f"({kb:.1f} KB)"
            )
        return "\n".join(linhas)