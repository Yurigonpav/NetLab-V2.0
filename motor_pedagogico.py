# motor_pedagogico.py
# Motor pedagógico compatível com os eventos brutos do AnalisadorPacotes.
# Gera explicações em três níveis (Simples, Técnico, Pacote Bruto).

import time
from datetime import datetime
from typing import Dict, Any

class MotorPedagogico:
    """Converte eventos brutos do analisador em eventos completos para o PainelEventos."""

    def gerar_explicacao(self, evento_bruto: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recebe um evento bruto (ex: {'tipo':'HTTP', 'ip_origem':'...', ...})
        Retorna um evento completo com todos os campos exigidos pelo PainelEventos.
        """
        tipo = evento_bruto.get("tipo", "OUTRO")
        metodo = {
            "HTTP": self._http,
            "HTTP_RESPONSE": self._http_response,
            "HTTPS": self._https,
            "DNS": self._dns,
            "TCP_SYN": self._tcp_syn,
            "ICMP": self._icmp,
            "ARP": self._arp,
        }.get(tipo, self._generico)
        return metodo(evento_bruto)

    # ------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------
    def _http(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        metodo = e.get("metodo", "GET")
        recurso = e.get("recurso", "/")
        creds = e.get("credenciais", [])
        payload = e.get("payload_bruto", "")
        timestamp = datetime.now().strftime("%H:%M:%S")

        titulo = f"Requisição HTTP {metodo} {recurso}"
        fluxo = f"{origem} --[HTTP]--> {destino}"
        alerta = ""
        nivel = "AVISO" if creds else "INFO"

        # Nível 1 - Simples
        if creds:
            n1 = f"⚠️ O dispositivo **{origem}** enviou dados sensíveis (login/senha) para **{destino}** usando HTTP sem criptografia. Qualquer pessoa na mesma rede pode capturar essas informações."
        else:
            n1 = f"O dispositivo **{origem}** fez uma requisição HTTP para **{destino}**. O conteúdo não é criptografado, mas não foram encontradas credenciais neste pacote."

        # Nível 2 - Técnico
        n2 = f"Requisição HTTP/1.1 {metodo} {recurso}\n"
        n2 += f"Origem: {origem}\nDestino: {destino}\n"
        if creds:
            n2 += f"⚠️ Credenciais em texto puro: {', '.join([f'{k}={v}' for k,v in creds])}\n"
        n2 += "Risco: Interceptação de dados em redes não criptografadas."

        # Nível 4 - Pacote Bruto
        n4 = f"<pre style='white-space:pre-wrap;font-family:Consolas;font-size:10px;'>{payload[:2000]}</pre>"
        if not payload:
            n4 = "<i>Payload bruto não disponível.</i>"

        return self._montar_evento(tipo="HTTP", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta=alerta, nivel=nivel)

    # ------------------------------------------------------------
    # Resposta HTTP
    # ------------------------------------------------------------
    def _http_response(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        status = e.get("status_code", "???")
        payload = e.get("payload_bruto", "")
        timestamp = datetime.now().strftime("%H:%M:%S")

        titulo = f"Resposta HTTP {status}"
        fluxo = f"{origem} --[HTTP {status}]--> {destino}"
        n1 = f"O servidor **{origem}** respondeu ao cliente **{destino}** com o código HTTP {status}."
        if status.startswith("2"):
            n1 += " A requisição foi bem-sucedida."
        elif status.startswith("4"):
            n1 += " Ocorreu um erro no lado do cliente (ex: página não encontrada)."
        elif status.startswith("5"):
            n1 += " Ocorreu um erro interno no servidor."

        n2 = f"Código de status HTTP {status}. Indica o resultado da requisição."
        n4 = f"<pre style='white-space:pre-wrap;font-family:Consolas;font-size:10px;'>{payload[:2000]}</pre>"
        if not payload:
            n4 = "<i>Payload bruto não disponível.</i>"

        return self._montar_evento(tipo="HTTP_RESPONSE", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta="", nivel="INFO")

    # ------------------------------------------------------------
    # HTTPS
    # ------------------------------------------------------------
    def _https(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        timestamp = datetime.now().strftime("%H:%M:%S")
        titulo = f"Conexão HTTPS protegida com {destino}"
        fluxo = f"{origem} --[HTTPS/TLS]--> {destino}"
        n1 = f"O dispositivo **{origem}** estabeleceu uma conexão criptografada com **{destino}** via HTTPS. O conteúdo é seguro contra espionagem."
        n2 = "Tráfego TLS/SSL. O handshake negocia uma chave de sessão única. Dados como senhas e cookies são transmitidos de forma cifrada."
        n4 = "Pacote criptografado – não é possível inspecionar o conteúdo sem as chaves de sessão."
        return self._montar_evento(tipo="HTTPS", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta="", nivel="INFO")

    # ------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------
    def _dns(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        dominio = e.get("dominio", "desconhecido")
        timestamp = datetime.now().strftime("%H:%M:%S")
        titulo = f"Consulta DNS: {dominio}"
        fluxo = f"{origem} --[DNS]--> {destino}"
        n1 = f"O dispositivo **{origem}** perguntou ao servidor DNS **{destino}** qual é o endereço IP de **{dominio}**."
        n2 = f"Consulta DNS tipo A para {dominio}. Sem criptografia – qualquer um na rede vê quais sites você acessa."
        n4 = f"Domínio consultado: {dominio}"
        alerta = "Consulta DNS em texto puro – use DNS over HTTPS (DoH) para privacidade."
        return self._montar_evento(tipo="DNS", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta=alerta, nivel="INFO")

    # ------------------------------------------------------------
    # TCP SYN
    # ------------------------------------------------------------
    def _tcp_syn(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        porta_orig = e.get("porta_origem", "?")
        porta_dest = e.get("porta_destino", "?")
        timestamp = datetime.now().strftime("%H:%M:%S")
        titulo = f"Início de conexão TCP – {origem}:{porta_orig}"
        fluxo = f"{origem}:{porta_orig} --[SYN]--> {destino}:{porta_dest}"
        n1 = f"O dispositivo **{origem}** iniciou uma conexão com **{destino}:{porta_dest}** (primeiro passo do handshake TCP)."
        n2 = "Pacote TCP com flag SYN. Inicia o three-way handshake (SYN, SYN-ACK, ACK)."
        n4 = "Pacote TCP SYN (sem payload)."
        return self._montar_evento(tipo="TCP_SYN", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta="", nivel="INFO")

    # ------------------------------------------------------------
    # ICMP
    # ------------------------------------------------------------
    def _icmp(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        timestamp = datetime.now().strftime("%H:%M:%S")
        titulo = f"Pacote ICMP entre {origem} e {destino}"
        fluxo = f"{origem} --[ICMP]--> {destino}"
        n1 = f"Pacote de diagnóstico (ping ou erro) trocado entre **{origem}** e **{destino}**."
        n2 = "Protocolo ICMP usado para mensagens de erro ou ping (echo request/reply)."
        n4 = "Pacote ICMP (detalhes dependem do tipo)."
        return self._montar_evento(tipo="ICMP", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta="", nivel="INFO")

    # ------------------------------------------------------------
    # ARP
    # ------------------------------------------------------------
    def _arp(self, e: Dict) -> Dict:
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        mac = e.get("mac_origem", "")
        timestamp = datetime.now().strftime("%H:%M:%S")
        titulo = f"Requisição ARP de {origem}"
        fluxo = f"{origem} --[ARP]--> broadcast"
        n1 = f"**{origem}** perguntou 'quem tem o IP {destino}?' para descobrir o endereço MAC correspondente."
        n2 = "Protocolo ARP mapeia IP para MAC dentro da rede local. Sem criptografia – vulnerável a ARP Spoofing."
        n4 = f"ARP who-has {destino} tell {origem}"
        alerta = "ARP sem autenticação – risco de ataque de interceptação (ARP spoofing)."
        return self._montar_evento(tipo="ARP", titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta=alerta, nivel="INFO")

    # ------------------------------------------------------------
    # Genérico (fallback)
    # ------------------------------------------------------------
    def _generico(self, e: Dict) -> Dict:
        tipo = e.get("tipo", "Desconhecido")
        origem = e.get("ip_origem", "?")
        destino = e.get("ip_destino", "?")
        timestamp = datetime.now().strftime("%H:%M:%S")
        titulo = f"Evento {tipo}"
        fluxo = f"{origem} --[{tipo}]--> {destino}"
        n1 = f"Atividade de rede do tipo {tipo} entre {origem} e {destino}."
        n2 = f"Protocolo {tipo} capturado. Sem detalhes adicionais."
        n4 = "Conteúdo bruto não disponível."
        return self._montar_evento(tipo=tipo, titulo=titulo, n1=n1, n2=n2, n4=n4,
                                   timestamp=timestamp, ip_envolvido=origem, ip_destino=destino,
                                   fluxo=fluxo, alerta="", nivel="INFO")

    # ------------------------------------------------------------
    # Montagem final do evento (compatível com PainelEventos)
    # ------------------------------------------------------------
    def _montar_evento(self, tipo: str, titulo: str, n1: str, n2: str, n4: str,
                       timestamp: str, ip_envolvido: str, ip_destino: str,
                       fluxo: str, alerta: str, nivel: str) -> Dict:
        return {
            "tipo": tipo,
            "titulo": titulo,
            "nivel1": n1,
            "nivel2": n2,
            "nivel4": n4,
            "timestamp": timestamp,
            "ip_envolvido": ip_envolvido,
            "ip_destino": ip_destino,
            "fluxo_visual": fluxo,
            "alerta_seguranca": alerta,
            "nivel": nivel,
            "icone": "",
            "contador": 1,
            "contador_sessao": 1,
        }