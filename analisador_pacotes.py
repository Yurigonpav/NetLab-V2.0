# analisador_pacotes.py
import re
from collections import defaultdict

class AnalisadorPacotes:
    def __init__(self):
        self.resetar()

    def resetar(self):
        self.total_pacotes = 0
        self.total_bytes = 0
        self.estatisticas_protocolos = defaultdict(int)    # protocolo -> contagem de pacotes
        self.bytes_por_protocolo = defaultdict(int)       # protocolo -> bytes acumulados
        self.trafego_dispositivos = defaultdict(lambda: {"enviado": 0, "recebido": 0})

    def processar_pacote(self, dados: dict):
        """Retorna um dicionário de evento se o pacote for relevante, ou None."""
        self.total_pacotes += 1
        tamanho = dados.get("tamanho", 0)
        self.total_bytes += tamanho

        proto = dados.get("protocolo", "Outro")
        self.estatisticas_protocolos[proto] += 1
        self.bytes_por_protocolo[proto] += tamanho

        ip_origem = dados.get("ip_origem")
        ip_destino = dados.get("ip_destino")

        if ip_origem:
            self.trafego_dispositivos[ip_origem]["enviado"] += tamanho
        if ip_destino:
            self.trafego_dispositivos[ip_destino]["recebido"] += tamanho

        evento = None

        # 1) DNS
        if proto == "DNS" and dados.get("dominio"):
            evento = {
                "tipo": "DNS",
                "ip_origem": ip_origem,
                "ip_destino": ip_destino,
                "dominio": dados["dominio"],
                "protocolo": "DNS"
            }

        # 2) TCP SYN (nova conexão)
        elif proto == "TCP" and dados.get("flags") == "SYN":
            evento = {
                "tipo": "TCP_SYN",
                "ip_origem": ip_origem,
                "ip_destino": ip_destino,
                "porta_origem": dados.get("porta_origem"),
                "porta_destino": dados.get("porta_destino"),
                "protocolo": "TCP"
            }

        # 3) HTTP (porta 80)
        elif dados.get("porta_destino") == 80 or dados.get("porta_origem") == 80:
            payload = dados.get("payload", b"")
            if payload:
                try:
                    linhas = payload.split(b"\r\n")
                    primeira_linha = linhas[0].decode('utf-8', errors='ignore')
                    if re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS)", primeira_linha):
                        partes = primeira_linha.split(' ')
                        metodo = partes[0] if len(partes) > 0 else "HTTP"
                        recurso = partes[1] if len(partes) > 1 else "/"
                        corpo = b""
                        credenciais = []
                        if metodo == "POST":
                            corpo_idx = payload.find(b"\r\n\r\n")
                            if corpo_idx != -1:
                                corpo = payload[corpo_idx+4:]
                                corpo_str = corpo.decode('utf-8', errors='ignore')
                                for match in re.finditer(r'(user|login|email|pass|password)=([^&\s]+)', corpo_str, re.I):
                                    credenciais.append((match.group(1), match.group(2)))
                        evento = {
                            "tipo": "HTTP",
                            "ip_origem": ip_origem,
                            "ip_destino": ip_destino,
                            "metodo": metodo,
                            "recurso": recurso,
                            "credenciais": credenciais,
                            "payload_bruto": payload[:500].decode('utf-8', errors='ignore'),
                            "protocolo": "HTTP"
                        }
                except:
                    pass

        # 4) HTTPS (porta 443)
        elif dados.get("porta_destino") == 443 or dados.get("porta_origem") == 443:
            evento = {
                "tipo": "HTTPS",
                "ip_origem": ip_origem,
                "ip_destino": ip_destino,
                "protocolo": "HTTPS"
            }

        # 5) ICMP
        elif proto == "ICMP":
            evento = {
                "tipo": "ICMP",
                "ip_origem": ip_origem,
                "ip_destino": ip_destino,
                "protocolo": "ICMP"
            }

        # 6) ARP
        elif proto == "ARP":
            evento = {
                "tipo": "ARP",
                "ip_origem": ip_origem,
                "ip_destino": ip_destino,
                "mac_origem": dados.get("mac_origem"),
                "protocolo": "ARP"
            }

        return evento

    def obter_estatisticas_protocolos(self):
        """Retorna lista de dicionários: [{'protocolo': 'TCP', 'pacotes': 10, 'bytes': 1500}, ...]"""
        resultado = []
        for proto, pacotes in self.estatisticas_protocolos.items():
            resultado.append({
                "protocolo": proto,
                "pacotes": pacotes,
                "bytes": self.bytes_por_protocolo.get(proto, 0)
            })
        resultado.sort(key=lambda x: x["pacotes"], reverse=True)
        return resultado

    def obter_top_dispositivos(self, top_n=10):
        """Retorna lista de dicionários: [{'ip': ip, 'enviado': bytes, 'recebido': bytes, 'total': bytes}, ...]"""
        ordenados = sorted(
            self.trafego_dispositivos.items(),
            key=lambda x: x[1]["enviado"] + x[1]["recebido"],
            reverse=True
        )
        resultado = []
        for ip, stats in ordenados[:top_n]:
            resultado.append({
                "ip": ip,
                "enviado": stats["enviado"],
                "recebido": stats["recebido"],
                "total": stats["enviado"] + stats["recebido"]
            })
        return resultado