# interface/janela_principal.py
# Janela principal do NetLab Educacional – VERSÃO AUTOSSUFICIENTE E CORRIGIDA
# Inclui a classe EstadoRede internamente para garantir funcionamento.

import socket
import threading
import time
from collections import deque

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout,
    QLabel, QPushButton, QComboBox,
    QMessageBox, QToolBar, QTabWidget,
    QDialog, QHBoxLayout, QTextEdit,
    QDialogButtonBox, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QFont

# Importações dos módulos originais do projeto
from analisador_pacotes import AnalisadorPacotes
from motor_pedagogico import MotorPedagogico
from banco_dados import BancoDados
from interface.painel_topologia import PainelTopologia
from interface.painel_trafego import PainelTrafego
from interface.painel_eventos import PainelEventos
from painel_servidor import PainelServidor

# ============================================================================
# CLASSE EstadoRede (gerencia cooldown e dispositivos)
# ============================================================================
class EstadoRede:
    """Gerencia estado da rede, cooldown de eventos e descoberta de dispositivos."""
    def __init__(self):
        self.ultimos_eventos = {}      # chave -> timestamp
        self.dispositivos = {}         # ip -> (mac, hostname, primeiro_visto)
        self._lock = threading.Lock()

    def deve_emitir_evento(self, chave: str, cooldown: int = 5) -> bool:
        """Retorna True se o evento ainda não foi emitido dentro do período de cooldown."""
        agora = time.time()
        with self._lock:
            if chave in self.ultimos_eventos:
                if agora - self.ultimos_eventos[chave] < cooldown:
                    return False
            self.ultimos_eventos[chave] = agora
            return True

    def registrar_dispositivo(self, ip: str, mac: str = "", hostname: str = "") -> str:
        """Registra um dispositivo na rede. Retorna 'NOVO' se for a primeira vez."""
        with self._lock:
            if ip not in self.dispositivos:
                self.dispositivos[ip] = (mac, hostname, time.time())
                return "NOVO"
            return "EXISTENTE"

    def obter_dispositivo(self, ip: str):
        """Retorna tupla (mac, hostname, timestamp) ou None."""
        return self.dispositivos.get(ip)

# ============================================================================
# IMPLEMENTAÇÃO INTERNA DAS FUNCIONALIDADES QUE ANTES ESTAVAM EM capturador_rede.py
# ============================================================================

# ----- Fila global de pacotes (thread-safe) -----
class _FilaPacotesGlobal:
    def __init__(self):
        self._fila = deque()
        self._lock = threading.Lock()

    def adicionar(self, pacote):
        with self._lock:
            self._fila.append(pacote)

    def consumir_todos(self):
        with self._lock:
            pacotes = list(self._fila)
            self._fila.clear()
            return pacotes

    def limpar(self):
        with self._lock:
            self._fila.clear()

fila_pacotes_global = _FilaPacotesGlobal()

# ----- Funções auxiliares de rede -----
def obter_ip_local() -> str:
    """Retorna o IP local da máquina (primeira interface não‑loopback)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def obter_interfaces_disponiveis() -> list:
    """Retorna uma lista com as descrições das interfaces de rede (para exibição)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        descricoes = []
        for iface in interfaces:
            desc = iface.get('description', iface.get('name', ''))
            if desc and 'loopback' not in desc.lower():
                descricoes.append(desc)
        return descricoes
    except Exception:
        return []

# ----- Thread de captura de pacotes (usa AsyncSniffer para não travar a GUI) -----
class _CapturadorPacotesThread(QThread):
    """Thread que captura pacotes usando AsyncSniffer do Scapy."""
    erro_ocorrido = pyqtSignal(str)
    sem_pacotes = pyqtSignal(str)   # mantido por compatibilidade

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self._running = False
        self.sniffer = None

    def run(self):
        self._running = True
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ARP, DNS, Ether, Raw

            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._processar_pacote,
                store=False,
                filter="ip"
            )
            self.sniffer.start()

            # Mantém a thread viva enquanto a captura estiver ativa
            while self._running:
                self.sleep(1)
        except Exception as e:
            self.erro_ocorrido.emit(f"Erro no AsyncSniffer: {str(e)}")
        finally:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()

    def _processar_pacote(self, packet):
        if not self._running:
            return

        dados = {
            "tamanho": len(packet),
            "ip_origem": None,
            "ip_destino": None,
            "mac_origem": None,
            "mac_destino": None,
            "protocolo": "Outro",
            "porta_origem": None,
            "porta_destino": None,
        }

        from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, Raw

        if packet.haslayer(Ether):
            dados["mac_origem"] = packet[Ether].src
            dados["mac_destino"] = packet[Ether].dst

        if packet.haslayer(IP):
            dados["ip_origem"] = packet[IP].src
            dados["ip_destino"] = packet[IP].dst

            if packet.haslayer(TCP):
                dados["protocolo"] = "TCP"
                dados["porta_origem"] = packet[TCP].sport
                dados["porta_destino"] = packet[TCP].dport
                # Captura flags TCP (para SYN, FIN, RST)
                flags = packet[TCP].flags
                if flags & 0x02:
                    dados["flags"] = "SYN"
                elif flags & 0x01:
                    dados["flags"] = "FIN"
                elif flags & 0x04:
                    dados["flags"] = "RST"
            elif packet.haslayer(UDP):
                dados["protocolo"] = "UDP"
                dados["porta_origem"] = packet[UDP].sport
                dados["porta_destino"] = packet[UDP].dport
                if packet.haslayer(DNS):
                    dados["protocolo"] = "DNS"
                    if packet[DNS].qr == 0:  # query
                        qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore') if packet[DNS].qd else ''
                        dados["dominio"] = qname.rstrip('.')
        elif packet.haslayer(ARP):
            dados["protocolo"] = "ARP"
            dados["ip_origem"] = packet[ARP].psrc
            dados["ip_destino"] = packet[ARP].pdst
            if not dados["mac_origem"]:
                dados["mac_origem"] = packet[ARP].hwsrc
            if not dados["mac_destino"]:
                dados["mac_destino"] = packet[ARP].hwdst
            dados["arp_op"] = "request" if packet[ARP].op == 1 else "reply"

        # Captura payload para HTTP (porta 80) e armazena como bytes
        if dados.get("porta_destino") == 80 and packet.haslayer(Raw):
            dados["payload"] = packet[Raw].load

        fila_pacotes_global.adicionar(dados)

    def parar(self):
        self._running = False
        if self.sniffer:
            self.sniffer.stop()
        self.wait(3000)

# ----- Thread de descoberta de dispositivos (ping + ARP) -----
class _DescobrirDispositivosThread(QThread):
    dispositivo_encontrado = pyqtSignal(str, str, str)  # ip, mac, hostname
    varredura_concluida = pyqtSignal(list)
    progresso_atualizado = pyqtSignal(str)
    erro_ocorrido = pyqtSignal(str)

    def __init__(self, habilitar_ping=True):
        super().__init__()
        self.habilitar_ping = habilitar_ping

    def run(self):
        try:
            ip_local = obter_ip_local()
            if not ip_local or ip_local == "127.0.0.1":
                self.erro_ocorrido.emit("Não foi possível determinar a rede local.")
                return

            partes = ip_local.split('.')
            rede = '.'.join(partes[:3])
            dispositivos = []
            self.progresso_atualizado.emit("Varredura ARP em andamento...")

            from scapy.all import arping
            resultado = arping(f"{rede}.0/24", timeout=2, verbose=False)
            for sent, received in resultado[0]:
                ip = received.psrc
                mac = received.hwsrc
                hostname = ""  # Pode-se adicionar reverse DNS se desejado
                dispositivos.append((ip, mac, hostname))
                self.dispositivo_encontrado.emit(ip, mac, hostname)

            self.progresso_atualizado.emit(f"Varredura concluída: {len(dispositivos)} dispositivo(s).")
            self.varredura_concluida.emit(dispositivos)
        except Exception as e:
            self.erro_ocorrido.emit(f"Erro na descoberta: {str(e)}")

# ============================================================================
# JANELA PRINCIPAL
# ============================================================================

class JanelaPrincipal(QMainWindow):
    """Janela principal do NetLab Educacional – versão autossuficiente."""

    def __init__(self, banco: BancoDados):
        super().__init__()
        self.banco            = banco
        self.analisador       = AnalisadorPacotes()
        self.motor_pedagogico = MotorPedagogico()

        self.capturador:  _CapturadorPacotesThread      = None
        self.descobridor: _DescobrirDispositivosThread  = None
        self.descoberta_rodando: bool = False

        self.sessao_id:  int  = None
        self.em_captura: bool = False

        self._bytes_no_segundo_atual: int = 0

        # Mapeamento: descrição amigável -> nome real da interface (formato \Device\NPF_...)
        self._mapa_interface_nome = {}

        # Estado da rede (cooldown e dispositivos)
        self.estado_rede = EstadoRede()
        self.fila_eventos_ui = []                     # eventos acumulados para exibição
        self.eventos_mostrados_recentemente = deque(maxlen=200)  # para deduplicação visual

        # Timers
        self.timer_consumir = QTimer()
        self.timer_consumir.timeout.connect(self._consumir_fila)

        self.timer_ui = QTimer()
        self.timer_ui.timeout.connect(self._atualizar_ui_por_segundo)

        self.timer_descoberta = QTimer()
        self.timer_descoberta.timeout.connect(self._descoberta_periodica)

        self.timer_eventos = QTimer()
        self.timer_eventos.timeout.connect(self._descarregar_eventos_ui)
        self.timer_eventos.start(2000)   # a cada 2 segundos

        self._configurar_janela()
        self._criar_menu()
        self._criar_barra_status()
        self._criar_barra_ferramentas()
        self._criar_area_central()

    # ──────────────────────────────────────────────
    # Configuração da janela
    # ──────────────────────────────────────────────

    def _configurar_janela(self):
        self.setWindowTitle("NetLab Educacional — Monitor de Rede")
        self.setMinimumSize(1200, 700)
        self.resize(1440, 860)
        geo = self.screen().availableGeometry()
        self.move(
            (geo.width()  - self.width())  // 2,
            (geo.height() - self.height()) // 2,
        )

    def _criar_menu(self):
        menu = self.menuBar()

        m_arq = menu.addMenu("&Arquivo")
        a_nova = QAction("&Nova Sessão", self)
        a_nova.setShortcut("Ctrl+N")
        a_nova.triggered.connect(self._nova_sessao)
        m_arq.addAction(a_nova)
        m_arq.addSeparator()
        a_sair = QAction("&Sair", self)
        a_sair.setShortcut("Ctrl+Q")
        a_sair.triggered.connect(self.close)
        m_arq.addAction(a_sair)

        m_mon = menu.addMenu("&Monitoramento")
        self.acao_captura = QAction("Iniciar Captura", self)
        self.acao_captura.setShortcut("F5")
        self.acao_captura.triggered.connect(self._alternar_captura)
        m_mon.addAction(self.acao_captura)

        m_ajd = menu.addMenu("&Ajuda")
        a_sobre = QAction("Sobre o NetLab", self)
        a_sobre.triggered.connect(self._exibir_sobre)
        m_ajd.addAction(a_sobre)

    def _criar_barra_ferramentas(self):
        barra = self.addToolBar("Principal")
        barra.setMovable(False)

        barra.addWidget(QLabel("  Interface: "))
        self.combo_interface = QComboBox()
        self.combo_interface.setMinimumWidth(230)
        self.combo_interface.setToolTip(
            "Interface de rede a ser monitorada.\n"
            "A interface ativa é selecionada automaticamente."
        )
        self._popular_interfaces()
        barra.addWidget(self.combo_interface)
        barra.addSeparator()

        self.botao_captura = QPushButton("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self.botao_captura.setMinimumWidth(155)
        self.botao_captura.clicked.connect(self._alternar_captura)
        barra.addWidget(self.botao_captura)

        barra.addSeparator()
        self.lbl_ip = QLabel(f"  Meu IP: {obter_ip_local()}  ")
        self.lbl_ip.setStyleSheet("color:#2ecc71; font-weight:bold;")
        barra.addWidget(self.lbl_ip)

    def _criar_area_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        self.abas = QTabWidget()
        layout.addWidget(self.abas)

        self.painel_topologia = PainelTopologia()
        self.painel_trafego   = PainelTrafego()
        self.painel_eventos   = PainelEventos()
        self.painel_servidor  = PainelServidor()

        self.abas.addTab(self.painel_topologia, "Topologia da Rede")
        self.abas.addTab(self.painel_trafego,   "Tráfego em Tempo Real")
        self.abas.addTab(self.painel_eventos,   " Modo Análise")
        self.abas.addTab(self.painel_servidor,  "Servidor")

    def _criar_barra_status(self):
        b = self.statusBar()
        self.lbl_status  = QLabel("Pronto. Clique em 'Iniciar Captura' para começar.")
        self.lbl_pacotes = QLabel("Pacotes: 0")
        self.lbl_dados   = QLabel("  Dados: 0 KB  ")
        b.addWidget(self.lbl_status)
        b.addPermanentWidget(self.lbl_pacotes)
        b.addPermanentWidget(self.lbl_dados)

    # ──────────────────────────────────────────────
    # Detecção de interfaces
    # ──────────────────────────────────────────────

    def _popular_interfaces(self):
        self.combo_interface.clear()
        self._mapa_interface_nome.clear()

        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces_raw = get_windows_if_list()
        except Exception:
            interfaces_raw = []

        if not interfaces_raw:
            descricoes = obter_interfaces_disponiveis()
            for desc in descricoes:
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = desc
            self._selecionar_interface_fallback()
            return

        for iface in interfaces_raw:
            desc = iface.get('description', iface.get('name', 'Desconhecida'))
            name = iface.get('name', '')
            if desc and name:
                self.combo_interface.addItem(desc)
                self._mapa_interface_nome[desc] = name

        ip_local = obter_ip_local()
        if ip_local:
            for iface in interfaces_raw:
                ips = iface.get('ips', [])
                if ip_local in ips:
                    desc = iface.get('description', iface.get('name', ''))
                    if desc:
                        idx = self.combo_interface.findText(desc)
                        if idx >= 0:
                            self.combo_interface.setCurrentIndex(idx)
                            self._status(f"Interface ativa detectada: {desc}")
                            return

        if self.combo_interface.count() > 0:
            self.combo_interface.setCurrentIndex(0)

    def _selecionar_interface_fallback(self):
        try:
            from scapy.all import conf
            default_iface = str(conf.iface)
            for i in range(self.combo_interface.count()):
                if default_iface in self.combo_interface.itemText(i):
                    self.combo_interface.setCurrentIndex(i)
                    return
        except Exception:
            pass

        try:
            ip_local = obter_ip_local()
            ultimo_octeto = ip_local.split(".")[-1] if ip_local else ""
            for i in range(self.combo_interface.count()):
                if ultimo_octeto and ultimo_octeto in self.combo_interface.itemText(i):
                    self.combo_interface.setCurrentIndex(i)
                    return
        except Exception:
            pass

    # ──────────────────────────────────────────────
    # Controle de captura
    # ──────────────────────────────────────────────

    @pyqtSlot()
    def _alternar_captura(self):
        if self.em_captura:
            self._parar_captura()
        else:
            self._iniciar_captura()

    def _iniciar_captura(self):
        descricao_selecionada = self.combo_interface.currentText()
        if not descricao_selecionada or "nenhuma" in descricao_selecionada.lower():
            QMessageBox.warning(
                self, "Interface Inválida",
                "Selecione uma interface de rede válida.\n\n"
                "Execute o programa como Administrador e verifique a instalação do Npcap."
            )
            return

        nome_dispositivo = self._mapa_interface_nome.get(descricao_selecionada)
        if not nome_dispositivo:
            nome_dispositivo = descricao_selecionada
            self._status(f"Aviso: usando nome direto '{nome_dispositivo}'")

        fila_pacotes_global.limpar()
        self.analisador.resetar()
        self._bytes_no_segundo_atual = 0
        self.sessao_id = self.banco.iniciar_sessao()

        self.capturador = _CapturadorPacotesThread(interface=nome_dispositivo)
        self.capturador.erro_ocorrido.connect(self._ao_ocorrer_erro)
        self.capturador.sem_pacotes.connect(self._ao_ocorrer_erro)
        self.capturador.start()

        self.timer_consumir.start(100)
        self.timer_ui.start(1000)
        self.timer_descoberta.start(30000)

        self.em_captura = True
        self.botao_captura.setText("Parar Captura")
        self.botao_captura.setObjectName("botao_parar")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Parar Captura")
        self._status(f"Capturando em: {descricao_selecionada} (dispositivo: {nome_dispositivo})")

    def _parar_captura(self):
        self.timer_consumir.stop()
        self.timer_ui.stop()
        self.timer_descoberta.stop()

        if self.capturador:
            self.capturador.parar()
            self.capturador = None

        self._consumir_fila()

        if self.sessao_id:
            self.banco.finalizar_sessao(
                self.sessao_id,
                self.analisador.total_pacotes,
                self.analisador.total_bytes,
            )

        self.em_captura = False
        self.botao_captura.setText("Iniciar Captura")
        self.botao_captura.setObjectName("botao_captura")
        self._repolir(self.botao_captura)
        self.acao_captura.setText("Iniciar Captura")
        self._status("Captura encerrada.")

    @staticmethod
    def _repolir(botao: QPushButton):
        botao.style().unpolish(botao)
        botao.style().polish(botao)

    # ──────────────────────────────────────────────
    # Processamento da fila de pacotes (COM GERAÇÃO DE EVENTOS)
    # ──────────────────────────────────────────────

    @pyqtSlot()
    def _consumir_fila(self):
        pacotes = fila_pacotes_global.consumir_todos()
        if not pacotes:
            return

        MAX_POR_CICLO = 100
        for i, dados in enumerate(pacotes):
            if i >= MAX_POR_CICLO:
                for restante in pacotes[i:]:
                    fila_pacotes_global.adicionar(restante)
                break

            self._bytes_no_segundo_atual += dados.get("tamanho", 0)
            evento = self.analisador.processar_pacote(dados)

            ip_origem  = dados.get("ip_origem", "")
            ip_destino = dados.get("ip_destino", "")
            mac_origem = dados.get("mac_origem", "")

            if ip_origem:
                self.painel_topologia.adicionar_dispositivo(ip_origem, mac_origem)
                self.banco.salvar_dispositivo(ip_origem, mac_origem)

            if ip_origem and ip_destino:
                self.painel_topologia.adicionar_conexao(ip_origem, ip_destino)

            # Se o analisador retornou um evento, enfileira para exibição
            if evento and evento.get("tipo"):
                if evento["tipo"] == "NOVO_DISPOSITIVO":
                    ip = evento.get("ip_origem")
                    if ip:
                        status = self.estado_rede.registrar_dispositivo(ip, evento.get("mac_origem"))
                        if status == "NOVO" and self.estado_rede.deve_emitir_evento(f"novo_{ip}", cooldown=30):
                            self.fila_eventos_ui.append(evento)
                else:
                    chave = f"{evento['tipo']}_{evento.get('ip_origem')}_{evento.get('dominio', '')}"
                    if self.estado_rede.deve_emitir_evento(chave, cooldown=5):
                        self.fila_eventos_ui.append(evento)

            # Amostragem para banco de dados
            if self.analisador.total_pacotes % 5 == 0:
                self.banco.salvar_pacote(
                    ip_origem=ip_origem,
                    ip_destino=ip_destino,
                    mac_origem=mac_origem,
                    mac_destino=dados.get("mac_destino", ""),
                    protocolo=dados.get("protocolo", ""),
                    tamanho_bytes=dados.get("tamanho", 0),
                    porta_origem=dados.get("porta_origem"),
                    porta_destino=dados.get("porta_destino"),
                    sessao_id=self.sessao_id,
                )

    # ──────────────────────────────────────────────
    # Agregação e descarregamento de eventos
    # ──────────────────────────────────────────────

    def _agregar_eventos(self, eventos):
        agregados = {}
        for ev in eventos:
            chave = (ev.get("tipo"), ev.get("ip_origem"), ev.get("dominio", ""))
            if chave not in agregados:
                agregados[chave] = ev.copy()
                agregados[chave]["contagem"] = 1
            else:
                agregados[chave]["contagem"] += 1
        return list(agregados.values())

    @pyqtSlot()
    def _descarregar_eventos_ui(self):
        if not self.fila_eventos_ui:
            return
        lote = self.fila_eventos_ui[:]
        self.fila_eventos_ui.clear()
        agregados = self._agregar_eventos(lote)
        for ev in agregados:
            chave_visual = (ev.get("tipo"), ev.get("ip_origem"), ev.get("ip_destino"), ev.get("dominio", ""))
            if chave_visual in self.eventos_mostrados_recentemente:
                continue
            self.eventos_mostrados_recentemente.append(chave_visual)
            self._exibir_evento_pedagogico(ev)

    # ──────────────────────────────────────────────
    # Atualização da UI (1 segundo)
    # ──────────────────────────────────────────────

    @pyqtSlot()
    def _atualizar_ui_por_segundo(self):
        kb_por_segundo = self._bytes_no_segundo_atual / 1024.0
        self._bytes_no_segundo_atual = 0

        self.painel_trafego.adicionar_ponto_grafico(kb_por_segundo)
        self.painel_trafego.atualizar_tabelas(
            estatisticas_protocolos=self.analisador.obter_estatisticas_protocolos(),
            top_dispositivos=self.analisador.obter_top_dispositivos(),
            total_pacotes=self.analisador.total_pacotes,
            total_bytes=self.analisador.total_bytes,
        )
        self.painel_topologia.atualizar()

        kb = self.analisador.total_bytes / 1024
        self.lbl_pacotes.setText(f"Pacotes: {self.analisador.total_pacotes:,}")
        self.lbl_dados.setText(
            f"  Dados: {kb/1024:.2f} MB  " if kb > 1024
            else f"  Dados: {kb:.1f} KB  "
        )

    # ──────────────────────────────────────────────
    # Exibição de evento pedagógico
    # ──────────────────────────────────────────────

    def _exibir_evento_pedagogico(self, evento: dict):
        evento["sessao_id"] = self.sessao_id
        explicacao = self.motor_pedagogico.gerar_explicacao(evento)
        if explicacao is None:
            explicacao = {
                "nivel1": f"Evento: {evento.get('tipo', 'Desconhecido')}",
                "nivel2": f"Origem: {evento.get('ip_origem', '?')} → Destino: {evento.get('ip_destino', '?')}",
                "nivel3": f"Dados: {evento}",
                "icone": "🔍",
                "nivel": "INFO",
                "alerta": "Evento detectado."
            }
        explicacao["sessao_id"] = self.sessao_id
        self.painel_eventos.adicionar_evento(explicacao)
        self.banco.salvar_evento(
            tipo_evento=evento.get("tipo", ""),
            descricao=explicacao.get("nivel1", "")[:500],
            ip_envolvido=evento.get("ip_origem"),
            sessao_id=self.sessao_id,
        )

    # ──────────────────────────────────────────────
    # Descoberta periódica de dispositivos
    # ──────────────────────────────────────────────

    def _descoberta_periodica(self):
        if not self.em_captura:
            return
        if self.descoberta_rodando or (self.descobridor and self.descobridor.isRunning()):
            return
        self.descoberta_rodando = True
        self._status("Varrendo a rede local em busca de dispositivos…")
        self.descobridor = _DescobrirDispositivosThread(habilitar_ping=True)
        self.descobridor.dispositivo_encontrado.connect(self._ao_encontrar_dispositivo)
        self.descobridor.varredura_concluida.connect(self._ao_concluir_varredura)
        self.descobridor.progresso_atualizado.connect(self._status)
        self.descobridor.erro_ocorrido.connect(self._ao_ocorrer_erro)
        self.descobridor.start()

    @pyqtSlot(str, str, str)
    def _ao_encontrar_dispositivo(self, ip: str, mac: str, hostname: str):
        self.painel_topologia.adicionar_dispositivo_manual(ip, mac, hostname)
        self.banco.salvar_dispositivo(ip, mac, hostname)
        evento = {
            "tipo":       "NOVO_DISPOSITIVO",
            "ip_origem":  ip,
            "ip_destino": "",
            "mac_origem": mac,
            "protocolo":  "ARP/DHCP",
            "tamanho":    0,
        }
        self.fila_eventos_ui.append(evento)

    @pyqtSlot(list)
    def _ao_concluir_varredura(self, dispositivos: list):
        self._status(f"Varredura concluída — {len(dispositivos)} dispositivo(s) encontrado(s).")
        self.descoberta_rodando = False

    # ──────────────────────────────────────────────
    # Tratamento de erros
    # ──────────────────────────────────────────────

    @pyqtSlot(str)
    def _ao_ocorrer_erro(self, mensagem: str):
        self._status(f"Erro: {mensagem[:80]}")
        QMessageBox.warning(self, "Erro", mensagem)
        if self.em_captura:
            self._parar_captura()
        self.descoberta_rodando = False

    # ──────────────────────────────────────────────
    # Ações gerais
    # ──────────────────────────────────────────────

    def _nova_sessao(self):
        if self.em_captura:
            self._parar_captura()
        self.analisador.resetar()
        self.painel_topologia.limpar()
        self.painel_trafego.limpar()
        self.painel_eventos.limpar()
        self._status("Nova sessão iniciada. Pronto para capturar.")

    def _status(self, msg: str):
        self.lbl_status.setText(msg)

    def _exibir_sobre(self):
        QMessageBox.about(
            self, "Sobre o NetLab Educacional",
            "<h2>NetLab Educacional v2.0</h2>"
            "<p>Software educacional para análise de redes locais.</p>"
            "<hr>"
            "<p><b>TCC — Curso Técnico em Informática</b></p>"
            "<p><b>Tecnologias:</b> Python · PyQt6 · Scapy · SQLite · PyQtGraph</p>"
            "<p><b>Versão autossuficiente</b> – não requer módulos externos.</p>"
        )

    def closeEvent(self, evento):
        if self.em_captura:
            self._parar_captura()
        self.banco.fechar()
        evento.accept()