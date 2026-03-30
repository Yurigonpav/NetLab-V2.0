# interface/painel_eventos.py
# Painel do Modo Aula — três níveis de explicação (Simples, Técnico, Pacote Bruto).
# O nível Pacote Bruto é exclusivo para HTTP e mostra o tráfego exatamente como capturado.

from collections import defaultdict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QScrollArea, QFrame, QPushButton, QTextEdit,
    QSplitter, QTabWidget, QLineEdit, QComboBox,
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont

ESTILOS_NIVEL = {
    "INFO":   {"borda": "#3498DB", "fundo": "#0d1a2a", "badge": "#1a4a6b"},
    "AVISO":  {"borda": "#E67E22", "fundo": "#1f1200", "badge": "#5a3000"},
    "CRITICO":{"borda": "#E74C3C", "fundo": "#200a0a", "badge": "#5a0000"},
}

ROTULOS_NIVEL = [
    ("", "Simples",      "Linguagem do dia a dia"),
    ("", "Técnico",      "Detalhes do protocolo"),
    ("", "Pacote Bruto", "Conteúdo exato como trafegou na rede"),
]


class CartaoEvento(QFrame):
    """Cartão compacto para a lista lateral de eventos capturados."""

    def __init__(self, dados: dict, parent=None):
        super().__init__(parent)
        nivel  = dados.get("nivel", "INFO")
        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {estilo['fundo']};
                border-left: 4px solid {estilo['borda']};
                border-radius: 3px;
                margin: 1px 2px;
            }}
            QFrame:hover {{ background-color: #1a2540; }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(2)

        header = QHBoxLayout()
        icone_titulo = QLabel(
            f"{dados.get('icone', '')} {dados.get('titulo', 'Evento')}".strip()
        )
        icone_titulo.setStyleSheet(
            f"color:{estilo['borda']};font-weight:bold;"
            f"font-size:10px;border:none;"
        )
        icone_titulo.setWordWrap(False)

        hora = QLabel(dados.get("timestamp", ""))
        hora.setStyleSheet("color:#7f8c8d;font-size:9px;border:none;")

        header.addWidget(icone_titulo, 1)
        header.addWidget(hora)
        layout.addLayout(header)

        ip_src   = dados.get("ip_envolvido", "")
        ip_dst   = dados.get("ip_destino", "")
        ip_texto = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_texto += f" -> {ip_dst}"

        lbl_ip = QLabel(ip_texto)
        lbl_ip.setStyleSheet(
            "color:#95a5a6;font-size:9px;font-family:Consolas;border:none;"
        )
        layout.addWidget(lbl_ip)

        # Badge de alerta de segurança
        if dados.get("alerta_seguranca"):
            badge = QLabel("Risco de segurança")
            badge.setStyleSheet(
                f"color:#E74C3C;font-size:8px;font-weight:bold;"
                f"background:{estilo['badge']};border-radius:2px;"
                f"padding:1px 4px;border:none;"
            )
            layout.addWidget(badge)


class PainelContadores(QWidget):
    """Barra horizontal com contadores por tipo de evento."""

    TIPOS_MONITORADOS = [
        ("DNS",   "", "#3498DB"),
        ("HTTP",  "", "#E74C3C"),
        ("HTTPS", "", "#2ECC71"),
        ("TCP_SYN","", "#9B59B6"),
        ("ICMP",  "", "#1ABC9C"),
        ("ARP",   "", "#E67E22"),
        ("DHCP",  "", "#16A085"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._contadores: dict = defaultdict(int)
        self._labels: dict     = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(8)

        titulo = QLabel("Eventos nesta sessão:")
        titulo.setStyleSheet("color:#7f8c8d;font-size:9px;")
        layout.addWidget(titulo)

        for tipo, icone, cor in self.TIPOS_MONITORADOS:
            lbl = QLabel(f"{icone} {tipo}: 0")
            lbl.setStyleSheet(
                f"color:{cor};font-size:9px;font-family:Consolas;"
                f"background:#0d1a2a;border:1px solid {cor}33;"
                f"border-radius:3px;padding:1px 6px;"
            )
            self._labels[tipo] = lbl
            layout.addWidget(lbl)

        layout.addStretch()

    def incrementar(self, tipo: str):
        self._contadores[tipo] += 1
        if tipo in self._labels:
            icone = next(
                (ic for t, ic, _ in self.TIPOS_MONITORADOS if t == tipo), "•"
            )
            self._labels[tipo].setText(
                f"{icone} {tipo}: {self._contadores[tipo]}"
            )

    def resetar(self):
        self._contadores.clear()
        for tipo, icone, _ in self.TIPOS_MONITORADOS:
            if tipo in self._labels:
                self._labels[tipo].setText(f"{icone} {tipo}: 0")


class PainelEventos(QWidget):
    """
    Painel completo do Modo Aula com três níveis de explicação.

    O nível Pacote Bruto exibe o conteúdo HTTP exatamente como
    trafegou na rede — disponível apenas para eventos HTTP.
    """

    LIMITE_EVENTOS = 300

    def __init__(self, parent=None):
        super().__init__(parent)
        self._todos_eventos:     list = []
        self._eventos_filtrados: list = []
        self._evento_atual:      dict = {}
        self._nivel_atual:       int  = 0
        self._filtro_protocolo:  str  = "Todos"
        self._filtro_texto:      str  = ""
        self._contagem_sessao:   dict = defaultdict(lambda: defaultdict(int))
        self._montar_layout()

    # ──────────────────────────────────────────────
    # Montagem da interface
    # ──────────────────────────────────────────────

    def _montar_layout(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 4)
        layout.setSpacing(4)

        # Cabeçalho
        cab = QHBoxLayout()
        fonte_titulo = QFont("Arial", 12)
        fonte_titulo.setBold(True)
        titulo = QLabel("  Modo Análise — Eventos de Rede em Tempo Real")
        titulo.setFont(fonte_titulo)
        cab.addWidget(titulo)
        cab.addStretch()

        btn_limpar = QPushButton("🗑  Limpar sessão")
        btn_limpar.setMaximumWidth(130)
        btn_limpar.clicked.connect(self.limpar)
        cab.addWidget(btn_limpar)
        layout.addLayout(cab)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#2c3e50;")
        layout.addWidget(sep)

        # Barra de filtros
        layout.addLayout(self._criar_barra_filtros())

        # Contadores
        self.painel_contadores = PainelContadores()
        layout.addWidget(self.painel_contadores)

        # Abas principais
        self.abas = QTabWidget()
        self.abas.setTabBarAutoHide(True)
        layout.addWidget(self.abas)

        self.abas.addTab(self._criar_aba_eventos(), "Eventos ao Vivo")
        

        # Rodapé
        self.lbl_rodape = QLabel("Nenhum evento registrado.")
        self.lbl_rodape.setStyleSheet(
            "color:#7f8c8d;font-size:10px;padding:2px;"
        )
        layout.addWidget(self.lbl_rodape)

        # Estado inicial
        self._trocar_nivel(0)
        self._exibir_boas_vindas()

    def _criar_barra_filtros(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(6)

        lbl = QLabel("Filtrar:")
        lbl.setStyleSheet("color:#7f8c8d;font-size:10px;")
        row.addWidget(lbl)

        self.combo_protocolo = QComboBox()
        self.combo_protocolo.setMaximumWidth(140)
        self.combo_protocolo.addItems([
            "Todos", "DNS", "HTTP", "HTTPS", "TCP_SYN", "TCP_FIN",
            "TCP_RST", "ICMP", "ARP", "DHCP", "SSH", "FTP",
            "SMB", "RDP", "NOVO_DISPOSITIVO",
        ])
        self.combo_protocolo.currentTextChanged.connect(
            self._ao_mudar_filtro_protocolo
        )
        row.addWidget(self.combo_protocolo)

        self.campo_busca = QLineEdit()
        self.campo_busca.setPlaceholderText("Buscar por IP, domínio, palavra-chave…")
        self.campo_busca.setMaximumWidth(280)
        self.campo_busca.textChanged.connect(self._ao_mudar_filtro_texto)
        row.addWidget(self.campo_busca)

        btn_limpar_filtro = QPushButton("✕ Limpar filtro")
        btn_limpar_filtro.setMaximumWidth(110)
        btn_limpar_filtro.clicked.connect(self._limpar_filtros)
        row.addWidget(btn_limpar_filtro)

        row.addStretch()
        return row

    def _criar_aba_eventos(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)

        # Lista lateral de eventos
        w_lista = QWidget()
        l_lista = QVBoxLayout(w_lista)
        l_lista.setContentsMargins(0, 0, 4, 0)
        l_lista.setSpacing(2)

        fonte_label = QFont("Arial", 10)
        fonte_label.setBold(True)
        lbl_lista = QLabel("Eventos Capturados")
        lbl_lista.setStyleSheet("color:#7f8c8d;padding-bottom:4px;")
        lbl_lista.setFont(fonte_label)
        l_lista.addWidget(lbl_lista)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._container = QWidget()
        self._layout_cartoes = QVBoxLayout(self._container)
        self._layout_cartoes.setContentsMargins(2, 2, 2, 2)
        self._layout_cartoes.setSpacing(3)
        self._layout_cartoes.addStretch()

        self._scroll.setWidget(self._container)
        l_lista.addWidget(self._scroll)
        splitter.addWidget(w_lista)

        # Painel de explicação
        w_expl = QWidget()
        l_expl = QVBoxLayout(w_expl)
        l_expl.setContentsMargins(4, 0, 0, 0)
        l_expl.setSpacing(4)

        lbl_expl = QLabel("📖  Explicação Didática")
        lbl_expl.setStyleSheet(
            "font-weight:bold;font-size:11px;color:#bdc3c7;"
        )
        l_expl.addWidget(lbl_expl)

        # Botões dos níveis
        row_niveis = QHBoxLayout()
        self.botoes_nivel = []
        for icone, rotulo, dica in ROTULOS_NIVEL:
            btn = QPushButton(f"{icone} {rotulo}")
            btn.setCheckable(True)
            btn.setMaximumHeight(26)
            btn.setToolTip(dica)
            idx = len(self.botoes_nivel)
            btn.clicked.connect(lambda _, n=idx: self._trocar_nivel(n))
            self.botoes_nivel.append(btn)
            row_niveis.addWidget(btn)
        row_niveis.addStretch()
        l_expl.addLayout(row_niveis)

        # Área de texto
        self.texto_explicacao = QTextEdit()
        self.texto_explicacao.setReadOnly(True)
        self.texto_explicacao.setStyleSheet("""
            QTextEdit {
                background-color: #0f1423;
                color: #ecf0f1;
                border: 1px solid #1e2d40;
                border-radius: 6px;
                padding: 14px;
                font-size: 11px;
            }
        """)
        l_expl.addWidget(self.texto_explicacao)

        splitter.addWidget(w_expl)
        splitter.setSizes([400, 580])

        return widget

    # ──────────────────────────────────────────────
    # Interface pública
    # ──────────────────────────────────────────────

    def adicionar_evento(self, dados: dict):
        """Recebe um evento do motor pedagógico e exibe na interface."""
        if len(self._todos_eventos) >= self.LIMITE_EVENTOS:
            self._todos_eventos.pop(0)

        sessao = dados.get("sessao_id", "sessao_default")
        tipo   = dados.get("tipo", "")
        self._contagem_sessao[sessao][tipo] += 1
        dados["contador_sessao"] = self._contagem_sessao[sessao][tipo]

        self._todos_eventos.append(dados)
        self.painel_contadores.incrementar(dados.get("tipo", ""))

        if self._passa_filtro(dados):
            self._adicionar_cartao(dados)
            self._eventos_filtrados.append(dados)

        self._evento_atual = dados
        self._renderizar_explicacao()
        self._atualizar_rodape()

    def limpar(self):
        self._todos_eventos.clear()
        self._eventos_filtrados.clear()
        self._evento_atual = {}
        self._contagem_sessao.clear()
        self.painel_contadores.resetar()

        while self._layout_cartoes.count() > 1:
            item = self._layout_cartoes.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.lbl_rodape.setText("Nenhum evento registrado.")
        self._exibir_boas_vindas()

    # ──────────────────────────────────────────────
    # Filtros
    # ──────────────────────────────────────────────

    @pyqtSlot(str)
    def _ao_mudar_filtro_protocolo(self, valor: str):
        self._filtro_protocolo = valor
        self._reaplicar_filtros()

    @pyqtSlot(str)
    def _ao_mudar_filtro_texto(self, texto: str):
        self._filtro_texto = texto.lower().strip()
        self._reaplicar_filtros()

    def _limpar_filtros(self):
        self.combo_protocolo.setCurrentText("Todos")
        self.campo_busca.clear()

    def _passa_filtro(self, dados: dict) -> bool:
        if (self._filtro_protocolo and
                self._filtro_protocolo != "Todos" and
                dados.get("tipo", "").upper() != self._filtro_protocolo.upper()):
            return False
        if self._filtro_texto:
            campos = " ".join([
                dados.get("ip_envolvido", ""),
                dados.get("ip_destino", ""),
                dados.get("titulo", ""),
                dados.get("nivel1", ""),
                dados.get("tipo", ""),
            ]).lower()
            if self._filtro_texto not in campos:
                return False
        return True

    def _reaplicar_filtros(self):
        while self._layout_cartoes.count() > 1:
            item = self._layout_cartoes.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._eventos_filtrados = [
            e for e in self._todos_eventos if self._passa_filtro(e)
        ]
        for evento in self._eventos_filtrados:
            self._adicionar_cartao(evento)
        self._atualizar_rodape()
        if self._eventos_filtrados:
            self._evento_atual = self._eventos_filtrados[-1]
            self._renderizar_explicacao()
        else:
            self._evento_atual = {}
            self._exibir_boas_vindas()

    def _atualizar_rodape(self):
        total    = len(self._todos_eventos)
        visiveis = len(self._eventos_filtrados)
        sessao   = self._evento_atual.get("sessao_id", "sessao_default") if self._evento_atual else None
        extra    = ""
        if sessao and sessao in self._contagem_sessao:
            resumo = ", ".join(
                f"{k}:{v}" for k, v in sorted(self._contagem_sessao[sessao].items())
            )
            extra = f" | Sessão {sessao}: {resumo}"
        if total == visiveis:
            self.lbl_rodape.setText(f"{total} evento(s) registrado(s).{extra}")
        else:
            self.lbl_rodape.setText(
                f"{visiveis} exibido(s) de {total} total "
                f"(filtro ativo).{extra}"
            )

    # ──────────────────────────────────────────────
    # Cartões e renderização
    # ──────────────────────────────────────────────

    def _adicionar_cartao(self, dados: dict):
        cartao = CartaoEvento(dados)
        dados_ref = dados
        cartao.mousePressEvent = lambda _: self._ao_clicar_cartao(dados_ref)

        pos = self._layout_cartoes.count() - 1
        self._layout_cartoes.insertWidget(pos, cartao)

        barra = self._scroll.verticalScrollBar()
        barra.setValue(barra.maximum())

    def _ao_clicar_cartao(self, dados: dict):
        self._evento_atual = dados
        self._renderizar_explicacao()

    def _trocar_nivel(self, nivel: int):
        """
        Troca o nível de explicação exibido.
        O nível 3 (Pacote Bruto) só exibe conteúdo se o evento for HTTP.
        """
        self._nivel_atual = nivel
        for i, btn in enumerate(self.botoes_nivel):
            btn.setChecked(i == nivel)
        if self._evento_atual:
            self._renderizar_explicacao()

    def _renderizar_explicacao(self):
        """Constrói o HTML da explicação para o evento atual no nível selecionado."""
        if not self._evento_atual or not self._evento_atual.get("titulo"):
            return

        e       = self._evento_atual
        titulo  = e.get("titulo", "Evento")
        nivel   = e.get("nivel", "INFO")
        hora    = e.get("timestamp", "")
        ip_src  = e.get("ip_envolvido", "")
        ip_dst  = e.get("ip_destino", "")
        cont    = e.get("contador", 1)
        cont_s  = e.get("contador_sessao", cont)
        fluxo   = e.get("fluxo_visual", "")
        alerta  = e.get("alerta_seguranca", "")

        estilo = ESTILOS_NIVEL.get(nivel, ESTILOS_NIVEL["INFO"])
        cor    = estilo["borda"]

        # Selecionar conteúdo pelo nível ativo (3 níveis)
        chaves_nivel = ["nivel1", "nivel2", "nivel4"]
        rotulo       = ROTULOS_NIVEL[self._nivel_atual]

        # Nível 3 (Pacote Bruto): só disponível para HTTP
        if self._nivel_atual == 2:
            conteudo = e.get("nivel4", "")
            if not conteudo:
                conteudo = (
                    "<div style='text-align:center;padding:40px;color:#7f8c8d;'>"
                    "<b>Pacote Bruto</b> está disponível apenas para eventos HTTP.<br><br>"
                    "Acesse um site HTTP (porta 80) e envie um formulário para "
                    "visualizar o conteúdo exato do pacote como trafegou na rede."
                    "</div>"
                )
        else:
            conteudo = e.get(chaves_nivel[self._nivel_atual], "Indisponível.")

        # Linha de IPs
        ip_linha = ip_src
        if ip_dst and ip_dst != ip_src:
            ip_linha += f" → {ip_dst}"

        # Bloco de fluxo visual
        bloco_fluxo = ""
        if fluxo:
            bloco_fluxo = (
                f"<div style='font-family:Consolas;font-size:11px;"
                f"background:#0d1520;padding:8px 14px;"
                f"border-radius:5px;color:#ecf0f1;margin:8px 0;"
                f"border-left:3px solid {cor};'>"
                f"{fluxo}</div>"
            )

        # Bloco de alerta de segurança
        bloco_alerta = ""
        if alerta:
            bloco_alerta = (
                f"<div style='background:#2a0a00;border:1px solid #E74C3C;"
                f"border-radius:5px;padding:10px 14px;margin:8px 0;'>"
                f"<b style='color:#E74C3C;'>ALERTA DE SEGURANÇA:</b><br>"
                f"<span style='color:#ecf0f1;'>{alerta}</span>"
                f"</div>"
            )

        html = f"""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;">

          <h3 style="color:{cor};margin:0 0 4px 0;">{titulo}</h3>

          <p style="color:#7f8c8d;font-size:10px;margin:0 0 10px 0;">
            🕐 {hora} &nbsp;·&nbsp;
            <code style="color:#3498DB;">{ip_linha}</code>
            &nbsp;·&nbsp; Ocorrências: <b>{cont}</b>
            &nbsp;·&nbsp; Nesta sessão: <b>{cont_s}</b>
          </p>

          {bloco_fluxo}
          {bloco_alerta}

          <div style="background:#0d1520;border-left:3px solid {cor};
                      border-radius:4px;padding:12px 16px;margin:8px 0;">
            <b style="color:{cor};font-size:10px;">
              {rotulo[0]} {rotulo[1]} — {rotulo[2]}
            </b><br><br>
            {conteudo}
          </div>

        </div>
        """
        self.texto_explicacao.setHtml(html)

    def _exibir_boas_vindas(self):
        self.texto_explicacao.setHtml("""
        <div style="font-family:Arial,sans-serif;font-size:11px;
                    line-height:1.7;color:#ecf0f1;padding:4px;">

          <h3 style="color:#3498DB;margin:0 0 10px 0;">
            👋 Bem-vindo ao Modo Análise
          </h3>

          <p>Este painel transforma pacotes reais capturados da rede em
          <b>explicações didáticas automáticas</b> em três níveis de
          profundidade.</p>

          <p><b>Como usar:</b><br>
          1. Clique em <b>Iniciar Captura</b> na barra superior<br>
          2. Acesse sites no navegador para gerar tráfego<br>
          3. Os eventos aparecerão aqui automaticamente<br>
          4. Clique em qualquer evento para ver a explicação<br>
          5. Use os botões abaixo para trocar o nível de detalhe</p>

          <p><b>Os três níveis de explicação:</b><br>
          <b>Simples</b> — linguagem do dia a dia, sem jargão<br><b>Técnico</b> — protocolos, portas, vulnerabilidades<br><b>Pacote Bruto</b> — conteúdo exato como trafegou na rede (exclusivo para HTTP), com destaques de campos e riscos
          </p>

          <p><b>Demonstração em sala de aula:</b><br>
          Execute o <code>servidor_teste_http.py</code>, acesse de outro
          dispositivo, envie o formulário de login e observe as credenciais
          aparecendo em texto puro no nível "Pacote Bruto".</p>

          <p style="color:#7f8c8d;font-size:10px;">
            Explore a aba <b>Protocolos</b> para ver as diferenças
            entre HTTP/HTTPS, TCP/UDP e o fluxo completo de uma requisição web.
          </p>
        </div>
        """)






