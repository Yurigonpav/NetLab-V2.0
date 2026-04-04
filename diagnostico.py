# diagnostico.py
# Ferramenta completa de diagnóstico para o NetLab Educacional.
# Testa:
#   1. Captura de pacotes em todas as interfaces de rede.
#   2. Funcionamento do AnalisadorPacotes (modo síncrono e assíncrono).
#   3. Geração de eventos (HTTP, HTTPS, DNS, TCP_SYN, etc.).
#   4. Compatibilidade dos eventos com o painel_eventos (campos obrigatórios).
#   5. Fluxo de filas (entrada, saída, timer de consumo).
# Execute como Administrador para testes de captura real.

import sys
import time
import logging
from collections import defaultdict

# Desativa logs verbosos do Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)

# Tenta importar o AnalisadorPacotes (se disponível)
try:
    from analisador_pacotes import AnalisadorPacotes
    ANALISADOR_DISPONIVEL = True
except ImportError:
    ANALISADOR_DISPONIVEL = False
    print("[!] analisador_pacotes.py não encontrado. Testes de analisador serão simulados.\n")

# Tenta importar Scapy para captura real
try:
    from scapy.all import get_if_list, AsyncSniffer, conf
    conf.verb = 0
    conf.use_pcap = True
    SCAPY_DISPONIVEL = True
except ImportError:
    SCAPY_DISPONIVEL = False
    print("[!] Scapy não instalado. Testes de interface serão ignorados.\n")

# ============================================================
# UTILITÁRIOS
# ============================================================

def print_secao(titulo):
    print("\n" + "=" * 70)
    print(f" {titulo}")
    print("=" * 70)

def print_ok(msg):
    print(f"✅ {msg}")

def print_falha(msg):
    print(f"❌ {msg}")

def print_info(msg):
    print(f"🔍 {msg}")

# ============================================================
# TESTE 1: INTERFACES DE REDE (original melhorado)
# ============================================================

def testar_interfaces():
    if not SCAPY_DISPONIVEL:
        print_info("Scapy não disponível. Pule teste de interfaces.")
        return []

    print_secao("1. TESTE DE INTERFACES DE REDE")
    interfaces = get_if_list()
    print(f"{len(interfaces)} interface(s) encontrada(s).\n")
    print("Testando cada interface por 4 segundos...")
    print("(Abra um site no navegador durante os testes)\n")

    ativas = []
    for i, iface in enumerate(interfaces):
        print(f"[{i}] Testando: {iface} ... ", end="", flush=True)
        try:
            sniffer = AsyncSniffer(iface=iface, store=True, quiet=True)
            sniffer.start()
            time.sleep(4)
            sniffer.stop()
            qtd = len(sniffer.results) if sniffer.results else 0
            if qtd > 0:
                print_ok(f"{qtd} pacotes — INTERFACE ATIVA")
                ativas.append((i, iface, qtd))
            else:
                print_falha("0 pacotes — inativa/sem tráfego")
        except Exception as e:
            print_falha(f"Erro: {e}")

    return ativas

# ============================================================
# TESTE 2: ANALISADOR DE PACOTES (síncrono e assíncrono)
# ============================================================

def gerar_pacote_teste(tipo, **kwargs):
    """Gera um dicionário de pacote simulado para teste."""
    base = {
        "protocolo": "TCP",
        "ip_origem": "192.168.1.100",
        "ip_destino": "192.168.1.1",
        "porta_origem": 12345,
        "porta_destino": 80,
        "tamanho": 150,
        "payload": b"",
    }
    if tipo == "HTTP":
        base.update({
            "protocolo": "TCP",
            "porta_destino": 80,
            "payload": b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        })
    elif tipo == "HTTP_POST":
        base.update({
            "protocolo": "TCP",
            "porta_destino": 8080,
            "payload": b"POST /login HTTP/1.1\r\nHost: test.com\r\n\r\nuser=admin&pass=123",
        })
    elif tipo == "HTTPS":
        base.update({
            "protocolo": "TCP",
            "porta_destino": 443,
            "payload": b"\x16\x03\x01\x02\x00...",  # simula TLS ClientHello
        })
    elif tipo == "DNS":
        base.update({
            "protocolo": "DNS",
            "dominio": "google.com",
            "tamanho": 80,
        })
    elif tipo == "TCP_SYN":
        base.update({
            "protocolo": "TCP",
            "flags": "SYN",
            "payload": b"",
        })
    elif tipo == "ICMP":
        base.update({
            "protocolo": "ICMP",
        })
    elif tipo == "ARP":
        base.update({
            "protocolo": "ARP",
            "mac_origem": "aa:bb:cc:dd:ee:ff",
        })
    # Sobrescreve com kwargs
    base.update(kwargs)
    return base

def testar_analisador_sincrono():
    print_secao("2. TESTE DO ANALISADOR (MODO SÍNCRONO)")
    if not ANALISADOR_DISPONIVEL:
        print_falha("AnalisadorPacotes não disponível. Pule teste.")
        return

    analisador = AnalisadorPacotes()
    tipos_teste = ["HTTP", "HTTP_POST", "HTTPS", "DNS", "TCP_SYN", "ICMP", "ARP"]
    resultados = {}

    for tipo in tipos_teste:
        pacote = gerar_pacote_teste(tipo)
        evento = analisador.processar_pacote(pacote)
        if evento:
            print_ok(f"{tipo} → evento: {evento.get('tipo')}")
            resultados[tipo] = evento
        else:
            print_falha(f"{tipo} → nenhum evento gerado")

    # Verifica estatísticas
    stats = analisador.obter_estatisticas_protocolos()
    print_info(f"Estatísticas: {stats}")
    return resultados

def testar_analisador_assincrono():
    print_secao("3. TESTE DO ANALISADOR (MODO ASSÍNCRONO + FILAS)")
    if not ANALISADOR_DISPONIVEL:
        print_falha("AnalisadorPacotes não disponível. Pule teste.")
        return

    analisador = AnalisadorPacotes()
    analisador.iniciar_thread()

    # Enfileira alguns pacotes
    pacotes = [
        gerar_pacote_teste("HTTP"),
        gerar_pacote_teste("DNS"),
        gerar_pacote_teste("TCP_SYN"),
        gerar_pacote_teste("HTTPS"),
    ]
    for p in pacotes:
        analisador.enfileirar(p)
        print_info(f"Enfileirado: {p.get('protocolo')}")

    # Aguarda processamento
    time.sleep(0.5)

    # Coleta resultados (simula timer da UI)
    eventos, _ = analisador.coletar_resultados()
    print_info(f"Eventos coletados da fila: {len(eventos)}")
    for ev in eventos:
        print_ok(f"  - {ev.get('tipo')} de {ev.get('ip_origem')}")

    analisador.parar_thread()
    return eventos

# ============================================================
# TESTE 4: COMPATIBILIDADE COM PAINEL_EVENTOS
# ============================================================

def testar_compatibilidade_painel(eventos):
    print_secao("4. COMPATIBILIDADE COM PAINEL_EVENTOS")
    if not eventos:
        print_info("Nenhum evento para testar compatibilidade.")
        return

    # Campos obrigatórios que o painel_eventos espera
    campos_obrigatorios = [
        "tipo", "titulo", "nivel1", "nivel2", "nivel4", "timestamp",
        "ip_envolvido", "alerta_seguranca", "fluxo_visual"
    ]
    campos_opcionais = ["ip_destino", "porta_origem", "porta_destino", "dominio"]

    for i, ev in enumerate(eventos):
        print_info(f"Evento {i+1}: {ev.get('tipo')}")
        faltam = [c for c in campos_obrigatorios if c not in ev]
        if faltam:
            print_falha(f"  Campos ausentes: {faltam}")
        else:
            print_ok("  Todos os campos obrigatórios presentes")

        # Verifica conteúdo mínimo
        if ev.get("nivel4") and "pacote bruto" in ev.get("nivel4", "").lower():
            print_ok("  Nível 'Pacote Bruto' preenchido")
        else:
            print_info("  Nível 'Pacote Bruto' pode estar vazio (ok para não-HTTP)")

# ============================================================
# TESTE 5: SIMULAÇÃO DO TIMER DA UI (CONSUMO DE FILA)
# ============================================================

def simular_timer_ui():
    print_secao("5. SIMULAÇÃO DO TIMER DA UI (LEITURA PERIÓDICA)")
    if not ANALISADOR_DISPONIVEL:
        print_falha("Analisador não disponível.")
        return

    analisador = AnalisadorPacotes()
    analisador.iniciar_thread()

    # Enfileira 10 pacotes variados
    for i in range(10):
        tipo = ["HTTP", "DNS", "TCP_SYN"][i % 3]
        analisador.enfileirar(gerar_pacote_teste(tipo))
    print_info("10 pacotes enfileirados.")

    # Simula timer lendo a cada 100ms, 5 vezes
    total_eventos = 0
    for _ in range(5):
        time.sleep(0.1)
        eventos, _ = analisador.coletar_resultados()
        total_eventos += len(eventos)
        print_info(f"  Leitura: {len(eventos)} eventos (total acumulado: {total_eventos})")

    analisador.parar_thread()
    if total_eventos == 10:
        print_ok("Timer leu todos os eventos corretamente.")
    else:
        print_falha(f"Timer leu apenas {total_eventos} de 10 eventos. Verifique tamanho da fila ou atrasos.")

# ============================================================
# FUNÇÃO PRINCIPAL
# ============================================================

def main():
    print("=" * 70)
    print(" DIAGNÓSTICO COMPLETO - NETLAB EDUCACIONAL")
    print("=" * 70)

    # 1. Interfaces
    interfaces_ativas = testar_interfaces()

    # 2. Analisador síncrono
    eventos_sinc = testar_analisador_sincrono()

    # 3. Analisador assíncrono
    eventos_assinc = testar_analisador_assincrono()

    # 4. Compatibilidade
    testar_compatibilidade_painel(eventos_sinc.values() if eventos_sinc else [])

    # 5. Simulação do timer
    simular_timer_ui()

    # Relatório final
    print_secao("RELATÓRIO FINAL")
    if interfaces_ativas:
        print_ok("✓ Captura de rede: pelo menos uma interface ativa.")
        print("  Use a interface com maior número de pacotes no NetLab.")
    else:
        print_falha("✗ Nenhuma interface capturou pacotes. Verifique Npcap e permissões de Admin.")

    if ANALISADOR_DISPONIVEL:
        if eventos_sinc:
            print_ok("✓ Analisador síncrono gera eventos corretamente.")
        else:
            print_falha("✗ Analisador síncrono falhou em gerar eventos.")

        if eventos_assinc:
            print_ok("✓ Analisador assíncrono (thread + filas) funciona.")
        else:
            print_falha("✗ Analisador assíncrono não produziu eventos.")

    print("\n📌 PRÓXIMOS PASSOS:")
    print("  1. Se o analisador funciona mas o NetLab não exibe eventos,")
    print("     verifique se o QTimer da UI está chamando coletar_resultados().")
    print("  2. Confira se os filtros do painel_eventos não estão ocultando eventos.")
    print("  3. Adicione logs no método _consumir_fila da janela principal.")
    print("  4. Execute o NetLab no terminal para ver mensagens de erro.")

    input("\nPressione Enter para sair...")

if __name__ == "__main__":
    main()