from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
from ryu.lib import hub
import time

# --- Módulos para os gráficos ---
import matplotlib
matplotlib.use('Agg') # Modo não-interativo, essencial para rodar em background
import matplotlib.pyplot as plt
import numpy as np

class FirewallWithGraphs(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallWithGraphs, self).__init__(*args, **kwargs)
        # Lógica de Switch
        self.mac_to_port = {}
        # Lógica de Firewall
        self.blocked_pairs = [("10.0.0.1", "10.0.0.2")]
        # Dicionário para guardar os switches (datapaths) conectados
        self.datapaths = {}
        # Listas para guardar os dados para os gráficos
        self.tempos_resposta = []
        self.pacotes_bloqueados_total = 0

        # Inicia uma "thread" em segundo plano para monitorar as estatísticas
        self.monitor_thread = hub.spawn(self._monitor)

    def stop(self):
        """
        Este método é chamado quando o Ryu é finalizado (com Ctrl+C).
        É o lugar para gerar nossos gráficos.
        """
        self.logger.info("Ryu está parando. Gerando gráficos e salvando dados...")
        hub.kill(self.monitor_thread) # Para a thread de monitoramento
        self._generate_graphs_and_data()

    def _monitor(self):
        """
        Um loop que roda em segundo plano, pedindo estatísticas aos switches a cada 10s.
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10) # Espera 10 segundos

    def _request_stats(self, datapath):
        """
        Pede as estatísticas de fluxo (flow stats) para um switch.
        """
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _generate_graphs_and_data(self):
        """
        Usa o Matplotlib e Numpy para criar os arquivos de saída.
        """
        # --- Gráfico de Tempo de Resposta ---
        plt.figure(figsize=(10, 5))
        plt.plot(self.tempos_resposta, marker='o', color='blue')
        plt.title('Tempo de Processamento do Controlador (ms)')
        plt.xlabel('Evento de Packet-In')
        plt.ylabel('Tempo (ms)')
        plt.grid(True)
        # Salva a imagem em um arquivo em vez de tentar mostrá-la
        plt.savefig('grafico_tempo_resposta.png')
        self.logger.info("Gráfico 'grafico_tempo_resposta.png' salvo.")
        plt.close() # Libera a memória da figura

        # --- Salvando os dados em CSV ---
        # Como pacotes bloqueados agora é um único valor, salvamos apenas o tempo de resposta
        np.savetxt('dados_tempo_resposta.csv', self.tempos_resposta, delimiter=',', fmt='%.4f')
        self.logger.info("Dados de tempo de resposta salvos em 'dados_tempo_resposta.csv'.")
        self.logger.info(f"Total de pacotes bloqueados (contados pelas regras): {self.pacotes_bloqueados_total}")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        Mantém a lista de switches conectados atualizada.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('Switch %s conectado.', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('Switch %s desconectado.', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Recebe as estatísticas do switch e conta os pacotes bloqueados.
        """
        body = ev.msg.body
        # Filtra as estatísticas para encontrar apenas as nossas regras de DROP (ação vazia)
        self.pacotes_bloqueados_total = sum(flow.packet_count for flow in body if not flow.instructions)
        # Nota: este é o total acumulado, não uma série temporal.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        for src, dst in self.blocked_pairs:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst)
            self.add_flow(datapath, 10, match, [])
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=dst, ipv4_dst=src)
            self.add_flow(datapath, 10, match, [])

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        start_time = time.time() # Marca o tempo de início

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, match=msg.match, actions=actions, data=data)
        datapath.send_msg(out)

        # Calcula o tempo de processamento e guarda na lista
        end_time = time.time()
        processing_time_ms = (end_time - start_time) * 1000
        self.tempos_resposta.append(processing_time_ms)
