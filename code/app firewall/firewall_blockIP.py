from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
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
        self.mac_to_port = {}
        
        # LISTA DE BLOQUEIO:
        self.blocked_pairs = [("10.0.0.1", "10.0.0.2")] 
        
        # Variáveis para os gráficos
        self.tempos_resposta = []
        self.pacotes_bloqueados_total = 0
        self.dados_bloqueio_temporal = [] # Guarda tuplas (timestamp, contagem)
        self.start_time = time.time() # Para o eixo X do gráfico

        self.logger.info("--- FIREWALL REATIVO (ABORDAGEM MANUAL) INICIADO ---")
        self.logger.info(f"Pares de IP a serem bloqueados: {self.blocked_pairs}")

    def stop(self):
        """
        Este método é chamado quando o Ryu é finalizado (com Ctrl+C).
        """
        self.logger.info("Ryu está parando. Gerando gráficos e salvando dados...")
        self._generate_graphs_and_data()

    def _generate_graphs_and_data(self):
        """
        Usa o Matplotlib para criar os arquivos de saída.
        """
        # --- Gráfico de Tempo de Resposta ---
        if self.tempos_resposta:
            plt.figure(figsize=(10, 5))
            plt.plot(self.tempos_resposta, marker='o', color='blue')
            plt.title('Tempo de Processamento do Controlador (ms)')
            plt.xlabel('Evento de Packet-In')
            plt.ylabel('Tempo (ms)')
            plt.grid(True)
            plt.savefig('grafico_tempo_resposta.png')
            self.logger.info("Gráfico 'grafico_tempo_resposta.png' salvo.")
            plt.close()
            np.savetxt('dados_tempo_resposta.csv', self.tempos_resposta, delimiter=',', fmt='%.4f')
            self.logger.info("Dados de tempo de resposta salvos em 'dados_tempo_resposta.csv'.")
        else:
            self.logger.info("Nenhum dado de tempo de resposta para gerar gráfico.")

        # --- Gráfico de Pacotes Bloqueados ---
        if self.dados_bloqueio_temporal:
            tempos, contagens = zip(*self.dados_bloqueio_temporal)
            plt.figure(figsize=(10, 5))
            plt.plot(tempos, contagens, marker='x', color='red', drawstyle='steps-post')
            plt.title('Total de Pacotes Bloqueados ao Longo do Tempo')
            plt.xlabel('Tempo desde o início (s)')
            plt.ylabel('Número de Pacotes Bloqueados')
            plt.grid(True)
            plt.savefig('grafico_pacotes_bloqueados.png')
            self.logger.info("Gráfico 'grafico_pacotes_bloqueados.png' salvo.")
            plt.close()
        else:
            self.logger.info("Nenhum dado de pacotes bloqueados para gerar o gráfico.")

        self.logger.info(f"TOTAL FINAL DE PACOTES BLOQUEADOS: {self.pacotes_bloqueados_total}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # ÚNICA REGRA: envia pacotes sem regra para o controlador (prioridade baixa).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch %s conectado. Regra de table-miss instalada.", datapath.id)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        processing_start_time = time.time()

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            ip_src = pkt_ipv4.src
            ip_dst = pkt_ipv4.dst
            
            if (ip_src, ip_dst) in self.blocked_pairs or (ip_dst, ip_src) in self.blocked_pairs:
                self.pacotes_bloqueados_total += 1
                current_time = time.time() - self.start_time
                self.dados_bloqueio_temporal.append((current_time, self.pacotes_bloqueados_total))
                
                self.logger.warning(
                    f"PACOTE BLOQUEADO: {ip_src} -> {ip_dst}. Total: {self.pacotes_bloqueados_total}"
                )
                return 
        
        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            # --- CÓDIGO CORRIGIDO ---
            # Criamos os campos do match em um dicionário primeiro
            match_fields = {
                'in_port': in_port,
                'eth_dst': dst_mac,
                'eth_type': eth.ethertype
            }
            # Se for um pacote IPv4, adicionamos os IPs ao dicionário
            if pkt_ipv4:
                match_fields['ipv4_src'] = pkt_ipv4.src
                match_fields['ipv4_dst'] = pkt_ipv4.dst
            
            # Criamos o objeto Match de uma só vez com todos os campos
            match = parser.OFPMatch(**match_fields)
            self.add_flow(datapath, 1, match, actions)
            # --- FIM DA CORREÇÃO ---

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=msg.match, actions=actions, data=data)
        datapath.send_msg(out)

        processing_end_time = time.time()
        processing_time_ms = (processing_end_time - processing_start_time) * 1000
        self.tempos_resposta.append(processing_time_ms)