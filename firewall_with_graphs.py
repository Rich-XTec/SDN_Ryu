from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
import matplotlib.pyplot as plt
import numpy as np

#Dados virtuais para referencia
tempos_resposta = [Tempo, 0.5, 0.7, 0.4, 0.6, 0.8, 0.9, 0.3, 0.4]  # em milissegundos
pacotes_bloqueados = [Pacotes Bloqueados, 1, 3, 5, 6, 8, 9, 10, 12]

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSION = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.blocked_pairs = [("10.0.0.1", "10.0.0.2")]  # lista de IPs bloqueados

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Regra default: encaminhar ao controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Adiciona regras de bloqueio
        for src, dst in self.blocked_pairs:
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src, ipv4_dst=dst)
            self.add_flow(datapath, 10, match, [])  # sem ação = DROP

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

# Criando dois gráficos lado a lado
fig, axs = plt.subplots(1, 2, figsize=(12, 5))

# Gráfico 1: Pacotes bloqueados ao longo do tempo
axs[0].plot(pacotes_bloqueados, marker='o', color='red')
axs[0].set_title('Pacotes Bloqueados')
axs[0].set_xlabel('Instante de Coleta')
axs[0].set_ylabel('Quantidade de Pacotes')

# Gráfico 2: Tempo de resposta médio ao longo do tempo
axs[1].plot(tempos_resposta, marker='x', color='blue')
axs[1].set_title('Tempo de Resposta (ms)')
axs[1].set_xlabel('Instante de Coleta')
axs[1].set_ylabel('Tempo (ms)')

np.savetxt('scores.csv', [p for p in zip(pacotes_bloqueados, tempos_resposta)], delimiter=',', fmt='%s')
plt.tight_layout()
plt.show()
