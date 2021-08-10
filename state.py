from hurst import compute_Hc
from console import Console
from scapy.all import *


def list2coords(l: list, mul=1):
    return [{'x': ind + mul, 'y': val} for ind, val in enumerate(l)]


class State:
    def __init__(self):
        self.cons = Console()
        self.size = 200
        self.num = 0

        self.hurst_memo = []
        self.lens = []
        self.ats = []
        self.at = 0
        self.queue = []
        self.attack_name = ''

        self.t = AsyncSniffer(prn=self.pkt_callback)

        self.t.start()

    def get_hurst(self, l, pos):
        if len(self.hurst_memo) > pos:
            return self.hurst_memo[pos]
        if pos != len(self.hurst_memo):
            print(pos)
            self.get_hurst(l, pos-1)

        h = compute_Hc(l[pos:pos + self.size])[0] * 0.7
        s = sum(self.ats[pos:pos + self.size])
        if s < self.size/2:
            h = 1 - h
        elif self.attack_name != '':
            self.cons.lines.append(self.attack_name)
            self.attack_name = ''

        self.hurst_memo.append(h)
        return self.hurst_memo[-1]

    def get_hurst_list(self, l: list):
        return [self.get_hurst(l, pos) for pos in range(0, len(l) - self.size) if len(l[pos:pos + self.size]) > self.size - 2]

    def pkt_callback(self, pkt: Packet):
        lens = self.lens
        self.num += 1
        num = self.num
        print(num, self.at)
        try:
            if IPv6 in pkt:
                lens.append(pkt[IPv6].plen)
                self.ats.append(self.at)
            elif IP in pkt:
                lens.append(pkt[IP].len)
                self.ats.append(self.at)
            else:
                pkt.show()
            # print(len(lens), lens[-1])
        except:
            pkt.show()

    def data(self):
        res = self.lens
        h = self.get_hurst_list(res)
        h1 = [0.5 for _ in h]

        if len(self.queue) > 0:
            self.cons.lines.append(self.queue[0])
            self.queue.pop(0)
            if len(self.queue) == 0:
                self.at = 0

        return {
                'lengths': list2coords(res),
                'hurst': list2coords(h, self.size),
                'mean_hurst': list2coords(h1, self.size),
                'console': self.cons.data(),
                'addresses': []
        }

    def set_size(self, size):
        self.size = max(size, 100)
        self.hurst_memo = []

    def set_attack(self, attack_name: str):
        self.at = 1
        self.attack_name = attack_name

    def set_solution(self, solution_id):
        with open(f'solutions/{solution_id}.sol', 'r', encoding='utf-8') as file:
            for line in file.readlines():
                self.queue.append(line)
