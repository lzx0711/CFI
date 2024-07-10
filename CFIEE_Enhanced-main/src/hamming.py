'''
Author: Taurus052
Date: 2024-04-24 10:04:10
LastEditTime: 2024-05-17 15:50:24
'''
import networkx as nx

def hamming_distance(s1, s2):
    # 计算两个字符串之间的汉明距离
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))

def generate_binary_strings(n):
    # 生成所有可能的n位二进制字符串
    return [format(i, '0' + str(n) + 'b') for i in range(2**n)]

def build_hamming_graph(n, HD):
    binary_strings = generate_binary_strings(n)
    n_graph = nx.DiGraph()
    # graph = {s: [] for s in binary_strings}
    
    for s1 in binary_strings:
        for s2 in binary_strings:
            if hamming_distance(s1, s2) == HD:
                n_graph.add_edge(s1,s2)
                n_graph.nodes[s1]['hamming_code'] = s1
                n_graph.nodes[s1]['level'] = s1.count('1') 
                n_graph.nodes[s1]['used'] = False
                n_graph.nodes[s2]['hamming_code'] = s2
                n_graph.nodes[s2]['level'] = s2.count('1')
                n_graph.nodes[s2]['used'] = False
                
                # Add neighbors
                if 'neighbors' not in n_graph.nodes[s1]:
                    n_graph.nodes[s1]['neighbors'] = []
                if 'neighbors' not in n_graph.nodes[s2]:
                    n_graph.nodes[s2]['neighbors'] = []
                if s2 not in n_graph.nodes[s1]['neighbors']:
                    n_graph.nodes[s1]['neighbors'].append(s2)
                if s1 not in n_graph.nodes[s2]['neighbors']:
                    n_graph.nodes[s2]['neighbors'].append(s1)
    return n_graph

def print_hamming_graph(graph):
    nodes = sorted(graph.nodes(data=True), key=lambda x: x[1]['level'])
    for node, data in nodes:
        children = [edge[1] for edge in graph.edges(node) if int(edge[1], 2) > int(node, 2)]
        print(node, '->', ', '.join(children))
        num_nodes = graph.number_of_nodes()
    print('Number of H nodes:', num_nodes)
    return num_nodes

# def separate_H_subgraphs(graph):
#     # 将H分解为节点与两个邻接节点的子图
    

# 测试
# graph = build_hamming_graph(3)
# print_hamming_graph(graph)