# -*- coding:utf-8 -*-
import pymetis, schedule, time
from random import choice
import random
from TargetNetwork import LoadTargetNetwork
from pyspark import SparkContext,SparkConf
# def LoadTargetNetwork():
#     Hostnum = 8
#     ConditionLines = []
#     NetworkHostLines = []
#     VulnerabilityLines = []
#     SoftwareApplicationLines = []
#     Access = ['FileAccess', 'User', 'Root']
#     SoftwareApplicationName = ['MS Windows 7 gold', 'MS Outlook 2007', 'MS Office 2010', 'MS Internet Explorer 10']
#
#     for i in range(Hostnum):
#         Condition = ['cpe:/' + str(i + 1), choice(Access), (i + 1)]  # for example: ['cpe:/1', 'Root', '1']
#         # cpeid authority hostid
#         ConditionLines.append(Condition)
#
#     for i in range(Hostnum):
#
#         if ((i + 1) == Hostnum):
#             Vulnerability = ['CVE-' + str(i + 1), ConditionLines[i], ConditionLines[0]]
#         else:
#             # x = random.randrange(Hostnum)
#             # if (x == i):
#             #     x = i + 1
#             Vulnerability = ['CVE-' + str(i + 1), ConditionLines[i], ConditionLines[i + 1]]
#
#         # CVEId precondition postcondition
#         VulnerabilityLines.append(Vulnerability)
#
#     for i in range(Hostnum):
#         # if i == 0:
#         #   SoftwareApplication = ['SoftwareApplication:' + choice(SoftwareApplicationName), 'port',VulnerabilityLines[0]]
#         # else:
#         SoftwareApplication = [choice(SoftwareApplicationName), 'port', VulnerabilityLines[i]]
#         SoftwareApplicationLines.append(SoftwareApplication)
#
#     # ['SoftwareApplication:MS Office 2010', 'port', ['Vulnerability:CVE-1', precondition, postcondition]]
#
#     for i in range(Hostnum):
#         NetworkHost = [(i + 1), str(i + 1) + '.62.2.22', SoftwareApplicationLines[i]]
#         # print NetworkHost[0]
#         NetworkHostLines.append(NetworkHost)
#     # example:['1.62.2.22', ['SoftwareApplication:MS Office 2010', 'port',
#     # ['Vulnerability:CVE-1', ['cpe:/1', 'User', '1'], ['cpe:/2', 'Root', '2']]]]
#
#     # Communication = [[0, 1, 1, 1, 1, 1, 1, 1],  # 1
#     #                  [1, 0, 1, 1, 1, 1, 1, 1],  # 2
#     #                  [0, 0, 0, 1, 1, 1, 1, 1],  # 3
#     #                  [0, 0, 1, 0, 1, 1, 1, 1],  # 4
#     #                  [0, 0, 0, 0, 0, 1, 1, 1],  # 5
#     #                  [0, 0, 0, 0, 1, 0, 1, 1],  # 6
#     #                  [0, 0, 0, 0, 0, 0, 0, 1],  # 7
#     #                  [0, 0, 0, 0, 0, 0, 1, 0]  # 8
#     #                  ]
#
#     # Communication = [[0, 1, 0, 0, 0, 1, 0, 0],  # 1
#     #                  [1, 0, 1, 0, 0, 0, 1, 0],  # 2
#     #                  [0, 1, 0, 1, 0, 0, 0, 0],  # 3
#     #                  [0, 0, 1, 0, 1, 0, 1, 0],  # 4
#     #                  [0, 0, 0, 1, 0, 1, 0, 1],  # 5
#     #                  [1, 0, 0, 0, 1, 0, 1, 1],  # 6
#     #                  [0, 1, 0, 1, 0, 1, 0, 1],  # 7
#     #                  [0, 0, 0, 0, 1, 1, 1, 0]  # 8
#     #                  ]
#
#     # adjancy = [[1, 5],
#     #             [0, 2, 6],
#     #             [1, 3],
#     #             [2, 4, 6],
#     #            [3, 5, 7],
#     #            [0, 4, 6, 7],
#     #            [1, 3, 5, 7],
#     #            [4, 5, 6]
#     #             ]
#
#     Communication = [[0 for i in range(Hostnum)] for i in range(Hostnum)]
#
#     for i in range(Hostnum):
#         for j in range(Hostnum):
#             if ((j == (i + 1)) or (j == (i - 1))):
#                 Communication[i][j] = 1
#                 Communication[j][i] = 1
#             elif (i != j):
#                 x = random.randrange(2)
#                 Communication[i][j] = x
#                 Communication[j][i] = x
#
#     adjancy = []
#     for i in Communication:
#         list = []
#         num = 0
#         for j in i:
#             if (j == 1):
#                 list.append(num)
#             num = num + 1
#         adjancy.append(list)
#
#     TargetNetwork = [NetworkHostLines, Communication, adjancy]
#
#     return TargetNetwork

# class AttackGraphNode(object):
#     Hostname = ''
#     IPAddress = ''
#     CVEId = ''
#     SoftwareApplicationName = ''
#     Attacker = 0
#     Viticm = 0
#
# class AttackGraphEdge(object):
#     SourceHost = 0
#     TargetHost = 0
#
# class AttackGraph(object):
#     node = AttackGraphNode
#     edge = AttackGraphEdge
def Duplicate(ids):
    news_ids = []
    for id in ids:
        if id not in news_ids:
            news_ids.append(id)
    return news_ids

def Exploit(host):
    #[5, '5.62.2.22', ['MS Internet Explorer 10', 'port', ['CVE-5', ['cpe:/5', 'Root', 5], [['cpe:/6', 'Root', 6], ['cpe:/7', 'FileAccess', 7], ['cpe:/8', 'FileAccess', 8]]]]]
    node = []
    #Hostname
    #node.Hostname = 'Host ' + str(host[0])
    node.append('Host ' + str(host[0]))
    #IPAddress
    #node.IPAddress = 'IPAddress: ' + host[1]
    node.append('IPAddress: ' + host[1])
    #CVEId
    #node.CVEId = 'CVEId: ' + host[2][2][0]
    node.append('CVEId: ' + host[2][2][0])
    #SoftwareApplicationName
    #node.SoftwareApplicationName = 'SoftwareApplicationName: ' + host[2][0]
    node.append('SoftwareApplicationName: ' + host[2][0])
    #AttackHost
    #node.Attacker = host[2][2][1][2]
    # node.append('Attacker: ' + str(host[2][2][1][2]))
    # #VictimHost
    # #node.Viticm = host[2][2][2][2]
    # for i in host[2][2][2]:
    #     node.append('Victim: ' + str(i[2]))
    # #node.append('Victim: ' + str(host[2][2][2][2]))
    return node

def DepthSearch(paj, visited, attacker):
    if (attacker not in visited):
        visited.append(attacker)
        AttackGraphNode = Exploit(NetworkHost.value[attacker])
        # for i in FoundPrivileges:
        #     if (NetworkHost.value[attacker] == i):
        #         FoundPrivileges.remove(i)
        x = NetworkHost.value[attacker][2][2][1][2]
        y = []
        for i in NetworkHost.value[attacker][2][2][2]:
            y.append(i[2])
        if AttackGraphNode not in AttackGraphNodes:
            AttackGraphNodes.append(AttackGraphNode)
        #FoundPrivileges.remove(NetworkHost.value[attacker])
        # MainStack.remove(NetworkHost.value[attacker])
        for i in  paj:
            if (i[0] == attacker):
                for j in i:
                    for m in y:
                        if (j == (m-1)):
                            if (NetworkHost.value[j] not in FoundPrivileges):
                                FoundPrivileges.append(NetworkHost.value[j])
                            if AttackGraphEdges not in AttackGraphEdges:
                                AttackGraphEdges.append([x, m])
                                #print NetworkHost.value[j]
                            DepthSearch(paj, visited, j)
            # else:
            #     FoundPrivileges = NetworkHost.value[y - 1]

def AttackGraphGeneration(paj):
    #does not seem right
    # [5, '5.62.2.22', ['MS Internet Explorer 10', 'port', ['CVE-5', ['cpe:/5', 'Root', 5],
    # [['cpe:/6', 'Root', 6], ['cpe:/7', 'FileAccess', 7], ['cpe:/8', 'FileAccess', 8]]]]]
    for i in FoundPrivileges:
        attacker = i[2][2][1][2] - 1
        DepthSearch(paj, visited, attacker)


    ParialAttackGraph = [AttackGraphNodes, AttackGraphEdges]

    return ParialAttackGraph, FoundPrivileges

# def Sort(results):
#     for i in Results:
#         index = Results.index(i)
#         if (index % 2 == 0):
#             PartialAttackGraphs = PartialAttackGraphs + i
#         # elif (index % 2 == 1):
#         #     AttackGraphEdges = AttackGraphEdges + i
#         elif (index % 2 == 1):
#             FoundPrivileges = FoundPrivileges + i
#             # elif (index % 4 == 3):
#             #     visited = visited + i
#
#     PartialAttackGraphs = Duplicate(PartialAttackGraphs)
#     # AttackGraphNodes = Duplicate(AttackGraphNodes)
#     FoundPrivileges = Duplicate(FoundPrivileges)

def MutilevelKwayPartition(k, adj, xadj, w):
    (edgecuts, parts) = pymetis.part_graph(nparts=k, adjncy=adj, xadj=xadj, eweights=w)
    print parts
    for i in range(0, k):
        PartialHost = []
        Partialadjancy = []

        for j in range(0, len(parts)):
            if (parts[j] == i):
                PartialHost.append(NetworkHost[j])
                Partialadjancy.append([j] + adjancy[j])

        PartialNetworkHosts.append(PartialHost)
        Partialadjancys.append(Partialadjancy)

    return Partialadjancys

if __name__ == '__main__':

    k = 2 #Mutilevel k-way partition
    PartialNetworkHosts = []
    Partialadjancys = []

    AttackGraphNodes = []
    AttackGraphEdges = []
    PartialAttackGraph = []
    PartialAttackGraphs = []

    partialHosts = []

    FoundPrivileges = []

    visited = []

    TargetNetwork = LoadTargetNetwork()

    NetworkHost = TargetNetwork[0]
    #Communication = TargetNetwork[1]
    adjancy = TargetNetwork[2]
    adj = TargetNetwork[3]
    xadj = TargetNetwork[4]
    w = TargetNetwork[5]

    Hostnum = len(NetworkHost)

    Partialadjancys = MutilevelKwayPartition(k, adj, xadj, w)
    # (edgecuts, parts) = pymetis.part_graph(nparts=k, adjncy=adj, xadj=xadj, eweights=w)
    # #use metis for graph partition
    #
    # #print edgecuts
    # print parts
    #
    #
    #
    # for i in range(0, k):
    #     PartialHost = []
    #     Partialadjancy = []
    #
    #     for j in range(0, len(parts)):
    #         if (parts[j] == i):
    #             PartialHost.append(NetworkHost[j])
    #             Partialadjancy.append([j] + adjancy[j])
    #
    #     PartialNetworkHosts.append(PartialHost)
    #     Partialadjancys.append(Partialadjancy)




    # for i in Partialadjancys:
    #     for j in i:
    #         print j
    #     print '----------------------------------------------------------'

    # for i in PartialNetworkHosts:
    #     for j in i:
    #         print j[0]
    #     print '----------------------------------------------------------'

    FoundPrivileges = [NetworkHost[0]]


    for i in FoundPrivileges:
        AttackGraphNodes.append(Exploit(i))


    # PartialAttackGraphs = Spark(NetworkHost, FoundPrivileges, Partialadjancys)

    conf = SparkConf().setAppName("AttackGraph").setMaster('local[*]')
    sc = SparkContext(conf=conf)

    start = time.time()

    DistPNH = sc.parallelize(Partialadjancys, k)

    NetworkHost = sc.broadcast(TargetNetwork[0])

    #wrtite a loop
    #find a better limit
    while (len(FoundPrivileges) != Hostnum):
        Results = DistPNH.map(lambda x: AttackGraphGeneration(x)).cache()
        # print Results.collect()
        # print Results.collect()
        # pags = Results.groupByKey()
        # print pags.collect()
        Results = Results.reduce(lambda x, y: x + y)

        for i in Results:
            index = Results.index(i)
            if (index % 2 == 0):
                PartialAttackGraphs = PartialAttackGraphs + i
            elif (index % 2 == 1):
                FoundPrivileges = FoundPrivileges + i

        FoundPrivileges = Duplicate(FoundPrivileges)

    end = time.time()

    PartialAttackGraphs = Duplicate(PartialAttackGraphs)

    Nodes = []
    Edges = []
    AttackGraph = []

    for i in PartialAttackGraphs:
         for j in i:
            if j not in PartialAttackGraph:
                if (len(j) == 4):
                    Nodes.append(j)
         for j in i:
            if j not in PartialAttackGraph:
                if (len(j) == 2):
                    Edges.append(j)

    Nodes = Duplicate(Nodes)
    Edges = Duplicate(Edges)
    AttackGraph.append(Nodes)
    AttackGraph.append(Edges)

    for i in AttackGraph:
        for j in i:
            print j

    print '----------------------------------------------------'

    # for i in FoundPrivileges:
    #     print i

    print end - start