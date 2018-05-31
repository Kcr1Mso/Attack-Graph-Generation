# -*- coding:utf-8 -*-

import time
from pyspark import SparkContext,SparkConf

times = 0
HostCopy = []
ConditionLines = []
NetworkHostLines = []
VulnerabilityLines = []
SoftwareApplicationLines = []

# <Host,Communication,Trust,I,id>


for i in range(9):
    Condition_c = ['cpe:/' + str(i), 'File Access', 'Host ' + str(i), str(i) + '.62.2.22']
    #cpeid authority hostid ipaddress
    ConditionLines.append(Condition_c)

for i in range(8):
    Vulnerability_c = ['CVE' + str(i + 1), [ConditionLines[i / 2]], [ConditionLines[i + 1]]]
    VulnerabilityLines.append(Vulnerability_c)

for i in range(9):
    if i == 0:
        SoftwareApplication_c = ['cpe:/' + str(i), str(i) + '.62.2.22', '0', ['Host ' + str(i)],
                                 [], []]
    else:
        SoftwareApplication_c = ['cpe:/' + str(i), str(i) + '.62.2.22', '0', ['Host ' + str(i)],
                                 [], [VulnerabilityLines[i - 1]]]
    SoftwareApplicationLines.append(SoftwareApplication_c)

for i in range(9):
    NetworkHost_c = [str(i) + '.62.2.22', [SoftwareApplicationLines[i]], []]
    NetworkHostLines.append(NetworkHost_c)
    if i > 0:
        NetworkHostLines[(i + 1) / 2 - 1][2].append(NetworkHostLines[i])

def func(row):
    x = row[0]   #单个主机
    y = row[1]   #权限集
    func_lines_x = []    #返回主机
    func_lines_y = []    #返回权限
    func_lines_z = []    #返回漏洞

#漏洞查找
    for l in x[2]:
        for i in l[1]:
            for j in i[5]:
                checks = 0
                for k in j[1]:
                    for s in y:
                        if k == s:
                            checks = checks+1
                            break
                if checks == len(j[1]):
                    func_lines_z.append(j)
                    func_lines_y.extend(j[2])
                    func_lines_x.extend(x[2])

    func_lines = [func_lines_x,func_lines_y,func_lines_z]
    return func_lines

def AttackGraph():

    conf = SparkConf().setAppName("AttackGraph").setMaster("local[*]")
    sc = SparkContext(conf=conf)

    start = time.clock()

    BFS = [[NetworkHostLines[0],[ConditionLines[0]]]]
    list_1 = [ConditionLines[0]]

    AttackGraphLines = []

    while len(BFS)!= 0 :
        data = sc.parallelize(BFS)

        data_s = data.map(lambda x: func(x))

        list_line = data_s.collect()
        list_0 = []
        list_2 = []
        for i in list_line:
            list_0.append(i[0])
            for j in i[1]:
                for k in list_1:
                    if j == k:
                        break
                else:list_1.append(j)
            for j in i[2]:
                for k in list_2:
                    if j == k:
                        break
                else:list_2.append(j)

        BFS = []
        for i in list_0:
            for j in i:
                BFS.append([j,list_1])

        for i in list_2:
            for j in i:
                for k in AttackGraphLines:
                    if j==k:
                        break
                else:
                    AttackGraphLines.append(j)


    end = time.clock()
    print (end - start)
    print ('AttackGraph')
    print (AttackGraphLines)

