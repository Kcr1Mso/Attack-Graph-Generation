from random import choice
import os
import random

def text_save(content,filename,mode='a'):
    # Try to save a list variable in txt file.
    file = open(filename,mode)
    for i in range(len(content)):
        file.write(str(content[i])+'\n')
    file.close()

def LoadTargetNetwork():

       Hostnum = 8
       ConditionLines = []
       NetworkHostLines = []
       VulnerabilityLines = []
       SoftwareApplicationLines = []
       Access = ['FileAccess', 'User', 'Root']
       SoftwareApplicationName = ['MS Windows 7 gold', 'MS Outlook 2007', 'MS Office 2010', 'MS Internet Explorer 10']

       for i in range(Hostnum):
              Condition = ['cpe:/' + str(i + 1), choice(Access), (i + 1)] # for example: ['cpe:/1', 'Root', '1']
              # cpeid authority hostid
              ConditionLines.append(Condition)

       for i in range(Hostnum):

              if ((i + 1) == Hostnum):
                  Vulnerability = ['CVE-' + str(i + 1), ConditionLines[i], [ConditionLines[0]]]
              elif (i == 0):
                  Vulnerability = ['CVE-' + str(i + 1), ConditionLines[i], ConditionLines[1:]]
              elif ((i + 2) == Hostnum):
                  Vulnerability = ['CVE-' + str(i + 1), ConditionLines[i], [ConditionLines[i + 1]]]
              else:
                  Vulnerability = ['CVE-' + str(i + 1), ConditionLines[i], [ConditionLines[i + 1], ConditionLines[i + 2]]]

              #CVEId precondition postcondition
              VulnerabilityLines.append(Vulnerability)

       for i in range(Hostnum):
              # if i == 0:
              #   SoftwareApplication = ['SoftwareApplication:' + choice(SoftwareApplicationName), 'port',VulnerabilityLines[0]]
              # else:
            SoftwareApplication = [choice(SoftwareApplicationName), 'port',VulnerabilityLines[i]]
            SoftwareApplicationLines.append(SoftwareApplication)

#['SoftwareApplication:MS Office 2010', 'port', ['Vulnerability:CVE-1', precondition, postcondition]]

       for i in range(Hostnum):
              NetworkHost = [(i + 1), str(i + 1) + '.62.2.22', SoftwareApplicationLines[i]]
              #print NetworkHost[0]
              NetworkHostLines.append(NetworkHost)
#example:['1.62.2.22', ['SoftwareApplication:MS Office 2010', 'port',
       # ['Vulnerability:CVE-1', ['cpe:/1', 'User', '1'], ['cpe:/2', 'Root', '2']]]]


       Communication = [[0, 1, 0, 0, 0, 1, 0, 0],  # 1
                        [1, 0, 1, 0, 0, 0, 1, 0],  # 2
                        [0, 1, 0, 1, 0, 0, 0, 0],  # 3
                        [0, 0, 1, 0, 1, 0, 1, 0],  # 4
                        [0, 0, 0, 1, 0, 1, 0, 1],  # 5
                        [1, 0, 0, 0, 1, 0, 1, 1],  # 6
                        [0, 1, 0, 1, 0, 1, 0, 1],  # 7
                        [0, 0, 0, 0, 1, 1, 1, 0]  # 8
                        ]

       adjancy = [[1, 5],
                   [0, 2, 6],
                   [1, 3],
                   [2, 4, 6],
                  [3, 5, 7],
                  [0, 4, 6, 7],
                  [1, 3, 5, 7],
                  [4, 5, 6]
                   ]

       adj = [1, 5, 0, 2, 6, 1, 3, 2, 4, 6, 3, 5, 7, 0, 4, 6, 7, 1, 3, 5, 7, 4, 5, 6]
       xaj = [0, 2, 5, 7, 10, 13, 17, 21, 24]
       w = [5, 1,
            1, 5, 1,
            1, 5,
            1, 5, 1,
            1, 5, 1,
            1, 1, 5, 1,
            1, 1, 1, 5,
            1, 1, 1
            ]




       Communication = [[0 for i in range(Hostnum)] for i in range(Hostnum)]

       for i in range(Hostnum):
           for j in range(Hostnum):
                   if ((j == (i + 1)) or (j == (i - 1))):
                       Communication[i][j] = 1
                   elif(i != j):
                       x = random.randrange(2)
                       Communication[i][j] = x
                       Communication[j][i] = x

       adjancy = []
       for i in Communication:
            list = []
            num = 0
            for j in i:
                if (j == 1):
                    list.append(num)
                num = num + 1
            adjancy.append(list)

       adj = []
       xaj = [0]
       num = 0
       w = []

       for i in adjancy:
           for j in i:
               adj.append(j)
               num = num + 1
               if ( j == (adjancy.index(i) + 1)):
                   w.append(5)
               else:
                   w.append(0)
           xaj.append(num)

       TargetNetwork = [NetworkHostLines, Communication, adjancy, adj, xaj, w]

       return TargetNetwork

if __name__ == '__main__':
    TargetNetwork = LoadTargetNetwork()

    os.remove('NetworkHost.txt')
    os.remove('Adjancy.txt')

    text_save(TargetNetwork[0], 'NetworkHost.txt')
    text_save(TargetNetwork[2], 'Adjancy.txt')

    for i in TargetNetwork[0]:
        print i

    for i in TargetNetwork[2]:
        print i

    for i in TargetNetwork[1]:
        print i

    print TargetNetwork[3]

    print TargetNetwork[4]

    print TargetNetwork[5]