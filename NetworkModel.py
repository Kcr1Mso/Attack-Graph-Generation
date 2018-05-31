
class NetworkHost(object):
    '''
    classdocs

    A network host is a two element tuple  <NetworkInterfaces, SoftwareApplications>
    '''
    NetworkInterfaces = []

#    a list of network interface contained by the network host

    SoftwareApplications = []

#    a list of installed software application on the network host



class NetworkInterface(object):
    '''
    classdocs

    A network interface denotes a OSI Layer 3 interface on a network host and is a three element tuple

    <IPAdress,Link,Host>
    '''

    IPAddress = ''

    # string    the IP address associated with the network interface

    Link = []

    # the communication link connected to the network interface

    Host = NetworkHost

    # the network host containing the network interface

    def __init__(self, IPAddress, Link, Host):

        '''
        Constructor
        '''

        self.IPAddress = IPAddress
        self.Link = Link
        self.Host = Host


class CommunicationLink(object):

    '''
    classdocs

    A communicationlink

    '''

    SourceNetworkInterface = NetworkInterface
    TargetNetworkInterface = NetworkInterface

    def __init__(self, SourceNetworkInterface, TargetNetworkInterface):

        '''
        Constructor
        '''

        self.SourceNetworkInterface = SourceNetworkInterface
        self.TargetNetworkInterface = TargetNetworkInterface


class SoftwareApplication(object):
    '''
    classdocs

    <CPEId,HostIPAdress,Port,BackendApplications,InformationSources>

    '''
    CPEId = ''  # string
    '''
    CPEId denotes the software product identifier
    '''
    HostIPAddress = ''  # string
    '''
    HostIPAddress denotes the IP address on which the software application is serving
    '''
    Port = 0  # Integer
    '''
    Port denotes the port on which it is serving
    '''
    BackendApplication = []  # list
    '''
    BackendApplications refers to the software applications whose services are used by this software application
    '''
    InformationSource = []  # list
    '''
    InformationSources is a list of information sources contained by the software application such as
     credentials store, cookies, DNS table, routing table, databases.
    '''

    Vulnerabilities = []

    def __init__(self, CPEId, HostIPAddress, Port, BackendApplication, InformationSource, Vulnerabilities):
        '''
        Constructor
        '''
        self.CPEId = CPEId
        self.HostIPAddress = HostIPAddress
        self.Port = Port
        self.BackendApplication = BackendApplication
        self.InformationSource = InformationSource
        self.Vulnerabilities = Vulnerabilities


class InformationSource(object):
    '''
    classdocs

    An information source denotes a sensitive data store that is contained by a software application and can be accessed
    and used by an attacker. It is represented by a three tuple
    <ReferencedSoftware;Preconditions; Postconditions>
    '''
    name = ''  # string

    ReferencedSoftware = []  # list
    '''
    The postconditions are gained on the software applications referenced by the information source that are stored by 
    the element ReferencedSoftware.
    '''
    Preconditions = []  # list
    '''
     In order to use an information source, an attacker should satisfy the preconditions that are stored in the list 
     Preconditions for the information source
    '''
    Postconditions = []  # list
    '''
    After successfully benefiting from the information source, the attacker gains the postconditions that are stored 
    in the list Postconditions for the information source. 
    '''

    def __init__(self, name, ReferencedSoftware, Preconditions, Postconditions):
        '''
        Constructor
        '''
        self.name = name
        self.ReferencedSoftware = ReferencedSoftware
        self.Preconditions = Preconditions
        self.Postconditions = Postconditions