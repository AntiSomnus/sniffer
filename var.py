class VAR():
    """Class for shared variables in multipule threads of main process"""
    def __init__(self):

        self.interfaces = []    #network interface list

        # False: Window not closed;
        # True: Window is closed
        self.flag_select = False            # False:no row is chosen, so that scroll bar refreshes;
        # True: have selected a row, so that the scroll bar freezes

        # False:the sniff has not started
        # True: the sniff is running
        self.flag_cancel = False            # False:no row has been cancelled(by right clicking the selected row)
        # True: now row is chosen,so that the scroll bar start refreshing
        self.flag_search = False            # False:haven't activate search yet
        # True: activate search and the scroll bar freezes

        self.list_packet = []               # each original packet
        self.list_tmp = []
        self.result_row = ''                # the row shown in widget listctrl

        self.tcp_seq = {}  # dictionary for tcp reassmebly
        self.ip_seq = {}  # dictionary for ip reassmebly
        self.network_speed_down = ''
        self.network_speed_up = ''
        self.size_upload = 0
        self.size_download = 0
        self.list_mac = []
        self.mac_dict = {}
        self.mac = ''
        self.dict_time = {}  # capture time dict  packet:time