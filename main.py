import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import sys
import threading
from multiprocessing import Manager, Process,Queue
from ctypes import *
from time import sleep,time
from datetime import datetime
import re
"""Import from other files in this directory"""
from var import VAR
from packet_r import Packet_r
#redirect all output to files in order to keep the console clean
#filename  = open("outputfile.txt",'w')
#sys.stdout = filename

from contextlib import contextmanager

@contextmanager
def redirect_stderr(new_target):
    """suppress all warnings to keep console clean"""
    import sys
    old_target, sys.stderr = sys.stderr, new_target
    try:
        yield new_target
    finally:
        sys.stderr = old_target

with open(os.devnull, 'w') as errf:
    """suppress all annoying warnings when loading scapy"""
    with redirect_stderr(errf):
        from scapy.all import *
        import wx

"""use pcap to capture in Windows"""
conf.use_pcap = True

"""Folling libs are used to parse http response"""
import urllib3
from io import BytesIO
from http.client import HTTPResponse
""" psutil is used to detect network speed"""
import psutil
class BytesIOSocket:
    """Class to read bytes using BytesIO"""

    def __init__(self, content):
        self.handle = BytesIO(content)

    def makefile(self, mode):
        return self.handle


def response_from_bytes(data):
    """Convert a bytes into a readable http response string"""
    sock = BytesIOSocket(data)
    response = HTTPResponse(sock)
    response.begin()
    return urllib3.HTTPResponse.from_httplib(response)


def packet_tcp_seq(seq):
    """Return tcp reassembly result"""
    seq_keys = list(share.tcp_seq.keys())
    seq_keys.sort()
    position = seq_keys.index(seq)
    p, q, final_tcp_seq = [], [], []
    p = packet_tcp_seq_backward(seq_keys, position, p)[::-1]
    p.append((seq, share.tcp_seq[seq]))
    q = packet_tcp_seq_forward(seq_keys, position, q)
    final_tcp_seq = p + q
    return final_tcp_seq


def packet_tcp_seq_forward(seq_keys, position, p):
    """Return tcp reassembly forward result"""
    flag = True
    total_len = len(seq_keys)
    remain_len = total_len - 1
    while position < total_len - 1:
        i = position + 1
        while i < total_len:
            if (i > total_len - 0.5 * remain_len and flag == True):
                flag == False
            if seq_keys[position] + share.tcp_seq[seq_keys[position]][1] == seq_keys[i]:
                position = i
                p.append((seq_keys[position], share.tcp_seq[seq_keys[position]]))
                break
            i += 1
        if i == total_len:
            break
    return p


def packet_tcp_seq_backward(seq_keys, position, p):
    """Return tcp reassembly backward result"""
    flag = True
    remain_len = position
    while position >= 1:
        i = position - 1
        while i >= 0:
            if (i < remain_len * 0.5 and flag == True):
                flag = False
            if seq_keys[i] + share.tcp_seq[seq_keys[i]][1] == seq_keys[position]:
                position = i
                p.append((seq_keys[position], share.tcp_seq[seq_keys[position]]))
                break
            i -= 1
        if i == -1:
            break
    return p


def packet_align(s):
    """Return wireshark-type raw hex"""
    s = [s[i:i + 32] for i in range(0, len(s), 32)]
    for n in range(len(s)):
        s[n] = [s[n][i:i + 2] for i in range(0, len(s[n]), 2)]
        s[n].append("\n")
        s[n].insert(0, format(n * 16, "04x"))
        s[n] = " ".join(s[n])
    return s


class GUI(wx.Frame):
    def __init__(self, parent, id, title, ifaces):
        """Initiate the GUI interface using wxpython when the Internet Interface list is loaded"""
        # load interface list
        self.sample_list = ifaces
        self.t = []  # initialize thread
        # initiate the frame
        wx.Frame.__init__(self, parent, id, title, size=(1000, 1030), style=wx.DEFAULT_FRAME_STYLE &
                          ~wx.MAXIMIZE_BOX ^ wx.RESIZE_BORDER, pos=(100, 0))
        # initiate the top panel
        topPanel = wx.Panel(self)

        # split the top panel into panel_1,panel_2_3,panel_4
        # panel_1:the panel for setup sniffer and brief info of packets sniffed
        self.panel_1 = wx.Panel(topPanel, -1, pos=(0, 0), size=(1000, 400))

        # panel_2_3:the splitable panel for panel_2 and panel_3
        self.panel_2_3 = wx.Panel(topPanel, -1, pos=(0, 400), size=(1000, 540))
        self.splitter = wx.SplitterWindow(self.panel_2_3)

        # panel_2:the panel for showing detailed info of results sniffed
        self.panel_2 = wx.Panel(self.splitter, -1, size=(1000, 50))

        # panel_3:the panel for showing reassembly(IP,TCP,HTTP) info of packets sniffed
        self.panel_3 = wx.Panel(self.splitter, -1, size=(1000, 50))
        self.splitter.SplitHorizontally(self.panel_2, self.panel_3)
        self.splitter.SetMinimumPaneSize(50)
        # panel_4:the panel for showing reassembly progress as well as button
        self.panel_4 = wx.Panel(topPanel, -1, pos=(0, 940), size=(1000, 60))

        # Progress of sizer to spilt and adjust all panels
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer.Add(self.panel_1, 1, wx.EXPAND | wx.ALL)
        sizer.Add(self.panel_2_3, 1, wx.EXPAND | wx.ALL)
        sizer.Add(self.panel_4, 1, wx.EXPAND | wx.ALL)
        topPanel.SetSizer(sizer)

        sizer2 = wx.BoxSizer(wx.VERTICAL)
        sizer2.Add(self.splitter, 1, wx.EXPAND | wx.ALL)
        self.panel_2_3.SetSizer(sizer2)

        self.notebook1 = wx.Notebook(self.panel_2)
        self.notebook2 = wx.Notebook(self.panel_3)
        bsizer = wx.BoxSizer()
        bsizer.Add(self.notebook1, 1, wx.EXPAND)
        self.panel_2.SetSizerAndFit(bsizer)

        bsizer = wx.BoxSizer()
        bsizer.Add(self.notebook2, 2, wx.EXPAND)
        self.panel_3.SetSizerAndFit(bsizer)

        # set custom font for text,labels
        self.font_12 = self.SetCustomFont(12)
        self.font_10 = self.SetCustomFont(10)

        self.notebook1.SetFont(self.font_10)
        self.notebook2.SetFont(self.font_10)

        '''1st line'''
        # choose interface
        self.hint_Iface = wx.StaticText(
            self.panel_1, label='NIC', pos=(10, 16))
        self.hint_Iface.SetFont(self.font_12)

        self.iface = wx.ComboBox(
            self.panel_1,
            pos=(100, 15),
            size=(500, -1),
            choices=self.sample_list,
            style=wx.CB_DROPDOWN | wx.CB_READONLY)
        self.iface.SetFont(self.font_10)
        self.Bind(wx.EVT_COMBOBOX, self.EvtComboBox, self.iface)

        # network speed(download and upload)
        self.hint_speed_down = wx.StaticText(self.panel_1, label='↓', pos=(660, 15))
        self.hint_speed_down.SetFont(self.font_12)
        share.network_speed_down = wx.StaticText(self.panel_1, label='', pos=(670, 15))
        share.network_speed_down.SetFont(self.font_12)

        self.hint_speed_up = wx.StaticText(self.panel_1, label='↑', pos=(850, 15))
        self.hint_speed_up.SetFont(self.font_12)
        share.network_speed_up = wx.StaticText(self.panel_1, label='', pos=(860, 15))
        share.network_speed_up.SetFont(self.font_12)

        '''2nd line'''
        # choose protocol
        self.hint_pro = wx.StaticText(
            self.panel_1, 
            label='PROTOCOL',
            pos=(10, 55)).SetFont(self.font_12)
        self.pro = wx.TextCtrl(self.panel_1, pos=(100, 55), size=(120, -1))
        self.pro.SetFont(self.font_10)
        self.Bind(wx.EVT_TEXT, self.EvtTextPro, self.pro)

        # choose src
        self.hint_src = wx.StaticText(
            self.panel_1,
            label='SRC',
            pos=(230, 55)).SetFont(self.font_12)
        self.src = wx.TextCtrl(self.panel_1, pos=(270, 55), size=(120, -1))
        self.src.SetFont(self.font_10)
        self.Bind(wx.EVT_TEXT, self.EvtTextSrc, self.src)

        # choose sport
        self.hint_sport = wx.StaticText(
            self.panel_1, 
            label='SPORT', 
            pos=(410, 55)).SetFont(self.font_12)
        self.sport = wx.TextCtrl(self.panel_1, pos=(480, 55), size=(120, -1))
        self.sport.SetFont(self.font_10)
        self.Bind(wx.EVT_TEXT, self.EvtTextSport, self.sport)

        # choose dst
        self.hint_dst = wx.StaticText(
            self.panel_1,
            label='DST',
            pos=(620, 55)).SetFont(self.font_12)
        self.dst = wx.TextCtrl(self.panel_1, pos=(660, 55), size=(120, -1))
        self.dst.SetFont(self.font_10)
        self.Bind(wx.EVT_TEXT, self.EvtTextDst, self.dst)

        # choose dport
        self.hint_dport = wx.StaticText(
            self.panel_1, 
            label='DPORT', 
            pos=(790, 55)).SetFont(self.font_12)
        self.dport = wx.TextCtrl(self.panel_1, pos=(850, 55), size=(120, -1))
        self.dport.SetFont(self.font_10)
        self.Bind(wx.EVT_TEXT, self.EvtTextDport, self.dport)

        '''3rd line'''
        # button start/stop
        self.button = wx.Button(
            self.panel_1, 
            label='START',
            pos=(660, 95), 
            size=(120, 30))
        self.button.SetFont(self.font_12)
        self.Bind(wx.EVT_BUTTON, self.EvtStart, self.button)

        # save file
        self.save = wx.Button(
            self.panel_1, label='SAVE', pos=(850, 95), size=(120, 30))
        self.save.SetFont(self.font_12)
        self.Bind(wx.EVT_BUTTON, self.EvtSave, self.save)
        self.save.Hide()

        # max performance checkbox  True means use additional process to listen, False means average CPU consumption
        self.max = wx.CheckBox(
            self.panel_1, label="MAX", pos=(10, 95), size=(70, 30))
        self.max.SetValue(True)
        self.max.SetFont(self.font_12)
        self.Bind(wx.EVT_CHECKBOX, self.EvtCheckBoxHigh, self.max)

        # search bar
        self.search = wx.SearchCtrl(
            self.panel_1,
            pos=(100, 95),
            size=(500, 30),
            style=wx.TE_PROCESS_ENTER)
        self.search.SetFont(self.font_10)
        self.search.ShowCancelButton(True)

        self.Bind(wx.EVT_TEXT_ENTER, self.EvtSearch, self.search)
        self.Bind(wx.EVT_SEARCHCTRL_CANCEL_BTN, self.EvtDelete, self.search)

        # brief info listctrl of packets sniffed
        share.result_row = wx.ListCtrl(
            self.panel_1, -1, style=wx.LC_REPORT, size=(980, 260), pos=(0, 140))
        share.result_row.SetFont(self.font_10)
        share.result_row.InsertColumn(0, "No.")
        share.result_row.InsertColumn(1, "Time ")
        share.result_row.InsertColumn(2, "Source address")
        share.result_row.InsertColumn(3, "Destination address")
        share.result_row.InsertColumn(4, "Length")
        share.result_row.InsertColumn(5, "Protocol")
        share.result_row.SetColumnWidth(0, 60)
        share.result_row.SetColumnWidth(1, 100)
        share.result_row.SetColumnWidth(2, 280)
        share.result_row.SetColumnWidth(3, 280)
        share.result_row.SetColumnWidth(4, 75)
        share.result_row.SetColumnWidth(5, 145)

        # left click to choose a row and show detail and the scroll bar freezes
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.EvtSelectRow, share.result_row)
        # right click to cancel a row and the scroll bar continues
        self.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.EvtCancelRow, share.result_row)

        # The button for reassembling tcp/http and save in local
        self.reassembly = wx.Button(self.panel_4, label='Reassembly', pos=(400, -1), size=(200, 30))
        self.reassembly.SetFont(self.font_12)
        self.Bind(wx.EVT_BUTTON, self.EvtReassemble, self.reassembly)
        self.reassembly.Hide()

        self.size_label = wx.StaticText(self.panel_4, label='', pos=(700, 7), size=(200, 30))
        self.size_label.SetFont(self.font_12)
        # Event bind for close the window
        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def SetCustomFont(self, size):
        """Get font size and return a Font instance"""
        return (wx.Font(size, wx.MODERN, wx.NORMAL, wx.LIGHT, False, u'Consolas'))

    def OnClose(self, event):
        """The event for closing the GUI, which is to terminate everthing involved"""
        global flag_dict
        flag_dict['close'] = True
        flag_dict['start'] = True
        self.Destroy()
        p.terminate()

    def EvtSave(self, event):
        """The event for clicking the Save button, which is to save selected packet(s) to a readable txt file"""
        num = share.result_row.GetSelectedItemCount()
        if (num == 0):
            dlg = wx.MessageDialog(None, u"You have to select at least a row so that you can save.", u"Fatal Error")
            if dlg.ShowModal() == wx.ID_YES:
                dlg.Destroy()
        else:
            selection = []
            index = share.result_row.GetFirstSelected()
            selection.append(index)
            while len(selection) != num:
                index = share.result_row.GetNextSelected(index)
                selection.append(index)

            filename = ""
            openFileDialog = wx.FileDialog(frame, "SAVE", "", "",
                                           "TXT files (.txt)|.txt",
                                           wx.FD_SAVE)
            if openFileDialog.ShowModal() == wx.ID_OK:
                filename = openFileDialog.GetPath()
            openFileDialog.Destroy()

            if (filename != ""):
                f = open(filename, "a")
                for i in selection:
                    f.write('No.' + str(share.list_packet[i].num) + '\nCapture Time:' + share.list_packet[i].time +
                            '\tSave Time:' + datetime.now().strftime("%H:%M:%S") +
                            '\n' + share.list_packet[i].show(dump=True) + '\n')
                f.close()
                # open the file as soon as the progress of saving is finished
                os.system(filename)

    def EvtStart(self, event):
        """The event for clicking the Start/Stop button, which is to start/stop the progress"""
        global flag_dict
        if (flag_dict['iface'] == ""):
            dlg = wx.MessageDialog(None, u"You have to choose a network interface", u"Fatal Error")
            if dlg.ShowModal() == wx.ID_YES:
                dlg.Destroy()
        else:
            flag_dict['start'] = not flag_dict['start']
            if (flag_dict['start']):
                self.button.SetLabel('Stop')
                sleep(1)
                if (flag_dict['error']==True):
                    flag_dict['start']=False
                    flag_dict['error'] = False
                    dlg = wx.MessageDialog(None, u"Filter is not right. Please rewrite!", u"Fatal Error")
                    self.button.SetLabel('Start')
                    if dlg.ShowModal() == wx.ID_YES:
                        dlg.Destroy()
                    
            else:
                self.button.SetLabel('Start')
            

    def EvtReassemble(self, event):
        """The event for clicking the Reassembly button, which is to save the whole packets' load information into a file
           Only support TCP reassembly(especially for ftp) and HTTP reassembly(get the whole html)"""
        filename = ""
        openFileDialog = wx.FileDialog(frame, "SAVE REASSEMBLY", "", "",
                                       "",
                                       wx.FD_SAVE)
        if openFileDialog.ShowModal() == wx.ID_OK:
            filename = openFileDialog.GetPath()
        openFileDialog.Destroy()

        if (filename != ""):
            try:
                f = open(filename, "wb")
                f.write(self.bytes_array)
                f.close()
            except:
                f = open(filename, "w")
                f.write(self.bytes_array)
                f.close()
            # open the file as soon as the progress of saving is finished
            os.system(filename)

    def EvtTextPro(self, event):
        """The event for entering the protocol, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['pro'] = event.GetString()

    def EvtTextSrc(self, event):
        """The event for entering the source address, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['src'] = event.GetString()

    def EvtTextSport(self, event):
        """The event for entering the source port, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['sport'] = event.GetString()

    def EvtTextDst(self, event):
        """The event for entering the destination address, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['dst'] = event.GetString()

    def EvtTextDport(self, event):
        """The event for entering the destination port, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['dport'] = event.GetString()

    def EvtComboBox(self, event):
        """The event for selecting the Network Interface in Combobox, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['iface'] = event.GetString()
        share.mac = share.mac_dict[flag_dict['iface']]
        flag_dict['mac']=share.mac_dict[flag_dict['iface']]

    def EvtCheckBoxHigh(self, event):
        """The event for selecting the mode of mulitiprocessing for the higher-end performance, which is to save it for filter(default:on)"""
        global flag_dict
        flag_dict['max'] = self.max.GetValue()

    def EvtSearch(self, event):
        """The event for entering keywords in search bar and using 'ENTER' to proceed, which is to show the results containing keywords.
           The packet list shown in GUI will immediately stop updating while the backend is still sniffering.
           In other words, one can only search the packets sniffed according to what have been sniffed.
           Clear the search bar and all packets sniffed in the backend will start updating again, even in the period of seaching"""
        share.result_row.DeleteAllItems()
        share.flag_search = True
        self.index_new = []
        keyword = self.search.GetValue()
        for i in range(len(share.list_tmp)):
            try:
                # keywords can exist in raw/utf-8/GB2312 packet
                sentence = share.list_packet[i].packet_to_all().lower()
                sentence += share.list_packet[i].packet_to_load_gb().lower()
                sentence += share.list_packet[i].packet_to_load_utf8().lower()
            except:
                pass
            if (keyword.lower() in sentence):
                share.result_row.Append(share.list_tmp[i])
                self.index_new.append(i)
        if (keyword == ""):
            # if nothing is in the searchbar, return the whole result and keep sniffering
            share.flag_search = False
            share.flag_select = False

    def EvtDelete(self, event):
        """The event for deleting the search bar using given icon, which is to give back the all packets sniifed and start updating."""
        share.result_row.DeleteAllItems()
        share.flag_search = True
        self.index_new = []
        keyword = self.search.GetValue()
        for i in range(len(share.list_tmp)):
            share.result_row.Append(share.list_tmp[i])
            self.index_new.append(i)
        if (keyword == ""):
            share.flag_search = False
            share.flag_select = False

    def EvtSelectRow(self, event):
        """The event for selecting a row(packet), which is to show detailed and reassembly information about the chosen packet."""
        # get index of selected packet
        self.save.Show()
        # if lock.locked():
        val = int(event.GetText())
        # Adding a dedicated new thread for time-consuming caculation it packet processing
        self.t.append(Thread(target=self.Choosing, args=(val,)))
        self.t[-1].start()

    def EvtCancelRow(self, event):
        """The event for right clicking a row(packet), which is to make the scroll bar update again."""
        self.save.Show()
        share.flag_cancel = True

    def CreateNewTab(self, notebook, title, content):
        """Create a new tab when the notebook and content is given"""
        bsizer = wx.BoxSizer()
        page = wx.Panel(notebook)
        notebook.AddPage(page, title)
        try:
            text = wx.TextCtrl(page, -1, content, style=wx.TE_MULTILINE | wx.BORDER_NONE | wx.TE_READONLY)
        except:
            text = wx.TextCtrl(page, -1, "UnicodeDecodeError: 'utf-8' codec can't decode this information",
                               style=wx.TE_MULTILINE | wx.BORDER_NONE | wx.TE_READONLY)
        text.SetMaxLength(2147438647)
        text.SetFont(self.font_10)
        bsizer.Add(text, 1, wx.EXPAND)
        page.SetSizerAndFit(bsizer)

    def Choosing(self, val):
        """Create a new tab when the notebook and content is given"""
        #clear the size label 
        self.size_label.SetLabel("")
        # freeze the panel_2,panel_# for processing
        self.panel_2.Freeze()
        self.panel_3.Freeze()

        # not cancel a row
        share.flag_cancel = False

        # clear all remaining tabs
        try:

            while (self.notebook2.GetPageCount()):
                self.notebook2.DeletePage(0)
            while (self.notebook1.GetPageCount()):
                self.notebook1.DeletePage(0)
        except:
            pass

        share.flag_select = True  # select a row
        layerlist = share.list_packet[val].packet_to_layerlist()
        final_tcp_seq = ""
        final_ip_seq = ""

        for i in layerlist:
            # notebook1 with detailed info for single packet
            s = ""
            s = s + "No. " + str(val) + "\n" + i[0] + "\n"
            for key in i[1]:
                s = s + "%-10s%s\n" % ((key[0].upper()+key[1:]+":"), i[1][key])
            wx.CallAfter(self.CreateNewTab, self.notebook1, i[0], s)
        wx.CallAfter(self.CreateNewTab, self.notebook1, "Whole in hex", share.list_packet[val].hexdump())
        try:
            if (share.list_packet[val].load):
                wx.CallAfter(self.CreateNewTab, self.notebook1, "Load in utf-8", share.list_packet[val].packet_to_load_utf8())
                wx.CallAfter(self.CreateNewTab, self.notebook1, "Load in GB2312", share.list_packet[val].packet_to_load_gb())
        except:
            pass

        try:
            self.panel_2.Thaw()
        except:
            pass

        for i in layerlist:
            # detect IP/TCP reassembly
            if "IP" in i:
                if i[1]["flags"] != 2:
                    (ip_src, ip_dst, ip_id) = (i[1]["src"], i[1]["dst"],
                                               i[1]["id"])
                    try:
                        final_ip_seq = share.ip_seq[(ip_src, ip_dst, ip_id)]
                    except:
                        final_ip_seq = 'Too large to assemble'

            if "TCP" in i:
                try:
                    final_tcp_seq = packet_tcp_seq(i[1]["seq"])
                except:
                    final_tcp_seq = 'Too large to assemble'
                final_tcp_seq = packet_tcp_seq(i[1]["seq"])
        if (final_tcp_seq != ""):  # Satisify TCP reassembly
            self.processing = wx.StaticText(self.panel_4, label='Processing.....................', size=(1000, 40))
            self.processing.SetFont(self.font_12)
            if (final_tcp_seq == 'Too large to assemble'):  # Too big for memory
                wx.CallAfter(self.CreateNewTab, self.notebook2, "TCP reassemble failed", final_tcp_seq)

            else:
                s = "No. " + str(val) + " can be TCP assembled by "
                for i in final_tcp_seq:
                    s = s + "No. " + str(i[1][0]) + ", "
                s = s[:-2] + "\n" + "After reassembly:" + "\n" + "\n"
                s_gb = s_utf8 = s_raw = ""
                try:
                    first_index = final_tcp_seq[0][1][0]
                    content = b''
                    for i in final_tcp_seq:
                        content += share.list_packet[i[1][0]].load
                    response = response_from_bytes(content)
                    h = ""
                    for i in response.headers:
                        h += str(i) + " : " + str(response.headers[i]) + "\n"
                    s = b"No. " + bytes(str(val), 'utf8') + b" can be HTTP assembled by "
                    for i in final_tcp_seq:
                        s = s + b"No. " + bytes(str(i[1][0]), 'utf8') + b", "
                    s = s[:-2] + b"\n" + b"After reassembly:" + b"\n" + b"\n"
                    try:
                        content = response.data
                    except:
                        pass
                    self.bytes_array = content
                    h = "HTTP Header in No. " + str(first_index) + '\n' + h

                    wx.CallAfter(self.CreateNewTab, self.notebook2, "HTTP HEADER", h)
                    wx.CallAfter(self.CreateNewTab, self.notebook2, "HTTP CONTENT", s + content)
                except:
                    self.reassemble_size=0
                    self.bytes_array = b""
                    for i in final_tcp_seq:
                        try:
                            self.bytes_array += share.list_packet[i[1][0]].load
                        except:
                            pass

                        s_raw = s_raw + share.list_packet[i[1][0]].packet_to_load_plain()
                        if (i[1][1] != 0):
                            self.reassemble_size+=len(share.list_packet[i[1][0]].load)
                            s_gb = s_gb + share.list_packet[i[1][0]].packet_to_load_gb()
                            s_utf8 = s_utf8 + share.list_packet[i[1][0]].packet_to_load_utf8()
                    q = ""
                    q = q + "".join(packet_align(s_raw))
                    s_gb = s + "\n" + "Decoded by GB2312:" + "\n" + s_gb
                    s_utf8 = s + "\n" + "Decoded by UTF8:" + "\n" + s_utf8
                    s_raw = s + "Raw bytes:" + "\n" + q
                    wx.CallAfter(self.CreateNewTab, self.notebook2, "TCP reassemble Hex", s_raw)
                    wx.CallAfter(self.CreateNewTab, self.notebook2, "TCP reassemble UTF-8", s_utf8)
                    wx.CallAfter(self.CreateNewTab, self.notebook2, "TCP reassemble GB2312", s_gb)
                    self.size_label.SetLabel("Total Size: "+str(self.reassemble_size)+"B")
                wx.CallAfter(self.reassembly.Show)


        if (final_ip_seq != "" and len(final_ip_seq) != 1):  # Satisify IP reassembly
            if (final_ip_seq == 'Too large to assemble'):  # Too big for memory

                wx.CallAfter(self.CreateNewTab, self.notebook2, "IP reassemble failed", final_ip_seq)

            else:
                self.reassemble_size=0
                s = "No. " + str(val) + " can be IP assembled by "
                for i in final_ip_seq:
                    s = s + "No. " + str(i[0]) + ", "
                s = s[:-2] + "\n" + "After reassembly:" + "\n" + "\n"
                s_gb = s_utf8 = s_raw = ""
                for i in final_ip_seq:
                    s_raw = s_raw + share.list_packet[i[0]].packet_to_load_plain()
                    s_gb = s_gb + share.list_packet[i[0]].packet_to_load_gb()
                    s_utf8 = s_utf8 + share.list_packet[i[0]].packet_to_load_utf8()
                    self.reassemble_size+=len(share.list_packet[i[0]].load)
                self.bytes_array = s_utf8

                q = ""
                q = q + "".join(packet_align(s_raw))
                s_gb = s + "\n" + "Decoded by GB2312:" + "\n" + s_gb
                s_utf8 = s + "\n" + "Decoded by UTF8:" + "\n" + s_utf8
                s_raw = s + "Raw bytes:" + "\n" + q
                wx.CallAfter(self.CreateNewTab, self.notebook2, "IP reassemble Hex", s_raw)
                wx.CallAfter(self.CreateNewTab, self.notebook2, "IP reassemble UTF-8", s_utf8)
                wx.CallAfter(self.CreateNewTab, self.notebook2, "IP reassemble GB2312", s_gb)
                wx.CallAfter(self.reassembly.Show)
                self.size_label.SetLabel("Total Size: "+str(self.reassemble_size)+"B")

        try:
            self.panel_3.Thaw()
        except:
            pass
        

def InfiniteProcess(flag_dict, pkt_lst):
    """The dedicated process to sniff, which is to get the iface and filter and then starting sniffing"""
    while (flag_dict['close'] == False):
        sleep(0.1)
        if (flag_dict['start'] == True and flag_dict['error'] == False):
            
            sleep(0.1)
            f = ""
            if (flag_dict['close'] == False):
                for key in flag_dict.keys():
                    if (flag_dict[key] != ''):
                        if (key == 'pro'):
                            f += " and " + flag_dict['pro']
                        elif (key == 'src' or key == 'dst'):
                            f += " and " + key + " " + flag_dict[key]
                        elif (key == 'sport'):
                            f += " and src port " + flag_dict['sport']
                        elif (key == 'dport'):
                            f += " and dst port " + flag_dict['dport']
                f = f[5:]
            #try:
            if (f == ""):
                a = sniff(
                    iface=flag_dict['iface'],
                    store=0,
                    pkt_lst=pkt_lst,
                    flag_dict=flag_dict,
                    stopperTimeout=0.2,
                )
            else:
                a = sniff(
                    iface=flag_dict['iface'],
                    store=0,
                    filter=f,
                    pkt_lst=pkt_lst,
                    flag_dict=flag_dict,
                    stopperTimeout=0.2,
                )
            #except NameError:
                #flag_dict['error']= True
                #continue
                


def process():
    """The dedicated thread to process raw packet, which is to process each raw packet and make it display in the Listctrl"""
    num = 0
    global pkt_lst
    while (True):
        try:
            p = pkt_lst.get()

        except:
            continue
        packet = Ether(p[0])
        packet.time = p[1]
        packet.num = num
        num += 1
        packet = Packet_r(packet)
        share.list_packet.append(packet)

        if (share.flag_search == False):
            share.result_row.Append(packet.packet_to_info())
        share.list_tmp.append(packet.packet_to_info())
        if ((share.flag_select == False and share.flag_search == False)
                or (share.flag_select == True and share.flag_cancel == True
                    and share.flag_search == False)):
            # make the scroll bar update
            share.result_row.EnsureVisible(share.result_row.GetItemCount() - 1)

        # possible preprocess for TCP reassembly
        if packet.haslayer(TCP):
            seq = packet.packet[TCP].seq
            if hasattr(packet.packet[TCP], "load"):
                seqlen = len(packet.packet[TCP].load)
            else:
                seqlen = 0
            share.tcp_seq[seq] = (packet.num, seqlen)

        # possible preprocess for IP reassembly
        if packet.haslayer(IP):
            if packet.packet[IP].flags != 2:
                if (packet.packet[IP].src, packet.packet[IP].dst,
                        packet.packet[IP].id) in share.ip_seq.keys():
                    share.ip_seq[(packet.packet[IP].src, packet.packet[IP].dst,
                                  packet.packet[IP].id)].append(
                        (packet.num, packet.packet[IP].flags,
                         packet.packet[IP].frag))
                else:
                    share.ip_seq[(packet.packet[IP].src, packet.packet[IP].dst,
                                  packet.packet[IP].id)] = [(packet.num, packet.packet[IP].flags,
                                                             packet.packet[IP].frag)]


def networkspeed():
    """The dedicated thread to show network speed, which is to display upload/download speed every second.
       The value might be much lower than the actual one due to computation and load bottleneck"""
    position = 0
    global flag_dict
    while (flag_dict['close'] == False):
        s_up=0.00
        s_down=0.00
        while (share.mac==''):
            sleep(0.5)
        sleep(1)
        t0 = time.time()
        macname=share.dict_mac2name[share.mac]
        upload=psutil.net_io_counters(pernic=True)[macname][0]
        download=psutil.net_io_counters(pernic=True)[macname][1]
        up_down=(upload,download)
        while (flag_dict['start']==True):
            last_up_down = up_down
            upload=psutil.net_io_counters(pernic=True)[macname][0]
            download=psutil.net_io_counters(pernic=True)[macname][1]
            t1 = time.time()
            up_down = (upload,download)
            try:
                s_up, s_down = [(now - last) / (t1 - t0) 
                        for now,last in zip(up_down, last_up_down)]             
                t0 = time.time()
            except:
                pass

            time.sleep(0.5) 
            os.system('cls')
            s_up,s_down=int(s_up),int(s_down) 
            if s_up // 1024 < 1:
                speed_up = str(round(s_up, 1)) + "Bps"
            elif s_up // 1024 ** 2 < 1:
                speed_up = str(round(s_up / 1024, 1)) + 'KBps'
            elif s_up // 1024 ** 3 < 1:
                speed_up = str(round(s_up / 1024 ** 2, 1)) + "MBps"
            if s_down // 1024 < 1:
                speed_down = str(round(s_down, 1)) + "Bps"
            elif s_up // 1024 ** 2 < 1:
                speed_down = str(round(s_down / 1024, 1)) + 'KBps'
            elif s_up // 1024 ** 3 < 1:
                speed_down = str(round(s_down / 1024 ** 2, 1)) + "MBps"
            share.network_speed_down.SetLabel('%10s' % speed_down)
            share.network_speed_up.SetLabel('%10s' % speed_up)
        

if __name__ == "__main__":
    # using class VAR instance 'share' to share variable among multiple threads in main process
    lock = threading.Lock()
    share = VAR()
    list_tmp = []
    while (len(list_tmp) <= 1):
        share.interfaces = []
        share.list_mac = []
        for i, n in ifaces.items():
            share.interfaces.append(i)
            share.list_mac.append(re.sub(r'\W+', '', n.mac.lower()))
        list_tmp = share.interfaces
    for i in range(len(share.interfaces)):
        share.mac_dict[share.interfaces[i]] = share.list_mac[i]

    # using manager to share values between processes
    manager = Manager()
    iface = manager.Value(c_char_p, "")
    pro = manager.Value(c_char_p, "")
    port = manager.Value(c_char_p, "")
    src = manager.Value(c_char_p, "")
    dst = manager.Value(c_char_p, "")
    flag_dict = manager.dict()
    flag_dict['start'] = False
    flag_dict['close'] = False
    flag_dict['max'] = True
    flag_dict['error'] = False
    flag_dict['iface'] = ''
    flag_dict['pro'] = ''
    flag_dict['src'] = ''
    flag_dict['sport'] = ''
    flag_dict['dst'] = ''
    flag_dict['dport'] = ''

    flag_dict['mac']=''
    flag_dict['up']=0
    flag_dict['down']=0
    
    # list to store and fetch packet
    pkt_lst = manager.Queue()
    p = Process(target=InfiniteProcess, name="InfiniteProcess", args=(flag_dict, pkt_lst))
    p.daemon = True
    p.start()
    
    finish = False
    process_list = [process, networkspeed]
    thread_list = []
    for i in range(len(process_list)):
        thread_list.append(threading.Thread(target=process_list[i]))
        thread_list[i].setDaemon(1)
        thread_list[i].start()

    app = wx.App()
    frame = GUI(None, -1, 'sniffer v1.1', share.interfaces)

    frame.Show()
    app.MainLoop()
