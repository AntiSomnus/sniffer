from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QAction,QTableWidget,QTableWidgetItem,QVBoxLayout,QTabWidget,QProgressBar,QFileDialog,QCompleter
from PyQt5.QtGui import QIcon,QFont,QCursor,QPixmap
from PyQt5.QtCore import pyqtSlot,QThread,Qt,pyqtSignal,QPoint
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QFrame, 
    QSplitter, QStyleFactory, QApplication,QMenu)
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from threading import Thread
import sys
from time import sleep
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
from httpconverter import HttpConverter
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


"""use pcap to capture in Windows"""
conf.use_pcap = True


""" psutil is used to detect network speed"""
import psutil

"""The following fuctions are used to handle tcp reassembly"""
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

"""The following fuction is used to convert hex bytes to formatted hex"""
def packet_align(s):
    """Return wireshark-type raw hex"""
    s = [s[i:i + 32] for i in range(0, len(s), 32)]
    for n in range(len(s)):
        s[n] = [s[n][i:i + 2] for i in range(0, len(s[n]), 2)]
        s[n].append("\n")
        s[n].insert(0, format(n * 16, "04x"))
        s[n] = " ".join(s[n])
    return s

class SearchButton(QtWidgets.QPushButton):
    def enterEvent(self,event):
        self.setStyleSheet("border: 1px solid grey;background-color: white;")
    def leaveEvent(self,event):
        self.setStyleSheet("border: none;background-color: white;")

class NewButton(QtWidgets.QPushButton):
    def enterEvent(self,event):
        self.setStyleSheet("background-color:rgb(225, 225, 225);color:blue")
    def leaveEvent(self,event):
        self.setStyleSheet("background-color: rgb(240, 240, 240);border-style: outset;border-width: 0px;color:blue")
class Table(QtWidgets.QTableWidget):
    def contextMenuEvent(self, event):
        self.menu = QtWidgets.QMenu(self)
        if ( len(self.selectedItems())> 6):
            saveAction = QtWidgets.QAction('Save selected %d packets'%(len(self.selectedItems())/6), self)
        else:
            saveAction = QtWidgets.QAction('Save selected packet', self)
        saveAction.triggered.connect(self.SaveReadablePackets)
        self.menu.addAction(saveAction)
        self.menu.setFont(QFont('Consolas', 10, QFont.Light))
        self.menu.popup(QtGui.QCursor.pos())
    def SaveReadablePackets(self):
        a=[]
        for i in self.selectedItems():
            a.append(i.row())
        filename = QFileDialog.getSaveFileName(filter="Text files (*.txt)")[0]
        if (filename != ""):
                f = open(filename, "w")
                for i in set(a):
                    if (share.flag_search==True):
                        i=share.dict_search[i]
                    f.write('No.' + str(share.list_packet[i].num) + '\nCapture Time:' + share.list_packet[i].time +
                            '\tSave Time:' + datetime.now().strftime("%H:%M:%S") +
                            '\n' + share.list_packet[i].show(dump=True) + '\n')
                f.close()
                # open the file as soon as the progress of saving is finished
                os.system(filename)

            
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        self.MainWindow=MainWindow
        self.MainWindow.setObjectName("self.MainWindow")

        self.MainWindow.resize(850, 800)
        self.centralwidget = QtWidgets.QWidget(self.MainWindow)
        self.MainWindow.setCentralWidget(self.centralwidget)
        #using grid layout to put widgets 
        #vlayout is used to expand items automatically
        self.vlayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setContentsMargins(0, 0, 0, 0)
        '''1st line'''
        #NIC label
        self.label_NIC = QtWidgets.QLabel(self.centralwidget)
        self.label_NIC.setText("NIC")
        self.label_NIC.setFont(QFont('Consolas', 11, QFont.Bold))

        #NIC comboBox
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setFont(QFont('Consolas', 10, QFont.Light))
        #add interface name into comboBox
        for i in share.interfaces:
            self.comboBox.addItem(i)
        self.comboBox.currentTextChanged.connect(self.EVT_COMBOBOX)
        #checkbox for max mod
        self.checkBox = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox.setFont(QFont('Consolas', 10, QFont.Light))
        self.checkBox.setText("OC")
        self.checkBox.setChecked(True)
        self.checkBox.clicked.connect(self.EvtCheckBoxHigh)
        self.checkBox.setToolTip("OC MODE:\nUsing a dedicated process to sniff continuously,\nwhich may enhance CPU usage.")
        '''1st line layout'''
        self.gridLayout.addWidget(self.label_NIC,0,0,1,1)
        self.gridLayout.addWidget(self.comboBox,0,1,1,7)
        self.gridLayout.addWidget(self.checkBox,0,8,1,1)
        '''2nd line'''
        #protocol label
        self.label_pro = QtWidgets.QLabel(self.centralwidget)
        self.label_pro.setFont(QFont('Consolas', 11, QFont.Bold))
        self.label_pro.setText("PRO")
        #source address label
        self.label_src = QtWidgets.QLabel(self.centralwidget)
        self.label_src.setFont(QFont('Consolas', 11, QFont.Bold))
        self.label_src.setText("SRC")
        #source port label
        self.label_sport = QtWidgets.QLabel(self.centralwidget)
        self.label_sport.setFont(QFont('Consolas', 11, QFont.Bold))
        self.label_sport.setText("SPORT")
        #destination address label
        self.label_dst = QtWidgets.QLabel(self.centralwidget)
        self.label_dst.setFont(QFont('Consolas', 11, QFont.Bold))
        self.label_dst.setText("DST")
        #destination port label
        self.label_dport = QtWidgets.QLabel(self.centralwidget)
        self.label_dport.setFont(QFont('Consolas', 11, QFont.Bold))
        self.label_dport.setText("DPORT")
  
        self.pro = QtWidgets.QLineEdit(self.centralwidget)
        self.pro.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.pro.setCompleter(QtWidgets.QCompleter(["ip","ip6","tcp","udp","arp","icmp","igmp"]))
        self.pro.textChanged.connect(self.EvtTextPro)
    

        self.src = QtWidgets.QLineEdit(self.centralwidget)
        self.src.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.src.textChanged.connect(self.EvtTextSrc)

        self.sport = QtWidgets.QLineEdit(self.centralwidget)
        self.sport.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.sport.textChanged.connect(self.EvtTextSport)

        self.dst = QtWidgets.QLineEdit(self.centralwidget)
        self.dst.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.dst.textChanged.connect(self.EvtTextDst)

        self.dport = QtWidgets.QLineEdit(self.centralwidget)
        self.dport.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.dport.textChanged.connect(self.EvtTextDport)
        
        
        '''2nd line layout'''
        self.gridLayout.addWidget(self.label_pro,1,0,1,1)
        self.gridLayout.addWidget(self.pro,1,1,1,1)
        self.gridLayout.addWidget(self.label_src,1,2,1,1)
        self.gridLayout.addWidget(self.src,1,3,1,1)
        self.gridLayout.addWidget(self.label_sport,1,4,1,1)
        self.gridLayout.addWidget(self.sport,1,5,1,1)
        self.gridLayout.addWidget(self.label_dst,1,6,1,1)
        self.gridLayout.addWidget(self.dst,1,7,1,1)
        self.gridLayout.addWidget(self.label_dport,1,8,1,1)
        self.gridLayout.addWidget(self.dport,1,9,1,1)

        
        '''3rd line'''
        self.searchbar =QtWidgets.QLineEdit(self.centralwidget)
        self.searchbar.setPlaceholderText("Search")
        self.searchbar.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.searchbar.setFrame(False)
        self.searchbar.setFixedHeight(30)

        self.searchbutton=SearchButton(self.centralwidget)
        self.searchbutton.setIcon(QIcon("1.png"))
        self.searchbutton.setStyleSheet("border: none;background-color: white;")
        self.searchbutton.setFixedSize(30,30)
        self.searchbutton.clicked.connect(self.Evtsearch)
        self.button = QtWidgets.QPushButton(self.centralwidget)
        self.button.setText("START")
        self.button.setFont(QFont('Consolas', 10, QFont.Light)) 
        self.button.clicked.connect(self.EvtStart)
        self.button.setFont(QFont('Consolas', 11, QFont.Light))
        self.button.setFixedHeight(30)

        


        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addWidget(self.searchbar)
        hbox.addWidget(self.searchbutton)
        hbox.setSpacing(0)
        self.searchbar.returnPressed.connect(self.Evtsearch)

        self.gridLayout.addLayout(hbox,2,0,1,10)
        self.gridLayout.addWidget(self.button,0,9,1,1)
        
        """table """
        self.tableWidget = Table(self.centralwidget)
        self.tableWidget.verticalHeader().setDefaultSectionSize(25)
        self.tableWidget.horizontalHeader().setFont(QFont('Consolas', 11, QFont.Light))
        self.tableWidget.setSizeAdjustPolicy(
        QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.tableWidget.setMinimumHeight(50)
        self.tableWidget.setColumnCount(6)
        self.tableWidget.setHorizontalHeaderLabels(['No.', 'Time', 'Source address', 'Destination address', 'Length','Protocol'])
        self.tableWidget.setColumnWidth(0,60)
        self.tableWidget.setColumnWidth(1,100)
        self.tableWidget.setColumnWidth(2,240)
        self.tableWidget.setColumnWidth(3,240)
        self.tableWidget.setColumnWidth(4,75)
        self.tableWidget.setColumnWidth(5,90)
        self.tableWidget.setShowGrid(False)
        self.tableWidget.setFont(QFont('Consolas', 10, QFont.Light))
        
        self.tableWidget.itemSelectionChanged.connect(self.EvtSelect)
        self.tableWidget.itemDoubleClicked.connect(self.cancel)

        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.setMouseTracking(True)
        self.tableWidget.cellEntered.connect(self.handleItemEntered)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)

        self.th=ProcessingThread()
        self.th.AddPacket.connect(self.AddPacketToTable)
        self.th.Scroll.connect(self.ScrollToEnd)
        self.th.start()

        self.th2=NetworkspeedThread()
        self.th2.SetNetworkSpeed.connect(self.SetSpeedOnStatusBar)
        self.th2.start()
        """tab1"""
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setMinimumHeight(50)
        self.tabWidget.setFont(QFont('Consolas', 10, QFont.Light))
        """tab2"""
        self.tabWidget_2 = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_2.setMinimumHeight(50)
        self.tabWidget_2.setFont(QFont('Consolas', 10, QFont.Light))

        """split window"""

        
        hbox = QtWidgets.QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
     
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.tableWidget)
        splitter.addWidget(self.tabWidget)
        splitter.addWidget(self.tabWidget_2)
        splitter.setSizes([230,225,225])
        hbox.addWidget(splitter)
        self.gridLayout.addLayout(hbox,3,0,5,10)
        self.gridLayout.setRowMinimumHeight(3,690)
        self.vlayout.addLayout(self.gridLayout)
        spacerItem = QtWidgets.QSpacerItem(20, 245, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.vlayout.addItem(spacerItem)

        """button: continue to reassemble"""
        self.continue_reassemble_button = NewButton(self.tabWidget_2)
        self.continue_reassemble_button.setGeometry(QtCore.QRect(500,-4,300,30))
        self.continue_reassemble_button.setText("Continue to reassemble")
        self.continue_reassemble_button.setFont(QFont('Consolas', 11, QFont.Light))
        self.continue_reassemble_button.clicked.connect(self.EvtContinueReassemble)
        self.continue_reassemble_button.setStyleSheet("background-color: rgb(240, 240, 240);border-style: outset;border-width: 0px;color:blue")
        self.continue_reassemble_button.hide()

        

        self.statusbar = QtWidgets.QStatusBar(self.MainWindow)
        self.statusbar.setFixedHeight(30)
        self.statusbar.setObjectName("statusbar")
        self.MainWindow.setStatusBar(self.statusbar)

        self.speedlabel=QtWidgets.QLabel(self.statusbar)
        self.speedlabel.setText("")
        self.speedlabel.setFixedWidth(350)
        self.speedlabel.setFont(QFont('Consolas', 10, QFont.Light))
        """progressbar"""
        self.pbar=QProgressBar(self.statusbar)
        self.pbar.setValue(0)
        self.pbar.setFixedWidth(150)
        self.pbar.setGeometry(QtCore.QRect(680, 0, 300, 28))

        self.save_reassemble_button = NewButton(self.statusbar)
        self.save_reassemble_button.setGeometry(QtCore.QRect(275, 0, 300, 28))
        self.save_reassemble_button.setText("Save reassembly Result")
        self.save_reassemble_button.setStyleSheet("background-color: rgb(240, 240, 240);border-style: outset;border-width: 0px;color:blue")
        self.save_reassemble_button.setFont(QFont('Consolas', 11, QFont.Light))
        self.save_reassemble_button.clicked.connect(self.EvtSaveReassemble)
        self.save_reassemble_button.hide()

        self.pbar.hide()
        #self.retranslateUi()
        
        self.title='Sniffer V2.0'
        self.MainWindow.setWindowTitle(self.title)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
    def CustomFont(self,num,style):
        return QFont('Consolas', num, style)
    def EvtCheckBoxHigh(self):
        """The event for selecting the mode of mulitiprocessing for the higher-end performance, which is to save it for filter(default:on)"""
        global flag_dict
        flag_dict['max'] = self.checkBox.isChecked()

    def Evtsearch(self):
        """The event for entering keywords in search bar and using 'ENTER' to proceed, which is to show the results containing keywords.
           The packet list shown in GUI will immediately stop updating while the backend is still sniffering.
           In other words, one can only search the packets sniffed according to what have been sniffed.
           Clear the search bar and all packets sniffed in the backend will start updating again, even in the period of seaching"""
        self.tableWidget.setRowCount(0)
        share.flag_search = True
        keyword = self.searchbar.text()
        after_search_index=0
        for i in range(len(share.list_tmp)):
            try:
                # keywords can exist in raw/utf-8/GB2312 packet
                sentence = share.list_packet[i].packet_to_all().lower()
                sentence += share.list_packet[i].packet_to_load_gb().lower()
                sentence += share.list_packet[i].packet_to_load_utf8().lower()
            except:
                pass
            if (keyword.lower() in sentence):
                share.dict_search[after_search_index]=i
                self.tableWidget.insertRow(after_search_index)
                for j in range(6):
                    item= QTableWidgetItem(share.list_tmp[i][j])
                    self.tableWidget.setItem(after_search_index,j, item)
                after_search_index+=1
        if (keyword == ""):
            # if nothing is in the searchbar, return the whole result and keep sniffering
            share.flag_search = False
            share.flag_select = False

       
    def SetSpeedOnStatusBar(self,l):
        s_up=l[0]
        s_down=l[1]
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
        title='  ↓ %s  ↑ %s' % (speed_down.rjust(10),speed_up.rjust(10))
        self.speedlabel.setText(title)
        
    def ScrollToEnd(self,l):
        self.tableWidget.scrollToBottom()
    def AddPacketToTable(self,l):
        num=l[-1]
        self.tableWidget.insertRow(num)
        for i in range(6):
            item= QTableWidgetItem(l[i])
            self.tableWidget.setItem(num,i, item)

    def EVT_COMBOBOX(self):
        """The event for selecting the Network Interface in Combobox, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['iface'] = self.comboBox.currentText()
        share.mac = share.mac_dict[flag_dict['iface']]
        flag_dict['mac']=share.mac_dict[flag_dict['iface']]

    def EvtTextPro(self):
        """The event for entering the protocol, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['pro'] = self.pro.text()
    
    def EvtTextSrc(self):
        """The event for entering the source address, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['src'] = self.src.text()
    def EvtTextSport(self):
        """The event for entering the source port, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['sport'] = self.sport.text()

    def EvtTextDst(self):
        """The event for entering the destination address, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['dst'] = self.dst.text()

    def EvtTextDport(self):
        """The event for entering the destination port, which is to save it for filter(default:all)"""
        global flag_dict
        flag_dict['dport'] = self.dport.text()

    def EvtStart(self):
        global flag_dict
        flag_dict['start'] = not flag_dict['start']
        if (flag_dict['start']):
            self.button.setText('Stop')
            title=self.title+" - "+flag_dict["iface"]+" - "+InputToFilter(flag_dict)
            self.MainWindow.setWindowTitle(title)
        else:
            self.button.setText('Start')
            self.MainWindow.setWindowTitle(self.title)

    def handleItemEntered(self,row,column):
        """move cursor on item"""
        '''for i in range(self.tabWidget.count()):
            self.tabWidget.removeTab(i)'''
        

    def EvtSelect(self):
        QtCore.QCoreApplication.processEvents()
        try:
            self.continue_reassemble_button.hide()
            self.save_reassemble_button.hide()
            self.pbar.hide()
        except:
            pass
        for i in self.tableWidget.selectedItems():
            val=i.row()
        if (share.flag_search==True):
            try:
                val=share.dict_search[val]
            except UnboundLocalError:
                return
        share.flag_select = True
        share.flag_cancel = False
        
        self.final_tcp_seq = ""
        self.final_ip_seq = ""
        count=self.tabWidget.count()
        for i in range(self.tabWidget.count()):
            self.tabWidget.removeTab(0)
        for i in range(self.tabWidget_2.count()):
            self.tabWidget_2.removeTab(0)
        try:
            layerlist = share.list_packet[val].packet_to_layerlist()
        except UnboundLocalError:
            return 

        #single packet infomation
        for i in layerlist:
            QtCore.QCoreApplication.processEvents()
            s = ""
            s = s + "No. " + str(val) + "\n" + i[0] + "\n"
            for key in i[1]:
                s = s + "%-10s%s\n" % ((key[0].upper()+key[1:]+":"), i[1][key])
            self.CreateNewTab(self.tabWidget,i[0],s)
        self.CreateNewTab(self.tabWidget, "Whole in hex",share.list_packet[val].hexdump())

        for i in layerlist:
            # detect IP/TCP reassembly
            if "IP" in i:
                if i[1]["flags"] != 2:
                    (ip_src, ip_dst, ip_id) = (i[1]["src"], i[1]["dst"],
                                               i[1]["id"])
                    try:
                        self.final_ip_seq = share.ip_seq[(ip_src, ip_dst, ip_id)]
                    except:
                        self.final_ip_seq = 'Too large to assemble'

            if "TCP" in i:
                try:
                    self.final_tcp_seq = packet_tcp_seq(i[1]["seq"])
                except:
                    self.final_tcp_seq = 'Too large to assemble'
                self.final_tcp_seq = packet_tcp_seq(i[1]["seq"])
        self.reassemble_size=0
        """TCP"""
        if (self.final_tcp_seq != ""):  # Satisify TCP reassembly
            if (self.final_tcp_seq == 'Too large to assemble'):  # Too big for memory
                self.CreateNewTab(self.tabWidget_2, "TCP reassemble failed", self.final_tcp_seq)
                return
            
            #First give the information of reassemble
            s = "No. " + str(val) + " can be TCP assembled by "
            for i in self.final_tcp_seq:
                QtCore.QCoreApplication.processEvents()
                s = s + "No. " + str(i[1][0]) + ", "
                try:
                    self.reassemble_size+=len(share.list_packet[i[1][0]].load)
                except:
                    """no load"""
                    pass
            s = s[:-2]
            self.CreateNewTab(self.tabWidget_2,"Reassembly Info(%dB)"%self.reassemble_size,s)
            if (len(self.final_tcp_seq)<2000):
                """Total reassemble seq len<2000 means quick reassemble, which shows result immediately"""
                self.ShowTcpResult()
            else:
                """Total reassemble seq len>2000 means slow reassemble, which should wait for user's response"""
                self.continue_reassemble_button.show()
            self.save_reassemble_button.show()
            return

        """IP"""
        if (self.final_ip_seq != "" and len(self.final_ip_seq) != 1):  # Satisify IP reassembly
            if (self.final_ip_seq == 'Too large to assemble'):  # Too big for memory
                self.CreateNewTab(self.tabWidget_2, "IP reassemble failed", self.final_ip_seq)
            s = "No. " + str(val) + " can be IP assembled by "
            for i in self.final_ip_seq:
                QtCore.QCoreApplication.processEvents()
                s = s + "No. " + str(i[0]) + ", "
                try:
                    self.reassemble_size+=len(share.list_packet[i[0]].load)
                except AttributeError:
                    """no load"""
                    pass
            s = s[:-2]
            self.CreateNewTab(self.tabWidget_2,"Reassembly Info(%dB)"%self.reassemble_size,s)
            if (len(self.final_ip_seq)<2000):
                """Total reassemble seq len<2000 means quick reassemble, which shows result immediately"""
                self.ShowIpResult()
            else:
                """Total reassemble seq len>2000 means slow reassemble, which should wait for user's response"""
                self.continue_reassemble_button.show()
            self.save_reassemble_button.show()
            return
                
    
    def ShowIpResult (self):
        s = "After reassembly:\n" 
        s_gb = s_utf8 = s_raw = ""
        for i in self.final_ip_seq:
            s_raw = s_raw + share.list_packet[i[0]].packet_to_load_plain()
            s_gb = s_gb + share.list_packet[i[0]].packet_to_load_gb()
            s_utf8 = s_utf8 + share.list_packet[i[0]].packet_to_load_utf8()
           
        self.file_content = s_utf8
        #self.size_label.SetLabel("Total Size: "+str(self.reassemble_size)+"B")
        q = ""
        q = q + "".join(packet_align(s_raw))
        s_gb = s + "\n" + "Decoded by GB2312:" + "\n" + s_gb
        s_utf8 = s + "\n" + "Decoded by UTF8:" + "\n" + s_utf8
        s_raw = s + "\n"+ "Raw bytes:" + "\n" + q
        self.CreateNewTab(self.tabWidget_2, "IP reassemble Hex", s_raw)
        self.CreateNewTab(self.tabWidget_2, "IP reassemble UTF-8", s_utf8)
        self.CreateNewTab(self.tabWidget_2, "IP reassemble GB2312", s_gb)
    def ShowTcpResult(self):
        s = "After reassembly:\n"
        s_gb = s_utf8 = s_raw = ""
        try:
            first_index = self.final_tcp_seq[0][1][0]
            content = b''
            for i in self.final_tcp_seq:
                QtCore.QCoreApplication.processEvents()
                content += share.list_packet[i[1][0]].load
            response = HttpConverter(content).getcontent()
            h = ""
            for i in response.headers:
                QtCore.QCoreApplication.processEvents()
                h += str(i) + " : " + str(response.headers[i]) + "\n"
            s = b"No. " + bytes(str(val), 'utf8') + b" can be HTTP assembled by "
            for i in self.final_tcp_seq:
                QtCore.QCoreApplication.processEvents()
                s = s + b"No. " + bytes(str(i[1][0]), 'utf8') + b", "
            s = s[:-2] + b"\n" + b"After reassembly:" + b"\n" + b"\n"
            try:
                content = response.data
            except:
                pass
            self.file_content = content
            h = "HTTP Header in No. " + str(first_index) + '\n' + h

            self.CreateNewTab(self.tabWidget_2, "HTTP HEADER", h)
            self.CreateNewTab(self.tabWidget_2, "HTTP CONTENT", s + content)
        except:
            self.file_content = b""
            for i in self.final_tcp_seq:
                QtCore.QCoreApplication.processEvents()
                try:
                    self.file_content += share.list_packet[i[1][0]].load
                except:
                    pass

                s_raw = s_raw + share.list_packet[i[1][0]].packet_to_load_plain()
                if (i[1][1] != 0):
                    s_gb = s_gb + share.list_packet[i[1][0]].packet_to_load_gb()
                    s_utf8 = s_utf8 + share.list_packet[i[1][0]].packet_to_load_utf8()
            #self.size_label.SetLabel("Total Size: "+str(self.reassemble_size)+"B")
            q = ""
            q = q + "".join(packet_align(s_raw))
            s_gb = s + "\n" + "Decoded by GB2312:" + "\n" + s_gb
            s_utf8 = s + "\n" + "Decoded by UTF8:" + "\n" + s_utf8
            s_raw = s + "\n"+ "Raw bytes:" + "\n" + q
            self.CreateNewTab(self.tabWidget_2,"TCP reassemble Hex", s_raw)
            self.CreateNewTab(self.tabWidget_2,"TCP reassemble UTF-8", s_utf8)
            self.CreateNewTab(self.tabWidget_2,"TCP reassemble GB2312", s_gb)
    def EvtContinueReassemble (self):
        self.continue_reassemble_button.hide()
        if (self.final_tcp_seq!=""):
            self.ShowTcpResult()
        elif (self.final_ip_seq!=""):
            self.ShowIpResult()
        
    def EvtSaveReassemble(self):
        self.file_content = b""
        self.pbar.show()
        current_num=0
        if (self.final_tcp_seq!=""):
            """mean TCP reassemble"""
            total_num=len(self.final_tcp_seq)
            for i in self.final_tcp_seq:
                QtCore.QCoreApplication.processEvents()
                try:
                    self.file_content += share.list_packet[i[1][0]].load
                except:
                    """No load"""
                    pass
                current_num+=1
                self.pbar.setValue(int(current_num/total_num*100))
        else:
            """mean TCP reassemble"""
            total_num=len(self.final_ip_seq)
            for i in self.final_ip_seq:
                QtCore.QCoreApplication.processEvents()
                try:
                    self.file_content += share.list_packet[i[0]].load
                except:
                    """No load"""
                    pass
                current_num+=1
                self.pbar.setValue(int(current_num/total_num*100))
        self.pbar.hide()
        filename = QFileDialog.getSaveFileName()[0]
        if (filename==""):
            return
        try:
            """if byte"""
            f = open(filename, "wb")
            f.write(self.file_content)
            f.close()
        except:
            """if not"""
            f = open(filename, "w")
            f.write(self.file_content)
            f.close()
        os.system(filename)
    def CreateNewTab(self,tab,title,content):
        a=QtWidgets.QTextBrowser() 
        a.setFrameStyle(QFrame.NoFrame)
        a.setText(content)
        a.setFont(QFont('Consolas', 10, QFont.Light)) 
        tab.addTab(a,title)
            
    def cancel(self):
        share.flag_cancel = True

class ProcessingThread(QThread):
    AddPacket = pyqtSignal(list)
    Scroll    = pyqtSignal(str)
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        self.isRunning = True

    def run(self):
        """The dedicated thread to process raw packet, which is to process each raw packet and make it display in the Listctrl"""
        num = 0
        global pkt_lst
        while self.isRunning:
            try:
                p = pkt_lst.get()

            except:
                continue
            list_byte.append(p[0])
            packet = Ether(p[0])
            packet.time = p[1]
            packet.num = num
            packet = Packet_r(packet)
            share.list_packet.append(packet)
            if (share.flag_search == False):
                l=packet.packet_to_info()
                l.append(num)
                self.AddPacket.emit(l)
            share.list_tmp.append(packet.packet_to_info())
            num += 1
            if ((share.flag_select == False and share.flag_search == False)
                    or (share.flag_select == True and share.flag_cancel == True
                        and share.flag_search == False)):
                # make the scroll bar update
                self.Scroll.emit("True")
                #ex.tableWidget.scrollToBottom()
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


    def stop(self):
        self.isRunning = False
        self.quit()
        self.wait()
class  NetworkspeedThread(QThread):
    SetNetworkSpeed = pyqtSignal(list)
    def __init__(self, parent=None):
        QThread.__init__(self, parent=parent)
        self.isRunning = True

    def run(self):
        """The dedicated thread to caculate networkspeed"""
        s_up=0.00
        s_down=0.00
        while (share.mac==''):
            sleep(0.5)
        t0 = time.time()
        macname=share.dict_mac2name[share.mac]
        upload=psutil.net_io_counters(pernic=True)[macname][0]
        download=psutil.net_io_counters(pernic=True)[macname][1]
        up_down=(upload,download)
        while self.isRunning:
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
            self.SetNetworkSpeed.emit([int(s_up),int(s_down)])

    def stop(self):
        self.isRunning = False
        self.quit()
        self.wait()


def InputToFilter(flag_dict):
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
    return f

def InfiniteProcess(flag_dict, pkt_lst):
    """The dedicated process to sniff, which is to get the iface and filter and then starting sniffing"""
    while (flag_dict['close'] == False):
        sleep(0.1)
        if (flag_dict['start'] == True and flag_dict['error'] == False):
            sleep(0.1)
            f=InputToFilter(flag_dict)
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

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
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
    flag_dict['iface'] = share.interfaces[0]
    flag_dict['pro'] = ''
    flag_dict['src'] = ''
    flag_dict['sport'] = ''
    flag_dict['dst'] = ''
    flag_dict['dport'] = ''

    flag_dict['mac']=''
    flag_dict['up']=0
    flag_dict['down']=0
    list_byte=manager.list()
    list_info=manager.list()
    # list to store and fetch packet
    pkt_lst = manager.Queue()
    p = Process(target=InfiniteProcess, name="InfiniteProcess", args=(flag_dict, pkt_lst))
    p.daemon = True
    p.start()
    flag_dict["select"]=False

    w = QtWidgets.QMainWindow()
    ex = Ui_MainWindow()
 
    
    
    ex.setupUi(w)
    w.show()
    sys.exit(app.exec_())
    p.terminate()