from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QAction, QTableWidget,QTableWidgetItem,QVBoxLayout,QTabWidget,QProgressBar,QFileDialog
from PyQt5.QtGui import QIcon,QFont
from PyQt5.QtCore import pyqtSlot,QThread,Qt
from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QFrame, 
    QSplitter, QStyleFactory, QApplication)
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
        import wx
        import wx.adv

"""use pcap to capture in Windows"""
conf.use_pcap = True


""" psutil is used to detect network speed"""
import psutil
""" pyshark for get brief info"""
import pyshark
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

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1000, 990)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        MainWindow.setCentralWidget(self.centralwidget)

        """STATIC THING"""
        self.label_NIC = QtWidgets.QLabel(self.centralwidget)
        self.label_NIC.setGeometry(QtCore.QRect(20, -10, 81, 71))

        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_NIC.setFont(font)
        self.label_NIC.setObjectName("label")
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(80, 10, 681, 31))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.comboBox.setFont(font)
        self.comboBox.setObjectName("comboBox")
        for i in share.interfaces:
            self.comboBox.addItem(i)
        self.comboBox.currentTextChanged.connect(self.EVT_COMBOBOX)


        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(20, 30, 81, 71))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(380, 30, 81, 71))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(200, 90, 36, 23))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setText("")
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(590, 30, 81, 71))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(770, 30, 81, 71))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(210, 30, 41, 71))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.label_7.setFont(font)
        self.label_7.setObjectName("label_7")

        self.pro = QtWidgets.QLineEdit(self.centralwidget)
        self.pro.setGeometry(QtCore.QRect(70, 50, 121, 31))
        self.pro.setObjectName("lineEdit")
        self.pro.textChanged.connect(self.EvtTextPro)

        self.src = QtWidgets.QLineEdit(self.centralwidget)
        self.src.setGeometry(QtCore.QRect(250, 50, 121, 31))
        self.src.setObjectName("lineEdit_2")
        self.src.textChanged.connect(self.EvtTextSrc)

        self.sport = QtWidgets.QLineEdit(self.centralwidget)
        self.sport.setGeometry(QtCore.QRect(450, 50, 121, 31))
        self.sport.setObjectName("lineEdit_3")
        self.sport.textChanged.connect(self.EvtTextSport)

        self.dst = QtWidgets.QLineEdit(self.centralwidget)
        self.dst.setGeometry(QtCore.QRect(640, 50, 121, 31))
        self.dst.setObjectName("lineEdit_4")
        self.dst.textChanged.connect(self.EvtTextDst)

        self.dport = QtWidgets.QLineEdit(self.centralwidget)
        self.dport.setGeometry(QtCore.QRect(840, 50, 121, 31))
        self.dport.setObjectName("lineEdit_5")
        self.dport.textChanged.connect(self.EvtTextDport)

        self.checkBox = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox.setGeometry(QtCore.QRect(20, 90, 61, 31))
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.checkBox.setFont(font)
        self.checkBox.setObjectName("checkBox")
        self.lineEdit_6 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_6.setGeometry(QtCore.QRect(210, 90, 381, 31))
        self.lineEdit_6.setObjectName("lineEdit_6")
        self.button = QtWidgets.QPushButton(self.centralwidget)
        self.button.setGeometry(QtCore.QRect(640, 90, 121, 28))
        self.button.setObjectName("pushButton")
        self.button.clicked.connect(self.EvtStart)

        self.save = QtWidgets.QPushButton(self.centralwidget)
        self.save.setGeometry(QtCore.QRect(840, 90, 121, 28))
        self.save.setObjectName("pushButton_2")

        """button: continue to reassemble"""
        self.continue_reassemble_button = QtWidgets.QPushButton(self.centralwidget)
        self.continue_reassemble_button.setGeometry(QtCore.QRect(200, 930, 300, 40))
        self.continue_reassemble_button.setText("Continue to reassemble")
        self.continue_reassemble_button.setFont(QFont('Consolas', 11, QFont.Light))
        self.continue_reassemble_button.clicked.connect(self.EvtContinueReassemble)
        self.continue_reassemble_button.hide()

        self.save_reassemble_button = QtWidgets.QPushButton(self.centralwidget)
        self.save_reassemble_button.setGeometry(QtCore.QRect(500, 930, 300, 40))
        self.save_reassemble_button.setText("Save reassembly Result")
        self.save_reassemble_button.setFont(QFont('Consolas', 11, QFont.Light))
        self.save_reassemble_button.clicked.connect(self.EvtSaveReassemble)
        self.save_reassemble_button.hide()
        """table """
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.tableWidget.verticalHeader().setDefaultSectionSize(25)
        self.tableWidget.horizontalHeader().setFont(QFont('Consolas', 11, QFont.Light))
        self.tableWidget.setSizeAdjustPolicy(
        QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.tableWidget.setMinimumHeight(50)
        self.tableWidget.setColumnCount(6)
        self.tableWidget.setHorizontalHeaderLabels(['No.', 'Time', 'Source address', 'Destination address', 'Length','Protocol'])
        self.tableWidget.setColumnWidth(0,60)
        self.tableWidget.setColumnWidth(1,100)
        self.tableWidget.setColumnWidth(2,280)
        self.tableWidget.setColumnWidth(3,280)
        self.tableWidget.setColumnWidth(4,75)
        self.tableWidget.setColumnWidth(5,145)
        self.tableWidget.setShowGrid(False)
        self.tableWidget.setFont(QFont('Consolas', 10, QFont.Light))
        
        self.tableWidget.itemSelectionChanged.connect(self.EvtSelect)
        self.tableWidget.itemDoubleClicked.connect(self.cancel)
        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.setMouseTracking(True)
        self.tableWidget.cellEntered.connect(self.handleItemEntered)
        self.tableWidget.verticalHeader().setVisible(False)

        """tab1"""
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setMinimumHeight(50)
        self.tabWidget.setFont(QFont('Consolas', 10, QFont.Light))
        """tab2"""
        self.tabWidget_2 = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget_2.setMinimumHeight(50)
        self.tabWidget_2.setFont(QFont('Consolas', 10, QFont.Light))

        """split window"""
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(0, 130,1000, 800))
        
        hbox = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        hbox.setContentsMargins(0, 0, 0, 0)
     
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.tableWidget)
        splitter.addWidget(self.tabWidget)
        splitter.addWidget(self.tabWidget_2)
        splitter.setSizes([300,300,300])
        hbox.addWidget(splitter)


        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setFixedHeight(20)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        """progressbar"""
        self.pbar=QProgressBar()
        self.pbar.setValue(0)
        self.pbar.setFixedWidth(1000)
        self.statusbar.addPermanentWidget(self.pbar)
        self.pbar.hide()
        self.retranslateUi(MainWindow)

        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_NIC.setText(_translate("MainWindow", "NIC"))
        self.label_2.setText(_translate("MainWindow", "PRO"))
        self.label_3.setText(_translate("MainWindow", "SPORT"))
        self.label_5.setText(_translate("MainWindow", "DST"))
        self.label_6.setText(_translate("MainWindow", "DPORT"))
        self.label_7.setText(_translate("MainWindow", "SRC"))
        self.checkBox.setText(_translate("MainWindow", "MAX"))
        self.button.setText(_translate("MainWindow", "START"))
        self.save.setText(_translate("MainWindow", "SAVE"))
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
        else:
            self.button.setText('Start')

    def handleItemEntered(self,row,column):
        '''for i in range(self.tabWidget.count()):
            self.tabWidget.removeTab(i)'''
        

    def EvtSelect(self):
        try:
            self.continue_reassemble_button.hide()
            self.save_reassemble_button.hide()
            self.pbar.hide()
        except:
            pass
        for i in self.tableWidget.selectedItems():
            val=i.row()
        share.flag_select = True
        share.flag_cancel = False
        
        self.final_tcp_seq = ""
        self.final_ip_seq = ""
        count=self.tabWidget.count()
        for i in range(self.tabWidget.count()):
            self.tabWidget.removeTab(0)
        for i in range(self.tabWidget_2.count()):
            self.tabWidget_2.removeTab(0)
        
        layerlist = share.list_packet[val].packet_to_layerlist()

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
        if (self.final_ip_seq==""):
            self.ShowTcpResult()
        else:
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
def process():
    """The dedicated thread to process raw packet, which is to process each raw packet and make it display in the Listctrl"""
    num = 0
    global pkt_lst
    while (True):
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
            ex.tableWidget.insertRow(num)
            l=packet.packet_to_info()
            for i in range(6):
                item= QTableWidgetItem(l[i])
                ex.tableWidget.setItem(num,i, item)
        share.list_tmp.append(packet.packet_to_info())
        num += 1
        if ((share.flag_select == False and share.flag_search == False)
                or (share.flag_select == True and share.flag_cancel == True
                    and share.flag_search == False)):
            # make the scroll bar update
            ex.tableWidget.scrollToBottom()
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
    finish = False
    process_list = [process]
    thread_list = []
    w = QtWidgets.QMainWindow()
    ex = Ui_MainWindow()
    for i in range(len(process_list)):
        thread_list.append(Thread(target=process_list[i]))
        thread_list[i].setDaemon(1)
        thread_list[i].start()
    
    
    ex.setupUi(w)
    w.show()
    sys.exit(app.exec_())
    p.terminate()