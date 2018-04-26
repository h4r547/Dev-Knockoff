from scapy.all import *
import os

def get_iface():
    no = 1
    ifaces = os.listdir("/sys/class/net")
    for iface in ifaces:
        print "["+str(no)+"] "+iface
        no += 1
    choice = raw_input("Enter Wireless Interface to Use: ")
    return ifaces[int(choice)-1]


def in_monitor(iface):
    chk = os.popen("iwconfig " + iface + " | grep Monitor").read()
    if chk == "":
        return False
    else:
        return True


def set_monitor(op, iface):
    os.system("sudo ifconfig " + iface + " down")
    if op == 1:
        os.system("sudo iw dev "+iface+" set type monitor")
    elif op == 0:
        os.system("sudo iw dev "+iface+" set type managed")
    else:
        print "Invalid choice"
    os.system("sudo ifconfig " + iface + " up")
    return in_monitor(iface)


def monitor_mode(iface):
    is_monitor = in_monitor(iface)

    if is_monitor:
        print "[+] Monitor mode enabled on " + iface
    else:
        while not is_monitor:
            print "[x] Monitor mode not enabled on " + iface + "\n[+] Enabling Monitor mode"
            is_monitor = set_monitor(1, iface)
            if is_monitor:
                print "[+] Monitor mode enabled on " + iface


def clean_up(iface):
    print "[+] Cleaning up the goodness :("
    set_monitor(0, iface)
    exit()


