#!/usr/bin/python3
# Author: Oier Saizar
import subprocess as sp
from sys import getsizeof

EXECUTE = False

class Command():

    def __init__(self):
        self.cla = ""
        self.ins = ""
        self.p1 = ""
        self.p2 = ""
        self.lc = ""
        self.datos = ""
        self.le = ""
        self.dfname = ""

    def toString(self):
        rt = ""
        if self.cla != "":
            rt += self.cla+" "
        if self.ins != "":
            rt += self.ins+" "
        if self.p1 != "":
            rt += self.p1+" "
        if self.p2 != "":
            rt += self.p2+" "
        if self.lc != "":
            rt += self.lc+" "
        if self.datos != "":
            rt += self.datos+" "
        if self.le != "":
            rt += self.le+" "
        if self.dfname != "":
            rt += self.dfname+" "

        return rt[:-1]

def int_to_hex_str(n, bytelength=0):
    if str(n)[:2] != "0x" and str(n)[:2] != "0X":
        hx = "%x" % int(n)
    else:
        hx = n[2:]
    if len(hx) % 2 == 1:
        hx = "0"+hx
    rt = ' '.join(a+b for a,b in zip(hx[::2], hx[1::2]))
    if bytelength != 0:
        l = bytelength - len(rt.split(" "))
        rt = ("00 "*l)+rt
    return rt

def parse_string(data): # can be a hex number (0xnnnnn) or a string -> nn nn nn nn
    if data[:2] == "0x" and data[:2] == "0X": # it's a hex number
        hx = data[2:]
    else: # it's text
        hx = data.encode("ascii").hex()

    if len(hx) % 2 == 1:
        hx = "0"+hx
    rt = ' '.join(a+b for a,b in zip(hx[::2], hx[1::2]))
    return rt

def parse_out(out):
    rt = {"response" : "", "status" : ""}
    lines = out.split("\n")
    rt["response"] = lines[-2]
    rt["status"] = lines[-1]

    return rt

def send_command(cmd):
    stdout = sp.getoutput("echo '{0}' | scriptor".format(cmd))
    out = parse_out(stdout)
    return out

def select_file(cmd):
    command = Command()
    cmd = cmd.split(" ")
    mode = cmd[1]
    data = int_to_hex_str(''.join(cmd[2:]))

    command.cla = "00"
    command.ins = "A4"

    if mode == "n":
        command.p1 = "04"
        command.p2 = "00"
        command.lc = int_to_hex_str(len(data.split(" ")))
        command.datos = data
    else: # mode i
        command.p1 = "02"
        command.p2 = "00"
        command.lc = "02"
        command.datos = data
        command.le = "0C"

    return command.toString()

def read_binary(cmd):
    command = Command()
    cmd = cmd.split(" ")

    command.cla = "00"
    command.ins = "B0"

    if len(cmd) > 3: # implicit id
        command.p1 = int_to_hex_str(int('10000000', 2) + int(cmd[4], 16))
        command.p2 = int_to_hex_str(cmd[1])
    else:
        offset = int_to_hex_str(cmd[1], bytelength=2).split(" ")
        command.p2 = offset[0]
        command.p1 = offset[1]

    command.le = int_to_hex_str(cmd[2])

    return command.toString()

def update_binary(cmd):
    command = Command()
    cmd = cmd.split(" ")

    command.cla = "00"
    command.ins = "D6"


    if cmd[2] == "id": # implicit id
        command.p1 = int_to_hex_str(int('10000000', 2) + int(cmd[3], 16))
        command.p2 = int_to_hex_str(cmd[1])
        data = parse_string(''.join(cmd[4:]))
    else:
        offset = int_to_hex_str(cmd[1], bytelength=2).split(" ")
        command.p2 = offset[0]
        command.p1 = offset[1]
        data = parse_string(''.join(cmd[2:]))


    command.lc = int_to_hex_str(len(data.split(" ")))
    command.datos = data
    command.le = "00"

    return command.toString()

def read_record(cmd): # TODO: add id
    command = Command()
    cmd = cmd.split(" ")

    command.cla = "00"
    command.ins = "B2"
    command.p1 = int_to_hex_str(cmd[1])

    if cmd[2] == "id": # implicit id
        command.p2 = int_to_hex_str(int('100', 2) + (int(cmd[3], 16)*2)**2) # shiftear 2
        command.le = int_to_hex_str(cmd[4])
    else:
        command.p2 = "04"
        command.le = int_to_hex_str(cmd[3])

    return command.toString()

def update_record(cmd):
    command = Command()
    cmd = cmd.split(" ")

    command.cla = "00"
    command.ins = "DC"
    command.p1 = int_to_hex_str(cmd[1])

    if cmd[2] == "id": # implicit id
        command.p2 = int_to_hex_str(int('100', 2) + (int(cmd[3], 16)*2)**2) # shiftear 2
        data = parse_string(''.join(cmd[4:]))
    else:
        command.p2 = "04"
        data = parse_string(''.join(cmd[2:]))

    command.lc = int_to_hex_str(len(data.split(" ")))
    command.datos = data

    return command.toString()

def append_record(cmd):
    command = Command()
    cmd = cmd.split(" ")
    data = parse_string(''.join(cmd[1:]))

    command.cla = "00"
    command.ins = "E2"
    command.p1 = "00"
    command.p2 = "00"
    command.lc = int_to_hex_str(len(data.split(" ")))
    command.datos = data

    return command.toString()

"""
create file data (file info):
    Identificador del fichero, 2 bytes
    Tipo de fichero, 1 byte
    Byte de opciones del fichero, 1 byte
    Tamaño del fichero, 2 bytes
    Condiciones de acceso al fichero en actualización e indicador de mecanismo de recuperación de datos,
    1 byte
"""

def create_file(cmd):
    command = Command()
    cmd = cmd.split(" ")
    mode = cmd[1]
    data = int_to_hex_str(cmd[2]) # file info

    command.cla = "80"
    command.ins = "E0"
    command.p1 = "00"
    command.p2 = "00"

    if mode == "df":
        name = parse_string(cmd[3])
        command.lc = int_to_hex_str(len(name.split(" ")))
        command.datos = data
        command.dfname = name
    else: # mode ef
        command.lc = "08"
        command.datos = data

    return command.toString()

def get_response(cmd):
    command = Command()
    cmd = cmd.split(" ")

    command.cla = "00"
    command.ins = "C0"
    command.p1 = "00"
    command.p2 = "00"
    command.le = int_to_hex_str(cmd[1])

    return command.toString()

def print_help():
    help = """
    select-file n <name>
    select-file id <id>

    read-binary <offset> <readlen> [id <id>]

    update-binary <offset> [id <id>] <data>

    read-record <readlen>
    update-record <regnum> <data>
    append-record <data>

    create-file df <fileinfo> <name>
    create-file ef <fileinfo>

    get-response <bites>
    """
    print (help)

def main():
    try:
        cmd = ""
        while cmd != "exit":
            cmd = input("> ")
            if cmd == "exit":
                continue
            elif "select-file" in cmd:
                cmd = select_file(cmd)
            elif "read-binary" in cmd:
                cmd = read_binary(cmd)
            elif "update-binary" in cmd:
                cmd = update_binary(cmd)
            elif "read-record" in cmd:
                cmd = read_record(cmd)
            elif "update-record" in cmd:
                cmd = update_record(cmd)
            elif "append-record" in cmd:
                cmd = append_record(cmd)
            elif "create-file" in cmd:
                cmd = create_file(cmd)
            elif "get-response" in cmd:
                cmd = get_response(cmd)
            elif "internal-authenticate" in cmd:
                cmd = internal_authenticate(cmd)
            elif "help" in cmd:
                print_help()

            print(cmd)

            if EXECUTE:
                resp = send_command(cmd)
                print ("{0}\n{1}".format(resp["response"], resp["status"]))

    except KeyboardInterrupt:
        print ("\nCtrl+c exiting...")

if __name__ == "__main__":
    main()
