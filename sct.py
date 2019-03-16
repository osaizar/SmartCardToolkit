#!/usr/bin/python3
# Author: Oier Saizar
import subprocess as sp
from cmd import Cmd
import crypto as c

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
        self.s2 = ""

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
        if self.s2 != "":
            rt += self.s2+" "
        if self.le != "":
            rt += self.le+" "
        if self.dfname != "":
            rt += self.dfname+" "

        return rt[:-1]

class Prompt(Cmd):

    def do_select_file(self, cmd):
        command = Command()
        cmd = cmd.split(" ")
        mode = cmd[0]
        data = parse_string(''.join(cmd[1:]))

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

        print(command.toString())

    def do_read_binary(self, cmd):
        command = Command()
        cmd = cmd.split(" ")

        command.cla = "00"
        command.ins = "B0"

        if len(cmd) > 2: # implicit id
            command.p1 = int_to_hex_str(int('10000000', 2) + int(cmd[3], 16))
            command.p2 = int_to_hex_str(cmd[0])
        else:
            offset = int_to_hex_str(cmd[0], bytelength=2).split(" ")
            command.p2 = offset[0]
            command.p1 = offset[1]

        command.le = int_to_hex_str(cmd[1])

        print(command.toString())

    def do_update_binary(self, cmd):
        command = Command()
        cmd = cmd.split(" ")

        command.cla = "00"
        command.ins = "D6"


        if cmd[1] == "id": # implicit id
            command.p1 = int_to_hex_str(int('10000000', 2) + int(cmd[2], 16))
            command.p2 = int_to_hex_str(cmd[0])
            data = parse_string(''.join(cmd[3:]))
        else:
            offset = int_to_hex_str(cmd[0], bytelength=2).split(" ")
            command.p2 = offset[0]
            command.p1 = offset[1]
            data = parse_string(''.join(cmd[1:]))


        command.lc = int_to_hex_str(len(data.split(" ")))
        command.datos = data
        command.le = "00"

        print(command.toString())

    def do_sec_update_binary(self, cmd):
        command = Command()
        sk = cmd.split(",")[1]
        cmd = cmd.split(",")[0]
        cmd = cmd.split(" ")

        command.cla = "04"
        command.ins = "D6"


        if cmd[1] == "id": # implicit id
            command.p1 = int_to_hex_str(int('10000000', 2) + int(cmd[2], 16))
            command.p2 = int_to_hex_str(cmd[0])
            data = parse_string(''.join(cmd[3:]))
        else:
            offset = int_to_hex_str(cmd[0], bytelength=2).split(" ")
            command.p2 = offset[0]
            command.p1 = offset[1]
            data = parse_string(''.join(cmd[1:]))


        command.lc = int_to_hex_str(len(data.split(" ")) + 3)
        command.datos = data

        unauth_command = command.toString()

        s2 = c.sign_command(unauth_command, sk)
        print("s2: "+s2.hex())
        sign = int_to_hex_str("0x"+s2[-3:].hex())

        command = unauth_command + " "+sign + " 03" # le 03

        print(command)

    def do_enc_sec_update_binary(self, cmd):
        command = Command()
        sk = cmd.split(",")[1]
        cmd = cmd.split(",")[0]
        cmd = cmd.split(" ")

        command.cla = "04"
        command.ins = "D6"


        if cmd[1] == "id": # implicit id
            command.p1 = int_to_hex_str(int('10000000', 2) + int(cmd[2], 16))
            command.p2 = int_to_hex_str(cmd[0])
            data = parse_string(''.join(cmd[3:]))
        else:
            offset = int_to_hex_str(cmd[0], bytelength=2).split(" ")
            command.p2 = offset[0]
            command.p1 = offset[1]
            data = parse_string(''.join(cmd[1:]))

        command.lc = int_to_hex_str(len(data.split(" ")) + 3)
        command.datos = data

        unauth_command = command.toString()

        s2 = c.sign_command(unauth_command, sk)
        print("s2: "+s2.hex())
        sign = int_to_hex_str("0x"+s2[-3:].hex())

        edata = c.encrypt_data(data, sk)
        command.datos = int_to_hex_str("0x"+edata)

        command = command.toString() + " "+sign + " 03" # le 03

        print(command)

    def do_read_record(self, cmd):
        command = Command()
        cmd = cmd.split(" ")

        command.cla = "00"
        command.ins = "B2"
        command.p1 = int_to_hex_str(cmd[0])

        if cmd[1] == "id": # implicit id
            command.p2 = int_to_hex_str(int('100', 2) + (int(cmd[2], 16)*2)**2) # shiftear 2
            command.le = int_to_hex_str(cmd[3])
        else:
            command.p2 = "04"
            command.le = int_to_hex_str(cmd[2])

        print(command.toString())

    def do_update_record(self, cmd):
        command = Command()
        cmd = cmd.split(" ")

        command.cla = "00"
        command.ins = "DC"
        command.p1 = int_to_hex_str(cmd[0])

        if cmd[1] == "id": # implicit id
            command.p2 = int_to_hex_str(int('100', 2) + (int(cmd[2], 16)*2)**2) # shiftear 2
            data = parse_string(''.join(cmd[3:]))
        else:
            command.p2 = "04"
            data = parse_string(''.join(cmd[1:]))

        command.lc = int_to_hex_str(len(data.split(" ")))
        command.datos = data

        print(command.toString())

    def do_sec_update_record(self, cmd):
        command = Command()
        sk = cmd.split(",")[1]
        cmd = cmd.split(",")[0]
        cmd = cmd.split(" ")

        command.cla = "00"
        command.ins = "DC"
        command.p1 = int_to_hex_str(cmd[0])

        if cmd[1] == "id": # implicit id
            command.p2 = int_to_hex_str(int('100', 2) + (int(cmd[2], 16)*2)**2) # shiftear 2
            data = parse_string(''.join(cmd[3:]))
        else:
            command.p2 = "04"
            data = parse_string(''.join(cmd[1:]))

        command.lc = int_to_hex_str(len(data.split(" ")) + 3)
        command.datos = data

        unauth_command = command.toString()

        s2 = c.sign_command(unauth_command, sk)
        print("s2: "+s2.hex())
        sign = int_to_hex_str("0x"+s2[-3:].hex())

        command = unauth_command + " "+sign + " 03" # le 03

        print(command)

    def do_append_record(self, cmd):
        command = Command()
        cmd = cmd.split(" ")
        data = parse_string(''.join(cmd))

        command.cla = "00"
        command.ins = "E2"
        command.p1 = "00"
        command.p2 = "00"
        command.lc = int_to_hex_str(len(data.split(" ")))
        command.datos = data

        print(command.toString())

    def do_sec_append_record(self, cmd):
        command = Command()
        sk = cmd.split(",")[1]
        cmd = cmd.split(",")[0]
        cmd = cmd.split(" ")
        data = parse_string(''.join(cmd))

        command.cla = "00"
        command.ins = "E2"
        command.p1 = "00"
        command.p2 = "00"
        command.lc = int_to_hex_str(len(data.split(" ")) + 3)
        command.datos = data

        unauth_command = command.toString()

        s2 = c.sign_command(unauth_command, sk)
        print("s2: "+s2.hex())
        sign = int_to_hex_str("0x"+s2[-3:].hex())

        command = unauth_command + " "+sign + " 03" # le 03

        print(command)

    def do_create_file(self, cmd):
        command = Command()
        cmd = cmd.split(" ")
        mode = cmd[0]
        data = int_to_hex_str(cmd[1]) # file info

        command.cla = "80"
        command.ins = "E0"
        command.p1 = "00"
        command.p2 = "00"

        if mode == "df":
            name = parse_string(cmd[2])
            command.lc = int_to_hex_str(len(name.split(" ")))
            command.datos = data
            command.dfname = name
        else: # mode ef
            command.lc = "08"
            command.datos = data

        print(command.toString())

    def do_sec_create_file(self, cmd):
        command = Command()
        sk = cmd.split(",")[1]
        cmd = cmd.split(",")[0]
        cmd = cmd.split(" ")
        mode = cmd[0]
        data = int_to_hex_str(cmd[1]) # file info

        command.cla = "84"
        command.ins = "E0"
        command.p1 = "00"
        command.p2 = "00"

        if mode == "df":
            name = parse_string(cmd[2])
            command.lc = int_to_hex_str(len(name.split(" ")) + 3)
            command.datos = data
            command.dfname = name
        else: # mode ef
            command.lc = "0B"
            command.datos = data

        unauth_command = command.toString()

        s2 = c.sign_command(unauth_command, sk)
        print("s2: "+s2.hex())
        sign = int_to_hex_str("0x"+s2[-3:].hex())

        command = unauth_command + " "+sign + " 03" # le 03

        print(command)

    def do_enc_sec_create_file(self, cmd):
        command = Command()
        sk = cmd.split(",")[1]
        cmd = cmd.split(",")[0]
        cmd = cmd.split(" ")
        mode = cmd[0]
        data = int_to_hex_str(cmd[1]) # file info

        command.cla = "84"
        command.ins = "E0"
        command.p1 = "00"
        command.p2 = "00"

        if mode == "df":
            name = parse_string(cmd[2])
            command.lc = int_to_hex_str(len(name.split(" ")) + 3)
            command.datos = data
            command.dfname = name
        else: # mode ef
            command.lc = "0B"
            command.datos = data

        unauth_command = command.toString()

        s2 = c.sign_command(unauth_command, sk)
        print("s2: "+s2.hex())
        sign = int_to_hex_str("0x"+s2[-3:].hex())

        edata = c.encrypt_data(data, sk)
        command.datos = int_to_hex_str("0x"+edata)

        command = command.toString() + " "+sign + " 03" # le 03

        print(command)

    def do_get_response(self, cmd):
        command = Command()
        cmd = cmd.split(" ")

        command.cla = "00"
        command.ins = "C0"
        command.p1 = "00"
        command.p2 = "00"
        command.le = int_to_hex_str(cmd[0])

        print(command.toString())

    def do_internal_authenticate(self, cmd):
        command = Command()
        cmd = cmd.split(" ")
        option = cmd[0]

        command.cla = "00"
        command.ins = "88"
        command.p1 = "00"

        if option == "local":
            command.p2 = "80"
        else: # global
            command.p2 = "00"

        rn = c.get_rn()
        print ("Sending RN : "+str(rn))
        command.lc = "08"
        command.datos = rn
        command.le = "0A"

        print(command.toString())

    def do_check_rn(self, cmd):
        command = Command()
        cmd = cmd.split(" ")
        rn = ' '.join(c for c in cmd[0:8])
        nt = ' '.join(c for c in cmd[8:10])
        rnc = ' '.join(c for c in cmd[10:18])

        print(str(c.check_rnc(nt, rnc, rn)))

    def do_get_sk(self, cmd):
        command = Command()
        cmd = cmd.split(" ")
        nt = ' '.join(c for c in cmd[0:3])
        print(c.get_sk(nt))

    def do_encrypt_data(self, cmd):
        sk = cmd.split(",")[1]
        data = ''.join(cmd.split(",")[0].split(" "))
        edata = c.encrypt_data(data, sk)
        print(int_to_hex_str("0x"+edata))

    def do_help(self, cmd):
        help = """
        select_file n <name>
        select_file id <id>

        read-binary <offset> <readlen> [id <id>]

        update_binary <offset> [id <id>] <data>

        read_record <readlen>
        update_record <regnum> [id <id>] <data>
        append_record <data>

        create_file df <fileinfo> <name>
        create_file ef <fileinfo>

        internal_authenticate local
        internal_authenticate global

        check_rn <rn> <response>

        get_sk <nt>

        get_response <bites>

        sec_<command> <arguments>,<sk>
        enc_sec_<command> <arguments>,<sk>
        """
        print (help)

    def do_exit(self, args):
        print("Quitting.")
        raise SystemExit

# Helping functions

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
    if str(data)[:2] != "0x" and str(data)[:2] != "0X":
        hx = data.encode("ascii").hex()
    else: # it's hex
        hx = data[2:]

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

def send_command(self, cmd):
    stdout = sp.getoutput("echo '{0}' | scriptor".format(cmd))
    out = parse_out(stdout)
    return out

if __name__ == "__main__":
    prompt = Prompt()
    prompt.prompt = "> "
    prompt.cmdloop("Write your commands, type 'help' for help")
