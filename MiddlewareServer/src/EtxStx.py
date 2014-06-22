STX = "\x02"
ETX = "\x03"

def IsStxEtxPacket(packet):
    if (len(packet) >= 3):
        if (packet[0] == STX) and (packet[-2] == ETX):
            return True
        else:
            return False
    else:
        return False

def CalcLRC(packet):
    lrc = 0
    for s in packet[1:]:
        lrc = lrc ^ ord(s)
    return lrc

def AddLRC(packet):
    lrc = CalcLRC(packet)
    return "%s%s" % (packet, chr(lrc))

if __name__ == "__main__":
    print AddLRC("CC")
