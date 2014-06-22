

def PCI_Mask_PAN(pan):
    """

    input  = 123456785233547890
    result = 123456********7890
    """
    return pan[:6] + ("*" * (len(pan)-10)) + pan[-4:] 

if __name__ == '__main__':
    pass