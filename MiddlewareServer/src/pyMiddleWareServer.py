import os
import logging
import logging.handlers
import socket
import ssl
from threading import Thread
import time
import uuid
import collections
import ConfigParser
import string
from datetime import datetime

import MySQLdb

from StringToAscii import *
from EtxStx import AddLRC
import AuthCodeMapping
import PCI_DSS


# Setup the  logger to a file


log = logging.getLogger()
log.setLevel(level=logging.INFO)

# make sure the logging directory exists
dirname = "../log"
if not os.path.isdir("./" + dirname + "/"):
    os.mkdir("./" + dirname + "/")

#Add rotating file handler to logger
handler = logging.handlers.TimedRotatingFileHandler('../log/debug.log', when="MIDNIGHT", backupCount=90)
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

#Add another one to log all INFO stuff to a different file
info = logging.handlers.TimedRotatingFileHandler('../log/info.log', when="MIDNIGHT", backupCount=90)
info.setLevel(logging.INFO)
info.setFormatter(formatter)
log.addHandler(info)

#Add another one to log all CRITICAL stuff to a different file
critical = logging.handlers.TimedRotatingFileHandler('../log/critical.log', when="MIDNIGHT", backupCount=90)
critical.setLevel(logging.CRITICAL)
critical.setFormatter(formatter)
log.addHandler(critical)

#Add a second logger, showing the same stuff to stderr
console = logging.StreamHandler()
console.setLevel(log.level)
console.setFormatter(formatter)
log.addHandler(console)

from daemon import Daemon

q = collections.deque()

_CurrentConfig = {
    "middleware_server.dbserver": "127.0.0.1",
    "middleware_server.dbdatabase": "middleware",
    "middleware_server.dbusername": "root",
    "middleware_server.dbpassword": "",
    "middleware_server.listening_port": "9000",
    "middleware_server.destination_host": "127.0.0.1",
    "middleware_server.destination_port": "9000",
    "middleware_server.destination_timeout": "10",
}



#-----------------------------------------------------------------------------
def LoadConfig(file, config={}, session=None):
    """
    returns a dictionary with key's of the form
    <section>.<option> and the values 
    """
    if session == None:
        SessionUUID = ''
    else:
        SessionUUID = session.SessionUUID
    log.debug('%s:    LoadConfiguration(%s)' % (SessionUUID, file,))
    config = config.copy()
    cp = ConfigParser.ConfigParser()
    cp.read(file)
    for sec in cp.sections():
        name = string.lower(sec)
        for opt in cp.options(sec):
            config[name + "." + string.lower(opt)] = string.strip(cp.get(sec, opt))
    return config

#-----------------------------------------------------------------------------
class LogEntry():
    logRetries = 0

    def __init__(self):
        self.logRetries = 0

#-----------------------------------------------------------------------------
class Session():
    SessionUUID = uuid.UUID
    Type = ""
    source_ip = ""
    destination_ip = ""
    destination_port = ""
    destination_timeout = ""
    request = ""
    response = ""
    error = ""
    ENQ_count = 0
    REQ_count = 0
    RES_count = 0
    ACK_req = 0
    ACK_res = 0
    NAK_req = 0
    NAK_res = 0
    EOT_req = 0
    EOT_res = 0
    PAN = ""
    service_code = ""
    AtmID = ""
    decline = False


    def __init__(self):
        self.SessionUUID = uuid.uuid1()
        self.Type = ""
        self.source_ip = ""
        self.destination_ip = ""
        self.destination_port = ""
        self.destination_timeout = ""
        self.request = ""
        self.response = ""
        self.error = ""
        self.ENQ_count = 0
        self.REQ_count = 0
        self.RES_count = 0
        self.ACK_req = 0
        self.ACK_res = 0
        self.NAK_req = 0
        self.NAK_res = 0
        self.EOT_req = 0
        self.EOT_res = 0
        self.PAN = ""
        self.service_code = ""
        self.AtmID = ""
        self.decline = False

#-----------------------------------------------------------------------------
class MyDaemon(Daemon):
    def __init__(self, pidfile):
        Daemon.__init__(self, pidfile)
        self.log = logging.getLogger('MyDaemon')

    def run(self):
        self.log.info('run() Start')

        try:
            Pinhole(_CurrentConfig['middleware_server.listening_port']).start()
            QueueLogger().start()
        except:
            self.log.exception('Exception')
        else:
            while True:
                time.sleep(60)
                self.log.info("------RUNNING------")
        self.log.debug('run() End')

#-----------------------------------------------------------------------------
class QueueLogger(Thread):
    running = False

    def __init__(self):
        Thread.__init__(self)
        self.log = logging.getLogger('QueueLogger')
        self.log.debug('__init__')
        self.CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        self.running = False

        try:
            self.connect()
            self.running = True
        except:
            self.log.exception("Connecting to Database")


    def connect(self):
        try:
            # Connect to DB
            self.con = MySQLdb.connect(
                host=self.CurrentConfig['middleware_server.dbserver'],
                port=int(self.CurrentConfig['middleware_server.dbport']),
                db=self.CurrentConfig['middleware_server.dbdatabase'],
                user=self.CurrentConfig['middleware_server.dbusername'],
                passwd=self.CurrentConfig['middleware_server.dbpassword'])
            self.log.info("Connected to Database %s" % (self.con,))
        except Exception as e:
            self.log.exception("Connecting to Database Failed")


    def run(self):
        while self.running:
            try:
                #self.log.debug('Getting whatever is in the Q')
                try:
                    l = q.pop()
                except:
                    self.log.debug('Nothing in the Queue, sleeping for 10 seconds')
                    time.sleep(10)
                else:
                    self.log.debug("Item in Queue Arrived = %s %s" % (l.__class__, l.__dict__))
                    if l.Type == 'Raw Message':
                        cur = self.con.cursor(MySQLdb.cursors.DictCursor)
                        sql = """
                            INSERT INTO messages
                            (session_uuid, message_time, source_ip, destination_ip, direction, data)
                            VALUES
                            ('%s', '%s', '%s', '%s', '%s', '%s')
                              """ % (
                            l.session.SessionUUID,
                            l.message_time,
                            l.session.source_ip,
                            l.session.destination_ip,
                            l.direction,
                            MySQLdb.escape_string(l.AsciiData))
                        #self.log.debug('SQL = %s' % (sql,))
                        cur.execute(sql)
                        cur.close()

            except Exception as e:
                self.log.critical("Error Logging Record: %s %s" % (e.args[0], e.args[1]))
                l.logRetries += 1
                self.connect()
                time.sleep(10)
                if l.logRetries >= 10:
                    self.log.critical("Not Logged: %s %s" % (l.__class__, l.__dict__))
                else:
                    q.append(l)
                    pass

#-----------------------------------------------------------------------------
class RequestThread(Thread):
    RequestPipes = []


    def __init__(self, session, source, sink):
        Thread.__init__(self)
        self.log = logging.getLogger('Request')
        self.session = session
        self.source = source
        self.sink = sink

        self.log.debug('%s: >  Creating new REQUEST THREAD  %s ( %s -> %s )' %
                       ( self.session.SessionUUID, self, source.getpeername(), sink.getpeername() ))
        RequestThread.RequestPipes.append(self)
        self.log.debug('%s: >  %s RequestPipes active' % (self.session.SessionUUID, len(RequestThread.RequestPipes)))


    def run(self):
        source_active = True
        while 1:
            try:
                data = self.source.recv(4096)


            except Exception as e:
                self.log.info('%s: >  Exception reading data, breaking: %s' % (self.session.SessionUUID, e))
                break

            try:
                if not data:
                    self.log.debug('%s: >  No Data, breaking' % (self.session.SessionUUID,))
                    source_active = False #Disconnect
                    break

                AsciiData = Str2Ascii(data)
                self.log.debug('%s: >  %s' % (self.session.SessionUUID, AsciiData))
                self.LogRaw(AsciiData)
                #increment the ENQ and other stats
                if AsciiData[0:5] == '<ENQ>':
                    self.session.ENQ_count += 1
                elif AsciiData[0:5] == '<STX>':
                    self.LogSTXPacket(AsciiData)
                    self.session.REQ_count += 1
                elif AsciiData[0:5] == '<ACK>':
                    self.session.ACK_req += 1
                elif AsciiData[0:5] == '<NAK>':
                    self.session.NAK_req += 1
                elif AsciiData[0:5] == '<EOT>':
                    self.session.EOT_req += 1

                self.log.debug('%s: >  Session = %s' % (self.session.SessionUUID, self.session.__dict__, ))

                if (AsciiData[0:5] == '<NAK>') and (self.session.RES_count == 3):
                    self.log.critical('%s: NAK Issue Detected, NAK not sent to FDI' % (self.session.SessionUUID,))
                else:
                    if self.session.decline == False:
                        self.log.debug('%s: >> %s' % (self.session.SessionUUID, AsciiData))
                        self.sink.send(data)
                    else:
                        self.log.info('%s: !! This transaction will be declined' % (self.session.SessionUUID))

                        if AsciiData[0:5] == '<STX>':
                            self.log.info('%s: <  Got <STX>, Sending Decline response' % (self.session.SessionUUID))
                            decline_msg = self.buildDecline()
                        elif AsciiData[0:5] == '<ACK>':
                            self.log.info('%s: <  Got <ACK>, Sending <EOT> response' % (self.session.SessionUUID))
                            decline_msg = Ascii2Str("<EOT>")
                        elif AsciiData[0:5] == '<EOT>':
                            self.log.info('%s: <  Got <EOT>, Sending <EOT> response' % (self.session.SessionUUID))
                            decline_msg = Ascii2Str("<EOT>")
                        else:
                            self.log.info('%s: <  Got <???> Sending <NAK> response' % (self.session.SessionUUID))
                            decline_msg = Ascii2Str("<NAK>")

                        try:
                            l = LogEntry()
                            l.session = self.session
                            l.session_uuid = self.session.SessionUUID
                            l.direction = ' <'
                            l.message_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                            l.Type = "Raw Message"
                            l.AsciiData = Str2Ascii(decline_msg)
                            q.appendleft(l)
                        except:
                            self.log.exception("Logging Raw")
                        self.log.info('%s: <x %s' % (self.session.SessionUUID, Str2Ascii(decline_msg)))
                        #self.source.send(decline_msg)
            except:
                self.log.exception('%s: >  exception, breaking' % (self.session.SessionUUID,))
                break

        try:
            if source_active:
                self.source.shutdown(socket.SHUT_RD)
            else:
                self.log.debug('%s: >  Source assumed to be already closed' % (self.session.SessionUUID, ))
        except Exception as e:
            self.log.info('%s: >  Exception closing source: %s' % (self.session.SessionUUID, e))

        try:
            self.log.debug('%s: >  Closing SK' % (self.session.SessionUUID, ))
            self.sink.shutdown(socket.SHUT_WR)
        except:
            self.log.exception('%s: >  Exception closing sink' % (self.session.SessionUUID, ))

        RequestThread.RequestPipes.remove(self)
        self.log.debug('%s: >  %s RequestPipes active' % (self.session.SessionUUID, len(RequestThread.RequestPipes)))


    def buildDecline(self):
        """
        Build the decline response message as emergency
        """
        self.session.RetrievalRefNo = "99999"
        raw = "BUILD DECLINE HERE"

        raw = raw + "<ETX>"
        raw = AddLRC(Ascii2Str(raw))

        return raw

    def LogRaw(self, AsciiData):
        try:
            l = LogEntry()
            l.session = self.session
            l.session_uuid = self.session.SessionUUID
            l.direction = '> '
            l.message_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
            l.Type = "Raw Message"
            l.AsciiData = AsciiData
            q.appendleft(l)
        except:
            self.log.exception("Logging Raw")


    def LogSTXPacket(self, data):
        try:
            AsciiData = Str2Ascii(data)
            noetx = AsciiData.split("<ETX>")
            stx = noetx[0]
            stx = stx.split("<STX>")[1]
            fields = stx.split("<FS>")
            self.log.debug("%s: >  fields=%s" % (self.session.SessionUUID, fields))

            self.session.AtmID = fields[1]
            Command = fields[2]

            if Command == "11" or Command == "12" or Command == "15":
                OperationType = "CW"
                self.log.info("%s: >  AtmID=[%s], Type=[Authorization], Operation=[%s]" % (
                self.session.SessionUUID, self.session.AtmID, OperationType,))
                Track2Data = fields[4]
                self.session.PAN, self.session.service_code = ParseTrack2(Track2Data)
                self.log.info("%s: >  PAN=[%s], SC=[%s]" % (
                self.session.SessionUUID, self.session.PAN, self.session.service_code))

            elif Command == "29":
                OperationType = "RW"
                self.log.info("%s: >  AtmID=[%s], Type=[Reversal], Operation=[%s]" % (
                self.session.SessionUUID, self.session.AtmID, OperationType,))
                Track2Data = fields[4]
                self.session.PAN, self.session.service_code = ParseTrack2(Track2Data)
                self.log.info("%s: >  PAN=[%s], SC=[%s]" % (
                self.session.SessionUUID, self.session.PAN, self.session.service_code))

            elif Command == "31" or Command == "32" or Command == "35":
                OperationType = "BI"
                self.log.info("%s: >  AtmID=[%s], Type=[Balance Enquiry], Operation=[%s]" % (
                self.session.SessionUUID, self.session.AtmID, OperationType,))

            elif Command == "51":
                OperationType = "Host Totals"
                self.log.info("%s: >  AtmID=[%s], Type=[Host Totals], Command=[%s]" % (
                self.session.SessionUUID, self.session.AtmID, Command,))

            elif Command == "50":
                OperationType = "Trail Host Totals"
                self.log.info("%s: >  AtmID=[%s], Type=[Trail Host Totals], Command=[%s]" % (
                    self.session.SessionUUID, self.session.AtmID, Command,))

            elif Command == "60":
                OperationType = "Configuration Request"
                self.log.info("%s: >  AtmID=[%s], Type=[Configuration Request], Command=[%s]" % (
                self.session.SessionUUID, self.session.AtmID, Command,))

            else:
                self.log.info("%s: >  AtmID=[%s], Type=[Unknown], Command=[%s]" % (
                self.session.SessionUUID, self.session.AtmID, Command,))


        except:
            self.log.exception("%s: EE Decoding Packet" % (self.session.SessionUUID))


def LogResponsePacketConfig(fields, SessionUUID, AtmID):
    try:
        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))
        terminal_id = fields[1]
        transaction_code = fields[2]
        pin_working_key_left = fields[3]
        pin_working_key_right = fields[5]
        mac_working_key_left = fields[6]
        mac_working_key_right = fields[7]

        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            UPDATE  config_messages
            set
            pin_working_key_left = '%s',
            pin_working_key_right = '%s',
            mac_working_key_left = '%s',
            mac_working_key_right = '%s',
            session_time = '%s'
            WHERE session_uuid = '%s' and atm_id = '%s'
            """ % (
            pin_working_key_left,
            pin_working_key_right,
            mac_working_key_left,
            mac_working_key_right,
            datetime.now(),
            SessionUUID,
            terminal_id)
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogResponsePacketReversal(fields, SessionUUID, AtmID):
    try:

        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))

        response_code = fields[4]

        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """

            UPDATE reversals set response_code = '%s', reversal_response_description = '%s'
            where session_uuid = '%s' and atm_id = '%s'
                """ % (
            response_code,
            AuthCodeMapping.AUTH_CODE_MAP[response_code],
            SessionUUID,
            AtmID)
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogResponsePacketAuth(fields, SessionUUID, AtmID):
    try:

        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))

        response_code = fields[5]
        auth_no = fields[6]
        amount_1 = fields[10]
        amount_2 = fields[11]

        if amount_1.strip() == '' or amount_2.strip() == '':
            amount_1_reformat = '0.00'
            amount_2_reformat = '0.00'

        else:
            amount_1_reformat = "%s.%s" % (amount_1[:-2], amount_1[-2:])
            amount_2_reformat = "%s.%s" % (amount_2[:-2], amount_2[-2:])

        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """

        UPDATE authorizations set response_code = '%s', retrieval_ref_no = '%s', account_balance = '%s',
        auth_response_text = '%s', surcharge_amount_res = '%s'
        where session_uuid = '%s' and atm_id = '%s'
            """ % (
            response_code,
            auth_no,
            amount_1_reformat,
            AuthCodeMapping.AUTH_CODE_MAP[response_code],
            amount_2_reformat,
            SessionUUID,
            AtmID)

        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogResponsePacketHostTotals(fields, SessionUUID, AtmID):
    try:
        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))
        terminal_id = fields[1]
        transaction_code = fields[2]
        business_date = fields[3]
        totals_data = fields[4]
        no_withdrawals = totals_data[0:4]
        no_enquiries = totals_data[4:8]
        no_transfers = totals_data[8:12]
        settlement = totals_data[12:20]
        settlement_reformat = "%s.%s" % (settlement[:-2], settlement[-2:])

        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            UPDATE host_totals set num_of_cw = '%s',
            num_of_transfers = '%s',
            num_of_bi = '%s',
            amount_cash_dispensed = '%s',
            host_date = '%s'
            WHERE session_uuid = '%s' and atm_id = '%s' and operation_code = '%s'
            """ % (
            no_withdrawals,
            no_transfers,
            no_enquiries,
            settlement_reformat,
            business_date,
            SessionUUID,
            terminal_id,
            transaction_code)
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogReqConfig(fields, SessionUUID):
    try:
        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))
        terminal_id = fields[1]
        transaction_code = fields[2]
        status_monitoring = fields[3]

        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            INSERT INTO config_messages
            (session_uuid, session_time, atm_id)
            VALUES
            ('%s', '%s', '%s')
            """ % (
            SessionUUID,
            datetime.now(),
            terminal_id)
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogReqPacketHostTotals(fields, SessionUUID, trantype):
    try:
        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))
        terminal_id = fields[1]
        transaction_code = fields[2]
        status_monitoring = fields[3]

        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            INSERT INTO host_totals
            (session_uuid, session_time, atm_id,  operation_code, trantype)
            VALUES
            ('%s', '%s', '%s', '%s', '%s')
            """ % (
            SessionUUID,
            datetime.now(),
            terminal_id,
            transaction_code,
            trantype)
        #log.info(sql)
        cur.execute(sql)

        #log health message (Status monitoring)
        session_uuid = SessionUUID
        middleware_id = 0
        session_time = datetime.now().strftime('%d%m%y')
        atm_id = terminal_id
        atm_date = datetime.now().strftime('%d%m%y')
        atm_time = datetime.now().strftime('%H%M%S')
        program_version_no = status_monitoring[0:10]
        table_version_no = status_monitoring[10:20]
        firmware_version_no = status_monitoring[20:30]
        alarm_chest_door_open = status_monitoring[30:31]
        alarm_top_door_open = status_monitoring[31:32]
        alarm_supervisor_active = status_monitoring[32:33]
        reciept_printer_paper_status = status_monitoring[33:34]
        reciept_printer_ribbon_status = status_monitoring[34:35]
        journal_printer_paper_status = status_monitoring[35:36]
        journal_printer_ribbon_status = status_monitoring[36:37]
        note_status_dispenser = status_monitoring[37:38]
        reciept_printer = status_monitoring[38:39]
        journal_printer = status_monitoring[39:40]
        dispenser = status_monitoring[40:41]
        communication_system = status_monitoring[41:42]
        cardreader = status_monitoring[42:43]
        cards_retained = status_monitoring[43:46]

        electronic_system = status_monitoring[46:48]
        current_error_code = status_monitoring[48:51]
        communication_failures = status_monitoring[51:54]

        cassetteA_denomination = status_monitoring[54:57]
        cassetteA_notes_loaded = status_monitoring[57:61]
        cassetteA_notes_dispensed = status_monitoring[61:65]
        cassetteA_reject_events = status_monitoring[65:68]

        cassetteB_denomination = status_monitoring[68:71]
        cassetteB_notes_loaded = status_monitoring[71:75]
        cassetteB_notes_dispensed = status_monitoring[75:79]
        cassetteB_reject_events = status_monitoring[79:82]

        cassetteC_denomination = status_monitoring[82:85]
        cassetteC_notes_loaded = status_monitoring[85:89]
        cassetteC_notes_dispensed = status_monitoring[89:93]
        cassetteC_reject_events = status_monitoring[93:96]

        cassetteD_denomination = status_monitoring[96:99]
        cassetteD_notes_loaded = status_monitoring[99:103]
        cassetteD_notes_dispensed = status_monitoring[103:107]
        cassetteD_reject_events = status_monitoring[107:110]


        #cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            INSERT INTO health_messages
            (session_uuid, session_time, middleware_id, atm_id, atm_date, atm_time, program_version_no, table_version_no,
            firmware_version_no, alarm_chest_door_open, alarm_top_door_open, alarm_supervisor_active,
            reciept_printer_paper_status, reciept_printer_ribbon_status,
            journal_printer_paper_status, journal_printer_ribbon_status,
            note_status_dispenser, reciept_printer, journal_printer,
            dispenser, communication_system,cardreader, cards_retained,
            electronic_system, current_error_code, communication_failures,
            cassetteA_denomination,cassetteA_notes_loaded,cassetteA_notes_dispensed,cassetteA_reject_events,
            cassetteB_denomination,cassetteB_notes_loaded,cassetteB_notes_dispensed,cassetteB_reject_events,
            cassetteC_denomination,cassetteC_notes_loaded,cassetteC_notes_dispensed,cassetteC_reject_events,
            cassetteD_denomination,cassetteD_notes_loaded,cassetteD_notes_dispensed,cassetteD_reject_events)
            VALUES
            ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
            '%s', '%s', '%s', '%s', '%s', '%s','%s','%s','%s','%s','%s','%s','%s','%s'
            ,'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')
            """ % (
            session_uuid
            , datetime.now()
            , middleware_id
            , atm_id
            , session_time
            , atm_time
            , program_version_no
            , table_version_no
            , firmware_version_no
            , alarm_chest_door_open
            , alarm_top_door_open
            , alarm_supervisor_active
            , reciept_printer_paper_status
            , reciept_printer_ribbon_status
            , journal_printer_paper_status
            , journal_printer_ribbon_status
            , note_status_dispenser
            , reciept_printer
            , journal_printer
            , dispenser
            , communication_system
            , cardreader
            , cards_retained
            , electronic_system
            , current_error_code
            , communication_failures

            , cassetteA_denomination
            , cassetteA_notes_loaded
            , cassetteA_notes_dispensed
            , cassetteA_reject_events

            , cassetteB_denomination
            , cassetteB_notes_loaded
            , cassetteB_notes_dispensed
            , cassetteB_reject_events

            , cassetteC_denomination
            , cassetteC_notes_loaded
            , cassetteC_notes_dispensed
            , cassetteC_reject_events

            , cassetteD_denomination
            , cassetteD_notes_loaded
            , cassetteD_notes_dispensed
            , cassetteD_reject_events)
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogReqPacketAuth(fields, SessionUUID, trantype):
    try:
        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))
        communication_identifier = fields[0][:8]
        terminal_identifier = fields[0][8:10]
        software_version_no = fields[0][10:12]
        encryption_mode_flag = fields[0][12:13]
        info_header = fields[0][13:20]
        terminal_id = fields[1]
        transaction_code = fields[2]
        seq_no = fields[3]
        track2 = fields[4]
        pan, service_code = ParseTrack2(track2)
        pan_hash = PCI_DSS.PCI_Mask_PAN(pan)
        amount = fields[5]

        surcharge = fields[6]
        amount_reformat = "%s.%s" % (amount[:-2], amount[-2:])
        surcharge_reformat = "%s.%s" % (surcharge[:-2], surcharge[-2:])
        pin_block = fields[7]
        status_monitoring = fields[10]
        nowtime = datetime.now().strftime('%H%M%S')
        nowdate = datetime.now().strftime('%d%m%y')
        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            INSERT INTO authorizations
            (session_uuid, session_time, atm_id,  operation_code, tran_seq_num, track2_data, tran_amount, surcharge_amount, pin_block,
            status_monitoring, local_tran_date, local_tran_time, comms_identifier, terminal_identifier, software_version_no,
            encryption_mode_flag, information_header, pan_hash, pan, service_code, tran_type)
            VALUES
            ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
            '%s', '%s', '%s', '%s', '%s', '%s','%s','%s','%s')
            """ % (
            SessionUUID,
            datetime.now(),
            terminal_id,
            transaction_code,
            seq_no,
            track2,
            amount_reformat,
            surcharge_reformat,
            pin_block,
            status_monitoring,
            nowdate,
            nowtime,
            communication_identifier,
            terminal_identifier,
            software_version_no,
            encryption_mode_flag,
            info_header,
            pan_hash,
            pan,
            service_code,
            trantype)
        #log.info(sql)
        cur.execute(sql)

        #log health message (Status monitoring)
        session_uuid = SessionUUID
        middleware_id = 0
        session_time = datetime.now().strftime('%d%m%y')
        atm_id = terminal_id
        atm_date = datetime.now().strftime('%d%m%y')
        atm_time = datetime.now().strftime('%H%M%S')
        program_version_no = status_monitoring[0:10]
        table_version_no = status_monitoring[10:20]
        firmware_version_no = status_monitoring[20:30]
        alarm_chest_door_open = status_monitoring[30:31]
        alarm_top_door_open = status_monitoring[31:32]
        alarm_supervisor_active = status_monitoring[32:33]
        reciept_printer_paper_status = status_monitoring[33:34]
        reciept_printer_ribbon_status = status_monitoring[34:35]
        journal_printer_paper_status = status_monitoring[35:36]
        journal_printer_ribbon_status = status_monitoring[36:37]
        note_status_dispenser = status_monitoring[37:38]
        reciept_printer = status_monitoring[38:39]
        journal_printer = status_monitoring[39:40]
        dispenser = status_monitoring[40:41]
        communication_system = status_monitoring[41:42]
        cardreader = status_monitoring[42:43]
        cards_retained = status_monitoring[43:46]

        electronic_system = status_monitoring[46:48]
        current_error_code = status_monitoring[48:51]
        communication_failures = status_monitoring[51:54]

        cassetteA_denomination = status_monitoring[54:57]
        cassetteA_notes_loaded = status_monitoring[57:61]
        cassetteA_notes_dispensed = status_monitoring[61:65]
        cassetteA_reject_events = status_monitoring[65:68]

        cassetteB_denomination = status_monitoring[68:71]
        cassetteB_notes_loaded = status_monitoring[71:75]
        cassetteB_notes_dispensed = status_monitoring[75:79]
        cassetteB_reject_events = status_monitoring[79:82]

        cassetteC_denomination = status_monitoring[82:85]
        cassetteC_notes_loaded = status_monitoring[85:89]
        cassetteC_notes_dispensed = status_monitoring[89:93]
        cassetteC_reject_events = status_monitoring[93:96]

        cassetteD_denomination = status_monitoring[96:99]
        cassetteD_notes_loaded = status_monitoring[99:103]
        cassetteD_notes_dispensed = status_monitoring[103:107]
        cassetteD_reject_events = status_monitoring[107:110]


        #cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            INSERT INTO health_messages
            (session_uuid, session_time, middleware_id, atm_id, atm_date, atm_time, program_version_no, table_version_no,
            firmware_version_no, alarm_chest_door_open, alarm_top_door_open, alarm_supervisor_active,
            reciept_printer_paper_status, reciept_printer_ribbon_status,
            journal_printer_paper_status, journal_printer_ribbon_status,
            note_status_dispenser, reciept_printer, journal_printer,
            dispenser, communication_system,cardreader, cards_retained,
            electronic_system, current_error_code, communication_failures,
            cassetteA_denomination,cassetteA_notes_loaded,cassetteA_notes_dispensed,cassetteA_reject_events,
            cassetteB_denomination,cassetteB_notes_loaded,cassetteB_notes_dispensed,cassetteB_reject_events,
            cassetteC_denomination,cassetteC_notes_loaded,cassetteC_notes_dispensed,cassetteC_reject_events,
            cassetteD_denomination,cassetteD_notes_loaded,cassetteD_notes_dispensed,cassetteD_reject_events)
            VALUES
            ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s',
            '%s', '%s', '%s', '%s', '%s', '%s','%s','%s','%s','%s','%s','%s','%s','%s'
            ,'%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')
            """ % (
            session_uuid
            , datetime.now()
            , middleware_id
            , atm_id
            , session_time
            , atm_time
            , program_version_no
            , table_version_no
            , firmware_version_no
            , alarm_chest_door_open
            , alarm_top_door_open
            , alarm_supervisor_active
            , reciept_printer_paper_status
            , reciept_printer_ribbon_status
            , journal_printer_paper_status
            , journal_printer_ribbon_status
            , note_status_dispenser
            , reciept_printer
            , journal_printer
            , dispenser
            , communication_system
            , cardreader
            , cards_retained
            , electronic_system
            , current_error_code
            , communication_failures

            , cassetteA_denomination
            , cassetteA_notes_loaded
            , cassetteA_notes_dispensed
            , cassetteA_reject_events

            , cassetteB_denomination
            , cassetteB_notes_loaded
            , cassetteB_notes_dispensed
            , cassetteB_reject_events

            , cassetteC_denomination
            , cassetteC_notes_loaded
            , cassetteC_notes_dispensed
            , cassetteC_reject_events

            , cassetteD_denomination
            , cassetteD_notes_loaded
            , cassetteD_notes_dispensed
            , cassetteD_reject_events)
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)

def LogReqPacketReversal(fields, SessionUUID, trantype):
    try:
        CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        # Connect to DB
        con = MySQLdb.connect(
            host=CurrentConfig['middleware_server.dbserver'],
            port=int(CurrentConfig['middleware_server.dbport']),
            db=CurrentConfig['middleware_server.dbdatabase'],
            user=CurrentConfig['middleware_server.dbusername'],
            passwd=CurrentConfig['middleware_server.dbpassword'])

        log.debug("%s:  < fields=%s" % (SessionUUID, fields))

        communication_identifier = fields[0][:8]
        terminal_identifier = fields[0][8:10]
        software_version_no = fields[0][10:12]
        encryption_mode_flag = fields[0][12:13]
        info_header = fields[0][13:20]
        terminal_id = fields[1]
        transaction_code = fields[2]
        seq_no = fields[3]
        track2 = fields[4]
        pan, service_code = ParseTrack2(track2)
        pan_hash = PCI_DSS.PCI_Mask_PAN(pan)

        amount = fields[5]
        surcharge = fields[6]
        dispensed_amount = fields[7]

        amount_reformat = "%s.%s" % (amount[:-2], amount[-2:])
        surcharge_reformat = "%s.%s" % (surcharge[:-2], surcharge[-2:])
        dispensed_amount_reformat = "%s.%s" % (dispensed_amount[:-2], dispensed_amount[-2:])
        status_monitoring = fields[8]
        nowtime = datetime.now().strftime('%H%M%S')
        nowdate = datetime.now().strftime('%d%m%y')
        cur = con.cursor(MySQLdb.cursors.DictCursor)
        sql = """
            INSERT INTO reversals
            (
            info_header,
            encryption_mode_flag,
            software_version_no,
            terminal_identifier,
            communication_identifier,
            session_uuid,
            session_time,
            atm_id,
            local_tran_date,
            local_tran_time,
            tran_type,
            seq_no,
            transaction_code,
            requested_amount,
            dispensed_amount,
            surcharge_amount,
            track2_masked,
            status_monitoring)
            VALUES
            ('%s', '%s',  '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s','%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')
            """ % (
            info_header,
            encryption_mode_flag,
            software_version_no,
            terminal_identifier,
            communication_identifier,
            SessionUUID,
            datetime.now(),
            terminal_id,
            nowdate,
            nowtime,
            trantype,
            seq_no,
            transaction_code,
            amount_reformat,
            dispensed_amount_reformat,
            surcharge_reformat,
            pan_hash,
            status_monitoring

        )
        cur.execute(sql)
        cur.close()
    except:
        log.exception("%s: EE Decoding Packet" % SessionUUID)





def ParseTrack2(Track2):

    separator = Track2.find('=')
    PAN = Track2[1:separator]
    ServiceCode1 = Track2[separator + 5:separator + 6]
    return PAN, ServiceCode1


class ResponseThread(Thread):
    ResponsePipes = []

    def __init__(self, session, source, sink):
        Thread.__init__(self)
        self.log = logging.getLogger('Response')
        self.session = session
        self.source = source
        self.sink = sink

        self.log.debug('%s:  < Creating new response thread  %s ( %s -> %s )' %
                       ( self.session.SessionUUID, self, source.getpeername(), sink.getpeername() ))
        ResponseThread.ResponsePipes.append(self)
        self.log.debug('%s:  < %s ResponsePipes active' % (self.session.SessionUUID, len(ResponseThread.ResponsePipes)))


    def run(self):
        source_active = True
        while 1:
            try:

                data = self.source.recv(4096)

                if not data:
                    self.log.debug('%s:  < Break ' % (self.session.SessionUUID, ))
                    source_active = False  #This is a reasonable assumption that the source has disconnected
                    break

                AsciiData = Str2Ascii(data)
                self.log.debug('%s:  < %s' % (self.session.SessionUUID, AsciiData))
                self.LogRaw(AsciiData)
                if AsciiData[0:5] == '<ENQ>':
                    #Increase ENQ
                    self.session.ENQ_count += 1
                elif AsciiData[0:5] == '<STX>':
                    #Log the Pocket
                    self.LogSTXPacket(AsciiData)
                    #Increase RES
                    self.session.RES_count += 1
                elif AsciiData[0:5] == '<ACK>':
                    #Increase ACK
                    self.session.ACK_res += 1
                elif AsciiData[0:5] == '<NAK>':
                    #Increase NAK
                    self.session.NAK_res += 1
                elif AsciiData[0:5] == '<EOT>':
                    #Increase EOT
                    self.session.EOT_res += 1

                self.log.debug('%s:  < Session = %s' % (self.session.SessionUUID, self.session.__dict__, ))

                if self.session.decline == True:
                    self.log.debug('%s: x < Ignoring message from Switch' % (
                        self.session.SessionUUID))
                else:
                    self.log.debug('%s: << %s' % (self.session.SessionUUID, AsciiData))
                    self.sink.send(data)
            except:
                self.log.exception('%s:  < exception, breaking' % (self.session.SessionUUID, ))
                break

        try:
            if source_active:
                self.source.shutdown(socket.SHUT_RD)
            else:
                self.log.debug('%s:  < Source assumed to be already closed' % (self.session.SessionUUID, ))
        except:
            self.log.exception('%s:  < Exception closing source' % (self.session.SessionUUID, ))

        try:
            self.log.debug('%s:  < Closing ' % (self.session.SessionUUID, ))
            self.sink.shutdown(socket.SHUT_WR)
        except Exception as e:
            self.log.info('%s:  < Exception closing sink: %s' % (self.session.SessionUUID, e))

        ResponseThread.ResponsePipes.remove(self)
        self.log.debug('%s:  < %s ResponsePipes active' % (self.session.SessionUUID, len(ResponseThread.ResponsePipes)))


    def LogRaw(self, AsciiData):
        try:
            l = LogEntry()
            l.session = self.session
            l.session_uuid = self.session.SessionUUID
            l.direction = ' <'
            l.message_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
            l.Type = "Raw Message"
            l.AsciiData = AsciiData
            q.appendleft(l)
        except:
            self.log.exception("Logging Raw")

            #------- DEF LOGGING OF PACKETS ----------

    def LogSTXPacket(self, data):
        try:
            AsciiData = Str2Ascii(data)
            noetx = AsciiData.split("<ETX>")
            stx = noetx[0]
            stx = stx.split("<STX>")[1]
            fields = stx.split("<FS>")

            self.log.debug("%s:  < fields=%s" % (self.session.SessionUUID, fields))
            AtmID = fields[2]
            Command = fields[3]

            ConfigCommand = fields[2]
            ConfigATMID = fields[1]

            #Balance Enquiries
            if Command == "29" or Command == "31" or Command == "32" or Command == "35":
                self.log.info("%s:  < AtmID=[%s], Type=[Authorization BI], ResponseCode=[%s]" % (
                    self.session.SessionUUID, AtmID, fields[5],))
            #Cash Withdrawals
            elif Command == "11" or Command == "12" or Command == "15":
                self.log.info("%s:  < AtmID=[%s], Type=[Authorization CW], ResponseCode=[%s]" % (
                    self.session.SessionUUID, AtmID, fields[5],))

            #Reversals
            elif ConfigCommand == "29":
                self.log.info(
                    "%s:  < AtmID=[%s], Type=[Reversal], Command=[%s]" % (
                    self.session.SessionUUID, ConfigATMID, ConfigCommand,))


            elif ConfigCommand == "51":
                self.log.info(
                    "%s:  < AtmID=[%s], Type=[Trail Host Totals], Command=[%s]" % (
                        self.session.SessionUUID, ConfigATMID, ConfigCommand,))

            elif ConfigCommand == "50":
                self.log.info(
                    "%s:  < AtmID=[%s], Type=[Host Totals], Command=[%s]" % (
                        self.session.SessionUUID, ConfigATMID, ConfigCommand))

            elif ConfigCommand == "60":
                self.log.info("%s:  < AtmID=[%s], Type=[Configuration], Command=[%s]" % (
                    self.session.SessionUUID, ConfigATMID, ConfigCommand,))
            else:
                self.log.info(
                    "%s:  < AtmID=[%s], Type=[Unknown], Command=[%s]" % (self.session.SessionUUID, AtmID, Command,))
        except:
            self.log.exception("%s: EE Decoding Packet" % (self.session.SessionUUID))

#---------Listen for incomming connections -------------------------
class Pinhole(Thread):
    def __init__(self, listening_port):
        Thread.__init__(self)
        self.log = logging.getLogger('Pinhole')
        self.CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {})
        self.newhost = self.CurrentConfig['middleware_server.destination_host']
        self.newport = self.CurrentConfig['middleware_server.destination_port']
        self.log.info('Redirecting: localhost:%s -> %s:%s' % ( listening_port, self.newhost, self.newport))
        self.running = False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.bind(('', int(listening_port)))
        self.sock.listen(5)


    def run(self):
        self.Running = True
        while self.Running:
            newsock, address = self.sock.accept()
            session = Session()
            self.CurrentConfig = LoadConfig('pyMiddleWareServer.ini', {}, session)
            session.source_ip = address[0]
            session.destination_ip = self.CurrentConfig['middleware_server.destination_host']
            session.destination_port = self.CurrentConfig['middleware_server.destination_port']
            session.destination_timeout = self.CurrentConfig['middleware_server.destination_timeout']
            self.log.info('%s: NN New Session from %s' % (session.SessionUUID, address))

            fwd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:

                ssl_sock = ssl.wrap_socket(fwd)
                ssl_sock.settimeout(int(session.destination_timeout))
                ssl_sock.connect((session.destination_ip, int(session.destination_port)))
                ssl_sock.do_handshake()
                self.log.info('SSL Handshake Completed')

                self.log.debug('%s:    Connected to switch %s:%s' % (
                    session.SessionUUID, session.destination_ip, session.destination_port,))
            except socket.timeout:
                session.error = "Timeout connecting to switch"
                self.log.critical('%s: EE Cant Connect to %s:%s : %s' % (
                session.SessionUUID, session.destination_ip, session.destination_port, session.error,))
                ssl_sock.close()
            except socket.sslerror:
                session.error = "SSL Error connecting to TNS"
                self.log.critical('%s: EE Cant Connect to %s:%s : %s' % (
                session.SessionUUID, session.destination_ip, session.destination_port, session.error,))
                ssl_sock.close()
            except:
                session.error = "Unknown Error connecting to switch"
                self.log.exception('%s: EE Unknown Error Connecting to %s:%s : %s' % (
                session.SessionUUID, session.destination_ip, session.destination_port, session.error,))
                ssl_sock.close()
            else:
                ssl_sock.settimeout(None)
                RequestThread(session, newsock, ssl_sock).start()
                ResponseThread(session, ssl_sock, newsock).start()


#-----------------------------------------------------------------------------

#-----------------------MAIN------------------------------

if __name__ == "__main__":
    import sys

    log = logging.getLogger('Main')

    log.debug("__main__()")
    _CurrentConfig = LoadConfig('pyMiddleWareServer.ini', _CurrentConfig)
    daemon = MyDaemon('/tmp/pyMiddleWareServer%s.pid' % (_CurrentConfig['middleware_server.listening_port'],))
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        elif 'foreground' == sys.argv[1]:
            daemon.run()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart|foreground" % sys.argv[0]
        sys.exit(2)
