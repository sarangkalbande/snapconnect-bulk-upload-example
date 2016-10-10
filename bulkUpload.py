# (c) Copyright 2014-2015, Synapse Wireless Inc.
"""Bulk Uploader for SPY file update and verify to a list of MACs

Command line options:

-e  Enable encryption
-k  Encryption Key
-m  Specify MAC list (text or CSV)
-s  Upload a SPY file
-b  Select bridge device
-c  Which column of a CSV MAC list to use (used with -m option)
-f  Find - scans across all channels
-n  Change node channel,netID
-x  Kill repeaters - disables forwarding on all nodes
-r  Retry RPCs
-t  Timeout per RPC
-z  Connect to a remote network
-j  Bridge address (required for remote conn using -z)
"""

import binascii
import logging
import optparse
import re
import os
import csv
import types
import sys
import socket

from snapconnect import snap
from snaplib import ScriptsManager
from snaplib import SnappyUploader

log = logging.getLogger("bulkUpload")
not_resp_out_filename = "Result_no_resp.txt"
resp_out_filename = "Result_resp.txt"
not_uploaded_out_filename = "Result_not_uploaded.txt"
uploaded_out_filename = "Result_uploaded.txt"

# Default per-RPC timeouts
DEF_RETRIES = 3
DEF_TIMEOUT = 3.0   # secs

#--------------------- CLASS DEFINITIONS ----------------------------

class Sequencer(object):
    """Execute a sequence of tasks. Each task_list object must implement 'start()' and
       expose an attribute 'cb_finished' which the task calls when done."""
    def __init__(self, tasks = None, finished = None):
        self.cb_finished = finished

        if tasks is None:
            tasks = []

        self.task_list = tasks
        self.is_running = False

    def start(self):
        self.is_running = bool(self.task_list)

        if self.is_running:
            task = self.task_list.pop(0)
            task.cb_finished = self.start
            task.start()
        else:
            self.complete()

    def complete(self):
        if callable(self.cb_finished):
            self.cb_finished()

class SkipSequence(object):
    """Sequencer task which provides conditional "skip" of subsequent tasks"""
    def __init__(self, sequencer, n_task_condition):
        """Provide 'sequencer', and callable which returns number of tasks to skip"""
        self.sequencer = sequencer
        self.n_task_condition = n_task_condition
        self.cb_finished = None

    def start(self):
        self.sequencer.task_list = self.sequencer.task_list[self.n_task_condition():]
        self.cb_finished()

class Pinger(object):
    responding_macs = []
    def __init__(self, comm, target_mac, bridge_mac=None, max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT, silent=False):
        self.comm = comm
        self.target_mac = target_mac
        self.timeout = timeout
        self.silent = silent
        self.max_attempts = max_attempts
        self.n_attempt = 0
        self.cb_finished = None
        self.got_response = False
        self.ch = None
        self.nid = None
        self.tmr = None

    def start(self):
        if self.n_attempt == self.max_attempts:
            self.complete()
        else:
            self.n_attempt += 1
            self.comm.replace_rpc_func('tellVmStat', self.tell_vmstat)
            self.comm.rpc(self.target_mac, 'vmStat', 7)  # Send VM_NET request
            self.tmr = self.comm.scheduler.schedule(self.timeout, self.start)

    def tell_vmstat(self, stat, net_id):
        """VM_NET reply"""
        if self.comm.rpc_source_addr() == self.target_mac:
            self.tmr.Stop()
            self.got_response = True
            self.ch = (stat >> 8)
            self.nid = net_id
            self.responding_macs.append(self.target_mac)
            self.complete()

    def complete(self):
        if not self.silent:
            if self.got_response:
                log.info("Pinger: %s found @ %d,%4X" % (binascii.hexlify(self.target_mac), self.ch, self.nid & 0xFFFF))
            else:
                log.info("Pinger: %s not found" % binascii.hexlify(self.target_mac))
        self.cb_finished()


class NoForward(object):
    def __init__(self, comm, target_mac, max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT):
        self.comm = comm
        self.target_mac = target_mac
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.n_attempt = 0
        self.cb_finished = None
        self.got_response = False
        self.tmr = None

    def start(self):
        if self.n_attempt == self.max_attempts:
            self.complete()
        else:
            self.n_attempt += 1
            if not self.comm.add_rpc_func('nv_done', self.nv_done):
                self.comm.replace_rpc_func('nv_done', self.nv_done)
            self.comm.rpc(self.target_mac, 'callback', 'nv_done', 'saveNvParam', 6, 0)
            self.tmr = self.comm.scheduler.schedule(self.timeout, self.start)

    def nv_done(self, arg):
        """SaveNV return callback"""
        if self.comm.rpc_source_addr() == self.target_mac:
            self.tmr.Stop()
            self.got_response = True
            self.complete()

    def complete(self):
        log.info("%s Disable Fwd %s" % (binascii.hexlify(self.target_mac), "OK" if self.got_response else "NO RESPONSE"))
        self.cb_finished()


class NetChanger(object):
    def __init__(self, comm, target_mac, new_ch, new_nid):
        self.comm = comm
        self.target_mac = target_mac
        self.new_ch = new_ch
        self.new_nid = new_nid
        self.cb_finished = None
        self.got_response = False
        self.ch_setter = None
        self.nid_setter = None

    def start(self):
        self.ch_setter = RpcInvoker(self.comm, self.target_mac, 'saveNvParam', (4, self.new_ch), max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT)
        self.ch_setter.cb_finished = self.ch_ready
        self.ch_setter.start()

    def ch_ready(self):
        if not self.ch_setter.got_response:
            self.complete()
        else:
            self.nid_setter = RpcInvoker(self.comm, self.target_mac, 'saveNvParam', (3, self.new_nid), max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT)
            self.nid_setter.cb_finished = self.complete
            self.nid_setter.start()

    def complete(self):
        self.got_response = self.nid_setter and self.nid_setter.got_response
        target_mac_str = binascii.hexlify(self.target_mac)
        if self.got_response:
            log.info("NetChanger: %s changed to (%d,0x%04X)" % (target_mac_str, self.new_ch, self.new_nid & 0xFFFF))
        else:
            log.info("NetChanger: %s failed to change %s" % (target_mac_str, "channel" if not self.nid_setter else
                                                             "NID  (WARNING: Channel changed to %d)" % self.new_ch))
        self.cb_finished()

class Finder(object):
    """Scan channels to find the target node.  Leaves bridge on channel where found, or where it last checked.
       'got_response' indicates if target found, and 'pinger' holds found ch/nid.
       Class attribute 'channel_list' sorts recently found channels to the top of list.
    """
    channel_list = [1,4,2,8,3,5,6,7,9,10,11,12,13,14,0,15]  # The usual suspects first

    def __init__(self, comm, target_mac, bridge_mac):
        self.comm = comm
        self.target_mac = target_mac
        self.target_mac_str = binascii.hexlify(target_mac)
        self.bridge_mac = bridge_mac
        self.cb_finished = None
        self.got_response = False
        self.ch_index = 0
        self.tmr = None
        self.nid_setter = None
        self.ch_setter = None
        self.pinger = None

    def start(self):
        print "Scan (%s):" % self.target_mac_str,
        self.nid_setter = RpcInvoker(self.comm, self.bridge_mac, 'setNetId', 0xFFFF)
        self.nid_setter.cb_finished = self.nid_ready
        self.nid_setter.start()

    def nid_ready(self):
        """Bridge NID is set"""
        if not self.nid_setter.got_response:
            # Unable to set bridge NID
            log.info("Warning: The bridge never responded to NID change")
            self.complete()
        else:
            self.set_channel()

    def set_channel(self):
        self.ch_setter = RpcInvoker(self.comm, self.bridge_mac, 'setChannel', self.channel_list[self.ch_index])
        self.ch_setter.cb_finished = self.ch_ready
        self.ch_setter.start()

    def ch_ready(self):
        """Bridge channel is set"""
        if not self.ch_setter.got_response:
            # Unable to set channel
            log.info("Warning: The bridge never responded to NID change")
            self.early_complete()
        else:
            print "%2d" % self.channel_list[self.ch_index],
            self.pinger = Pinger(self.comm, self.target_mac, max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT, silent=True)
            self.pinger.cb_finished = self.next_channel
            self.pinger.start()

    def next_channel(self):
        if self.pinger.got_response:
            self.complete()
        else:
            self.ch_index += 1
            if self.ch_index >= len(self.channel_list):
                self.complete()
            else:
                self.set_channel()

    def early_complete(self):
        """Called when the Finder must exit before attempting each applicable channel"""
        log.info("Finder exited early - sending reboot to reset bridge")
        self.emerg_rebooter = RpcInvoker(self.comm, self.bridge_mac, 'reboot')
        self.emerg_rebooter.cb_finished = self.ermerg_reboot_resp
        # Now continue to the regular "complete" path
        self.complete()

    def ermerg_reboot_resp(self):
        """Intended as the landing place (callback) for the reboot request"""
        #Today, just show that this was called
        log.info("...reboot completed")

    def complete(self):
        print
        if self.pinger and self.pinger.got_response:
            # Sort found channel to the top of search list
            del self.channel_list[self.ch_index]
            self.channel_list.insert(0, self.pinger.ch)
            self.got_response = True
            log.info("Finder: %s @ (%d,%04X)" % (self.target_mac_str, self.pinger.ch, self.pinger.nid & 0xFFFF))
        else:
            self.got_response = False
            log.info("Finder: %s not found" % self.target_mac_str)

        self.cb_finished()


class RpcInvoker(object):
    """Invoke one RPC call on target node, using 'callback' to capture the return value"""
    def __init__(self, comm, target_mac, rpc_func, rpc_args=(), max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT):
        self.comm = comm
        self.target_mac = target_mac
        self.timeout = timeout
        self.rpc_func = rpc_func
        self.rpc_args = rpc_args if type(rpc_args) is types.TupleType else (rpc_args,)
        self.max_attempts = max_attempts
        self.return_value = None
        self.got_response = False
        self.n_attempt = 0
        self.cb_finished = None
        self.tmr = None

    def start(self):
        if self.n_attempt == self.max_attempts:
            self.complete()
        else:
            self.n_attempt += 1
            if callable(self.target_mac):
                self.target_mac = self.target_mac()
            if not self.comm.add_rpc_func('rpc_response', self.rpc_response):
                self.comm.replace_rpc_func('rpc_response', self.rpc_response)
            self.comm.rpc(self.target_mac, 'callback', 'rpc_response', self.rpc_func, *self.rpc_args)
            self.tmr = self.comm.scheduler.schedule(self.timeout, self.start)

    def rpc_response(self, return_val):
        """RPC callback() response"""
        # Make sure this is who should be responding and that we handle only one response per RPC
        if (self.comm.rpc_source_addr() == self.target_mac) and (self.got_response == False):
            self.tmr.Stop()
            self.got_response = True
            self.return_value = return_val
            self.complete()

    def complete(self):
        self.cb_finished()


class FindBridge(object):
    """Attempt to find bridge with mcast(ttl=1)
       'bridge_addr' will be set if found
    """
    bridge_addr = None
    def __init__(self, comm):
        self.comm = comm
        #self.remoteConn = remoteConn
        self.bridge_addr = None
        self.bridge_ch = None
        self.bridge_nid = None
        self.TIMEOUT = 1.0
        self.max_attempts = 3
        self.n_attempt = 0
        self.cb_finished = None
        self.tmr = None

    def start(self):
        if self.n_attempt == self.max_attempts:
            self.complete()
        else:
            self.n_attempt += 1
            self.comm.replace_rpc_func('tellVmStat', self.tell_vmstat)
            self.comm.mcast_rpc(1, 1, 'vmStat', 7)  # VM_NET
            self.tmr = self.comm.scheduler.schedule(self.TIMEOUT, self.start)

    def tell_vmstat(self, stat, net_id):
        """VM_NET reply"""
        self.bridge_ch = (stat >> 8)
        self.bridge_nid = net_id
        self.bridge_addr = self.comm.rpc_source_addr()
        self.tmr.Stop()
        self.complete()

    def complete(self):
        if self.bridge_addr:
            log.info("Connected bridge: %s (%d,0x%04X)" % (binascii.hexlify(self.bridge_addr), self.bridge_ch, self.bridge_nid & 0xFFFF))
        else:
            log.info("Bridge not found")
        self.cb_finished()

class FindRemBridge(object):
    """Attempt to find bridge over the TCP link; bridge address will be specified
    """
    def __init__(self, comm, bridge_addr):
        self.comm = comm
        self.bridge_addr = bridge_addr
        self.bridge_ch = None
        self.bridge_nid = None
        self.TIMEOUT = 5.0
        self.max_attempts = 3
        self.n_attempt = 0
        self.cb_finished = None
        self.tmr = None
        self.bridge_found = False

    def start(self):
        if self.n_attempt == self.max_attempts:
            self.complete()
        else:
            self.n_attempt += 1
            self.comm.replace_rpc_func('tellVmStat', self.tell_vmstat)
            self.comm.rpc(self.bridge_addr, 'vmStat', 7)  # VM_NET
            self.tmr = self.comm.scheduler.schedule(self.TIMEOUT, self.start)

    def tell_vmstat(self, stat, net_id):
        """VM_NET reply"""
        self.bridge_ch = (stat >> 8)
        self.bridge_nid = net_id
        self.tmr.Stop()
        self.complete()

    def complete(self):
        if self.bridge_ch:
            log.info("Connected bridge: %s (%d,0x%04X)" % (binascii.hexlify(self.bridge_addr), self.bridge_ch, self.bridge_nid & 0xFFFF))
            self.bridge_found = True
        else:
            log.info("Could not verify the bridge (Check address and network connection)")
        self.cb_finished()

class Uploader(object):
    uploaded_macs = []

    def __init__(self, comm, target_mac, spy_file):
        self.comm = comm
        self.target_mac = target_mac
        self.cb_finished = None
        self.tmr = None
        self.success = False
        try:
            f = open(spy_file, 'rb')
            self.image = ScriptsManager.getSnappyStringFromExport(f.read())
        except:
            log.error("Uploader can't read file %s" % spy_file)
            raise

    def start(self):
        print "uploading",
        self.comm.replace_rpc_func('tellVmStat', self.tell_vmstat)
        self.comm.replace_rpc_func('su_recvd_reboot', self.su_recvd_reboot)
        upload = self.comm.spy_upload_mgr.startUpload(self.target_mac, self.image)
        upload.registerFinishedCallback(self.cb_upm_finished)
        upload.registerProgressCallback(self.cb_upm_progress)

    def complete(self):
        print
        log.info("Uploader: %s %s" % (binascii.hexlify(self.target_mac), "success!" if self.success else "*fail*"))
        if self.success:
            self.uploaded_macs.append(self.target_mac)
        self.cb_finished()

    def cb_upm_progress(self, snappy_upload_obj, cur_chunk):
        log.debug("  Upload chunk %d" % cur_chunk)
        print '.',

    def cb_upm_finished(self, snappy_upload_obj, result):
        self.success = result == SnappyUploader.SNAPPY_PROGRESS_COMPLETE
        self.complete()

    def tell_vmstat(self, arg, val):
        """handle received tellVmStat() RPC calls"""
        self.comm.spy_upload_mgr.onTellVmStat(self.comm.rpc_source_addr(), arg, val)

    def su_recvd_reboot(self, dummy):
        self.comm.spy_upload_mgr.on_recvd_reboot(self.comm.rpc_source_addr())


# --------------------------------------- MAIN ------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                        filename='bulkUpload.log')

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger('').addHandler(console)

    class MainApp(object):
        def __init__(self):
            self.macs = []
            bridge_mac = None

            parser = optparse.OptionParser()

            parser.add_option("-e", "--encryption", dest="encrypt", help="Enable encryption", default=0)
            parser.add_option("-k", "--encryptionKey", dest="encryption_key", help="Key for encryption", default='')
            parser.add_option("-m", "--macfile", dest="macfile", help="Mac list (def MacList.txt)", default='MacList.txt')
            parser.add_option("-s", "--spyfile", dest="spyfile", help="SPY file", default='')
            parser.add_option("-b", "--bridge", dest="comport", help="COM port 'COM4', 'USB100', or 'USB200'",
                              default='DEFAULT')
            parser.add_option("-c", "--column", dest="column", help="CSV column (def 1)", default=1)
            parser.add_option("-f", "--find", dest="find", help="Find nodes on any channel/NID", action="store_true")
            parser.add_option("-n", "--network", dest="network", help="Change network (ch,0xNeId)(ex 1,0xD110)", default='')
            parser.add_option("-x", "--nofwd", dest="nofwd", help="Kill repeaters (no forwarding)", action="store_true")
            parser.add_option("-r", "--retry", dest="retry", help="Retry RPCs (def 3x)", default=3)
            parser.add_option("-t", "--timeout", dest="timeout", help="Timeout RPCs (def 3s)", default=3)
            parser.add_option("-z", "--remoteConn", dest="remoteConn", help="Connect to a remote SNAP network via this IP (Ex 74.198.44.1)", default='')
            parser.add_option("-j", "--remoteBridgeAddress", dest="remoteBrAddr", help="Remote conn requires the bridge SNAP address", default='')

            (options, args) = parser.parse_args()

            if options.network:
                try:
                    net = options.network.split(',')
                    new_chan = int(net[0])
                    new_nid = int(net[1], 16)
                except:
                    print "Error: network option must be in form CH,0xNeId (ex: 4,0x1c2c or 4,0x1C2C)"
                    return

            global DEF_RETRIES, DEF_TIMEOUT
            DEF_RETRIES = int(options.retry)
            DEF_TIMEOUT = int(options.timeout)

            if len(options.macfile) > 4 and options.macfile[-4:] == '.csv':
                self.parse_csv(options.macfile, int(options.column))
            else:
                self.parse_maclist(options.macfile)

            if options.comport == 'USB200':
                s_type = snap.SERIAL_TYPE_SNAPSTICK200
                s_port = 0
            elif options.comport == 'USB100' or options.comport == "DEFAULT":
                s_type = snap.SERIAL_TYPE_SNAPSTICK100
                s_port = 0
            else:
                s_type = snap.SERIAL_TYPE_RS232
                s_port = options.comport

            if sys.platform == 'linux2' and options.comport == "DEFAULT":
                # On linux, default to the E10 serial port if no comport is specified
                s_type = snap.SERIAL_TYPE_RS232
                s_port = '/dev/ttyS1'

            #Add initial function callbacks. These will be replaced with calls to replace_rpc_func
            funcs = {'tellVmStat': lambda arg,val:None,
                     'su_recvd_reboot': lambda dummy:None}

            self.comm = snap.Snap(license_file = 'License.dat', nvparams_file = 'nvparams.dat', funcs=funcs)

            if not options.remoteConn and options.remoteBrAddr:
                print "Error: remoteBrAddr without a specified remote IP address (remote Conn)"


            # Setup NV Param
            self.comm.save_nv_param(snap.NV_FEATURE_BITS_ID, 0x100)   # Send with RPC CRC
            self.comm.save_nv_param(snap.NV_MESH_ROUTE_AGE_MAX_TIMEOUT_ID, 0)
            self.comm.save_nv_param(snap.NV_MESH_OVERRIDE_ID, 1)
            self.comm.save_nv_param(snap.NV_LOCKDOWN_FLAGS_ID, 0x2)
            self.comm.save_nv_param(snap.NV_MESH_INITIAL_HOPLIMIT_ID, 2+1) #Plus one for the hop to the bridge
            self.comm.save_nv_param(snap.NV_MESH_MAX_HOPLIMIT_ID, 5+1) #Plus one the hop to the bridge
            self.comm.save_nv_param(snap.NV_AES128_ENABLE_ID, int(options.encrypt))
            self.comm.save_nv_param(snap.NV_AES128_KEY_ID, options.encryption_key)

            snap.RpcCodec.validateCrc = False   # Allow non-crc receive RPCs

            if options.remoteConn:
                try: # is this a valid address
                    socket.inet_aton(options.remoteConn)
                    self.comm.connect_tcp(options.remoteConn, tcp_keepalives = True, retry_timeout = 10)
                except:                    # Not Legal
                    print "Error: IP address must be proper format xx.xx.xx.xx"
                    return


                self.comm.set_hook(snap.hooks.HOOK_SNAPCOM_OPENED, callback=self.Snapcom_Opened)
                self.comm.set_hook(snap.hooks.HOOK_SNAPCOM_CLOSED, callback=self.Snapcom_Closed)

                # Now check that the user specified a bridge address and it is valid (AA.BB.CC or AABBCC)
                if len(options.remoteBrAddr) == 6: #AABBCC
                    bridge_mac = binascii.unhexlify(options.remoteBrAddr)
                    print #DEBUG
                elif len(options.remoteBrAddr) == 8 and (options.remoteBrAddr[2] == '.') and options.remoteBrAddr[5] == '.': #AA.BB.CC
                    #Make sure it fits the pattern, then strip dots for conversion
                    tempStr = options.remoteBrAddr[0:2] + options.remoteBrAddr[3:5] + options.remoteBrAddr[6:8]
                    bridge_mac = binascii.unhexlify(tempStr)
                else:
                    print "Error: BridgeAddress not configured for remote connection  (Ex aabbcc or AA.BB.CC)"
                    return

                log.info("Attempting to use remote bridge: %s" % (binascii.hexlify(bridge_mac)))
            else: #Not a remote connection
                self.comm.open_serial(s_type, s_port)

            # Control thread is managed by Sequencer
            self.seq = Sequencer()

            if options.remoteConn:
                # Ping to verify the remote connection/bridge
                if not bridge_mac:
                    print "Error: BridgeAddress not configured for remote connection  (Ex aabbcc or AA.BB.CC)"
                    return
                self.rem_bridge_finder = FindRemBridge(self.comm, bridge_mac)
                self.seq.task_list.append(self.rem_bridge_finder)
            else:
                # Find the Local bridge
                self.bridge_finder = FindBridge(self.comm)
                self.seq.task_list.append(self.bridge_finder)
                bridge_mac = lambda: self.bridge_finder.bridge_addr

            # Next we build sequence from input MAC list file
            for mac in self.macs:
                pinger = Finder(self.comm, mac, bridge_mac) if options.find else Pinger(self.comm, mac, max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT)

                # Skip the ping attempt if we did not find the bridge (remote or local)
                skip_next_if_no_bridge = SkipSequence(self.seq, lambda pinger=pinger: int(not self.rem_bridge_finder.bridge_found if options.remoteConn else not self.bridge_finder.bridge_addr))
                self.seq.task_list.append(skip_next_if_no_bridge)
                self.seq.task_list.append(pinger)

                skip_next_if_no_ping = SkipSequence(self.seq, lambda pinger=pinger: int(not pinger.got_response))

                if options.network:
                    self.seq.task_list.append(skip_next_if_no_ping)
                    self.seq.task_list.append(NetChanger(self.comm, mac, new_chan, new_nid))

                if options.nofwd:
                    self.seq.task_list.append(skip_next_if_no_ping)
                    self.seq.task_list.append(NoForward(self.comm, mac))

                if options.spyfile:
                    self.seq.task_list.append(skip_next_if_no_ping)
                    self.seq.task_list.append(Uploader(self.comm, mac, options.spyfile))
                elif options.network:
                    # If we made network changes and didn't upload, we need to reboot
                    self.seq.task_list.append(skip_next_if_no_ping)
                    self.seq.task_list.append(RpcInvoker(self.comm, mac, 'reboot', max_attempts=DEF_RETRIES, timeout=DEF_TIMEOUT))


            # Finally, we restore the Bridge to original settings
            if options.find:
                restore_bridge = RpcInvoker(self.comm, bridge_mac, 'reboot')
                self.seq.task_list.append(restore_bridge)

            log.info("----- Bulk Uploader Start -----")

            self.seq.start()
            while self.seq.is_running:
                self.comm.poll()

            not_uploaded = set(self.macs)-set(Uploader.uploaded_macs)
            not_responding = set(self.macs)-set(Pinger.responding_macs)

            print

            if options.spyfile:
                if not_uploaded:
                    print "MACs not uploaded"
                    for m in not_uploaded:
                        print binascii.hexlify(m)
            else:
                if not_responding:
                    print "MACs not responding"
                    for m in not_responding:
                        print binascii.hexlify(m)

            # Now let's generate a list of mac for the responding and un-responding nodes
            not_resp_file = open(not_resp_out_filename, 'w')
            for m in not_responding:
                not_resp_file.write("%s\n" % (str(binascii.hexlify(m))))
            not_resp_file.close()

            resp_file = open(resp_out_filename, 'w')
            for m in Pinger.responding_macs:
                resp_file.write("%s\n" % (str(binascii.hexlify(m))))
            resp_file.close()

            not_up_file = open(not_uploaded_out_filename, 'w')
            for m in not_uploaded:
                not_up_file.write("%s\n" % (str(binascii.hexlify(m))))
            not_up_file.close()

            up_file = open(uploaded_out_filename, 'w')
            for m in Uploader.uploaded_macs:
                up_file.write("%s\n" % (str(binascii.hexlify(m))))
            up_file.close()

            if options.remoteConn:
                self.comm.disconnect_tcp(options.remoteConn)

            log.info("----- Bulk Uploader End -----")
            print

        def parse_maclist(self, mac_file):
            self.macs = []
            try:
                s = open(mac_file, 'rb').read()
            except:
                log.error("Can't open file: %s" % mac_file)
                raise

            try:
                bytes = re.findall('[0-9a-fA-F]{2}', s)
                for i in range(0,len(bytes),3):
                    self.macs.append(binascii.unhexlify(bytes[i] + bytes[i+1] + bytes[i+2]))
            except:
                log.error("Error in mac-list file %s" % mac_file)
                raise

        def parse_csv(self, mac_file, column):
            try:
                f = open(mac_file)
            except:
                log.error("Can't open file: %s" % mac_file)
                raise

            self.macs = []
            r = csv.reader(f)
            for s in r:
                try:
                    self.macs.append(binascii.unhexlify(s[column-1].replace('.','')))
                except:
                    log.info("Error in csv file '%s'", s[column-1])

        #-----  HOOKS -----------------------

        def Snapcom_Opened(self, connection_info, remote_snap_addr):
            #template: HOOK_SNAPCOM_OPENED => some_function(connection_info, snap_address)
            log.info("TCP connect success: Remote= "+ str(binascii.hexlify(remote_snap_addr)))

        def Snapcom_Closed(self, connection_info, remote_snap_addr):
            #template: HOOK_SNAPCOM_CLOSED => some_function(connection_info, snap_address)
            if remote_snap_addr == None:
                log.info("TCP connection never established")
            else:
                log.info("TCP session closed")


    app = MainApp()



