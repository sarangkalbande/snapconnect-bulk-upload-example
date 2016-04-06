(c) Copyright 2014-2015 Synapse Wireless, Inc.

# SNAPconnect Example - Bulk Uploader

## Running This Example

The bulkUpload script can be used to perform operations on large lists 
of SNAP nodes.  The tool has the ability to scan multiple channels and 
Network IDs to locate nodes, and after finding nodes can disable 
multicast forwarding, change the channel and network ID, and upload SPY 
files to the nodes.

### MAC file format

The input file for the bulkUpload script should be a list of MAC addresses.
You can seperate the MAC addresses with new lines or spaces.

```
Example:
AABBCC DDEEFF
001122 334455
```

Additionally, a single column of a CSV file may be used to provide the 
list of MAC addresses as well.  If you are using a CSV file, make sure 
to use the -c option to specify which column contains the MAC addresses.

### Running the bulkUpload module as a standalone demo

```bash
python bulkUpload.py --help
```

This command will display the command-line options:

```
    Usage: bulkUpload.py [options]

    Options:
    -h, --help      show this help message and exit
    -e ENCRYPT, --encryption=ENCRYPT
        	        Enable encrytion
    -k ENCRYPTION_KEY, --encryptionKey=ENCRYPTION_KEY
                      Key for encryption
    -m MACFILE, --macfile=MACFILE
                	Mac list
    -s SPYFILE, --spyfile=SPYFILE
                        SPY file
    -b COMPORT, --bridge=COMPORT
                       	COM port 'COM4', 'USB100', or 'USB200'
    -c COLUMN, --column=COLUMN
                        CSV column
    -f, --find      Find nodes on any channel/NID
    -n NETWORK, --network=NETWORK
                        Change network (ch,0xNeId)
    -x, --nofwd     Kill repeaters (no forwarding)
    -r RETRY, --retry=RETRY
                        Retry RPCs (def 3x)
    -t TIMEOUT, --timeout=TIMEOUT
                        Timeout RPCs (def 3s)
    -z REMOTECONN, --remoteConn=REMOTECONN
                        Connect to a remote SNAP network via IP address  (Ex
                        74.198.44.130)
    -j REMOTEBRADDR, --remoteBridgeAddress=REMOTEBRADDR
                          Remote conn requires the SNAP bridge address
```

### Example of Local use

```bash
python bulkUpload.py -m my_mac_file.txt
```

- Pings the list of mac addresses in file "macfiles\onemac.txt"
- Uses the default bridge device "USB100"  (paddle board)
- Will only try and ping the device on the current channel of the bridge device (USB)

### Example of Remote use

```bash
python bulkUpload.py -z 10.84.5.80 -j 03FF01 -m my_mac_file.txt -f
```

- Pings the list of mac addresses in file "my_mac_file.txt"
- Will attempt to connect to an E10 with an IP addr of 10.84.5.80
- Will scan through all channels in an attempt to ping each specified address

The uploader displays its progress on the console, and also creates a file
called "bulkUpload.log".  If the log file exists, it will be appended to with
each run of the program. Otherwise a new log file will be created.

Output files are generated giving the user a list of those nodes that did 
and did not respond as well as any nodes that did successfully upload 
a .spy file or failed during the process. These files will remain blank 
if no nodes fit the category (ex. if no upload was performed). These files 
are overwritten with the results of each bulkupload process.

## Common Uses

To find a series of nodes in a .csv (listed in first column) using a 
device with an IP of 10.84.5.80 and a SNAP bridge with an address of 03.FF.01

```bash
python bulkUpload.py -f -m nodeList.csv -c 1 -z 10.84.5.80 -j 03FF01
```

To move a series of nodes in a .csv to a different channel

```bash
python bulkUpload.py -f -m nodeList.csv -c 1 -z 10.84.5.80 -j 03FF01 -n 3,0xbeef
```

To move nodes to another channel and also upload a new script

```bash
python bulkUpload.py -f -m myNodes.txt -c 1 -z 10.84.5.80 -j 03FF01 -n 3,0xbeef -s myScript.spy
```

To simply ping a list of nodes on one channel

```bash
python bulkUpload.py -c 0 -z 10.84.5.80 -j 03FF01
```

## Notes

### Stopping the program during execution
If you kill the program during operation the SNAP bridge of remote 
connection will remain on the last Channel/NID combination associated 
with the halted bulkupload process. Simply reboot the module or run 
another bulkupload that runs to completion.

### Channel Order
The system is designed to begin with the most commonly used channels 
rather than blindly beginning on channel 0 each time. Once a node is 
discovered, the corresponding channel will be placed at the beginning of 
the list. This cuts down on the time finding devices clustered
together on the same groups of channels.

### Remote Connection
It is important you specify the SNAP address of the RF bridge to be used
for the remote connection (future version might avoid this). You will 
not receive an error if you attempt a connection to an IP address not 
associated with a valid SNAP Connect instance.

### Output files
The result files (ex. Result_resp.txt) will be overwritten with the 
results of each bulkupload process that runs to completion (ie. save the
file with a different filename if you wish to save the list.)

### Large Networks
Increase the timeout (-t) if you have a large network and want to allow
more time for the node to respond.

## License

Copyright © 2016 [Synapse Wireless](http://www.synapse-wireless.com/), licensed under the [Apache License v2.0](LICENSE.md).

<!-- meta-tags: vvv-snapconnect, vvv-wx, vvv-gui,vvv-python, vvv-example -->
