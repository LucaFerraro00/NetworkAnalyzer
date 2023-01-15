# Network analyzer (SNIFFER)

The project aims at building a multiplatform application capable of intercepting incoming and outgoing traffic through the network interfaces of a computer. The application will set the network adapter in promiscuous mode, collect IP address, port and protocol type of observed traffic and will generate a textual report describing a synthesis of the observed events.<br>
Such a report should list for each of the network address/port pairs that have been observed, the protocols that was transported, the cumulated number of bytes transmitted, the timestamp of the first and last occurrence of information exchange.<br>
Command line parameters will be used to specify the network adapter to be inspected, the output file to be generated, the interval after which a new report is to be generated, or a possible filter to apply to captured data.
The system has been developed using third party libraries (libpcap) in order to support deployment on several platforms.


The system  designed consists of a multi-platform library that supports network data capturing and recording, and a sample application that gives access to it.
The library has been properly documented, and provide a clear definition of its intended usage, as well as of any error condition that can be reported.
By using the sample application, the user is able to:
* define the network adapter to be sniffed
select a time interval after which an updated version of the report will be generated
* temporarily pause and subsequently resume the sniffing process
* define the file that will contain the report


### Report example:
```csv
142.250.180.170/443,172.22.32.35/65436,54,ethernet-ipv4-TCP,14/01/2023 - 15:28:57.313,14/01/2023 - 15:28:57.313
142.250.184.46/443,172.22.32.35/65438,1466,ethernet-ipv4-TCP,14/01/2023 - 15:28:57.833,14/01/2023 - 15:28:57.833
142.250.180.142/443,172.22.32.35/52344,9961,ethernet-ipv4-UDP,14/01/2023 - 15:28:58.054,14/01/2023 - 15:29:02.992
142.250.180.142/443,172.22.32.35/65434,15236,ethernet-ipv4-TCP,14/01/2023 - 15:28:56.973,14/01/2023 - 15:28:57.177
172.22.32.35/65437,142.251.209.42/443,66,ethernet-ipv4-TCP,14/01/2023 - 15:28:57.587,14/01/2023 - 15:28:57.587
130.192.3.21/53,172.22.32.35/50640,141,ethernet-ipv4-UDP,14/01/2023 - 15:28:57.821,14/01/2023 - 15:28:57.821
172.22.32.35/52312,142.250.180.174/443,5224,ethernet-ipv4-UDP,14/01/2023 - 15:28:36.167,14/01/2023 - 15:29:02.665
142.250.184.67/443,172.22.32.35/51488,69,ethernet-ipv4-UDP,14/01/2023 - 15:28:58.224,14/01/2023 - 15:28:58.224
142.250.180.174/443,172.22.32.35/57412,1309,ethernet-ipv4-UDP,14/01/2023 - 15:28:57.898,14/01/2023 - 15:28:57.922
142.250.180.131/443,172.22.32.35/51907,17319,ethernet-ipv4-UDP,14/01/2023 - 15:28:57.317,14/01/2023 - 15:28:57.977
172.22.32.35/65436,142.250.180.170/443,66,ethernet-ipv4-TCP,14/01/2023 - 15:28:57.257,14/01/2023 - 15:28:57.257
172.22.32.35/52276,142.251.209.14/443,150,ethernet-ipv4-UDP,14/01/2023 - 15:28:36.164,14/01/2023 - 15:28:42.505
172.22.32.35/65434,142.250.180.142/443,128,ethernet-ipv4-TCP,14/01/2023 - 15:28:56.963,14/01/2023 - 15:28:56.963
142.250.184.42/443,172.22.32.35/65439,2612,ethernet-ipv4-TCP,14/01/2023 - 15:28:58.062,14/01/2023 - 15:28:58.978
172.22.32.35/54426,142.251.209.10/443,300,ethernet-ipv4-UDP,14/01/2023 - 15:28:34.862,14/01/2023 - 15:28:57.220
130.192.3.21/53,172.22.32.35/49661,365,ethernet-ipv4-UDP-DNS,14/01/2023 - 15:28:56.937,14/01/2023 - 15:28:56.937
172.22.32.35/65439,142.250.184.42/443,66,ethernet-ipv4-TCP,14/01/2023 - 15:28:58.048,14/01/2023 - 15:28:58.048
142.250.180.174/443,172.22.32.35/52312,1296,ethernet-ipv4-UDP,14/01/2023 - 15:28:36.214,14/01/2023 - 15:29:08.258
172.22.32.35/51907,142.250.180.131/443,2352,ethernet-ipv4-UDP,14/01/2023 - 15:28:57.488,14/01/2023 - 15:28:58.257
142.251.209.42/443,172.22.32.35/64412,2584,ethernet-ipv4-UDP,14/01/2023 - 15:28:57.606,14/01/2023 - 15:28:57.678
172.22.32.35/65438,142.250.184.46/443,128,ethernet-ipv4-TCP,14/01/2023 - 15:28:57.880,14/01/2023 - 15:28:57.880
172.22.32.35/65435,142.250.180.142/443,571,ethernet-ipv4-TCP,14/01/2023 - 15:28:56.944,14/01/2023 - 15:28:56.944
142.250.184.42/443,172.22.32.35/60884,1359,ethernet-ipv4-UDP,14/01/2023 - 15:28:58.260,14/01/2023 - 15:28:58.406
172.22.32.35/52344,142.250.180.142/443,2781,ethernet-ipv4-UDP,14/01/2023 - 15:28:58.071,14/01/2023 - 15:28:58.421
172.22.32.35/55013,130.192.3.21/53,74,ethernet-ipv4-UDP-DNS,14/01/2023 - 15:28:56.906,14/01/2023 - 15:28:56.906
142.251.209.14/443,172.22.32.35/52276,143,ethernet-ipv4-UDP,14/01/2023 - 15:28:42.939,14/01/2023 - 15:28:48.098
172.22.32.35/60884,142.250.184.42/443,1501,ethernet-ipv4-UDP,14/01/2023 - 15:28:58.236,14/01/2023 - 15:28:58.286
172.22.32.35/64412,142.251.209.42/443,1292,ethernet-ipv4-UDP,14/01/2023 - 15:28:57.620,14/01/2023 - 15:28:57.620
142.251.209.10/443,172.22.32.35/54426,67,ethernet-ipv4-UDP,14/01/2023 - 15:28:51.233,14/01/2023 - 15:28:51.233

```


## Usage

The application can be run through

 `cargo run [OPTIONS] <nic_id> <file_name> <time_interval>`

  inside the **NetworkAnalyzer_Binary** folder
  

**ARGS**:

    <nic_id>           The target network interface card to be user
    
    <file_name>        The output file where a complete report should be provided
    
    <time_interval>    Define the time interval after wihich the report is updated

The options are used to select `filters` of the capture


**OPTIONS**:

    -a, --ip_filter_source <ip_address_source>
            Keep only data that contains selected ip_address as source (ip address should have
            xxx.xxx.xxx.xxx format). Example of available ip address to filter:
                172.22.32.37

    -b, --ip_filter_dest <ip_address_destination>
            Keep only data that contains selected ip_address as destination (ip address should have
            xxx.xxx.xxx.xxx format). Example of available ip address to filter:
                172.22.32.37

    -c, --port_filter_source <port_source>
            Keep only data that contains selected port as source.
            MUST BE A NUMBER!

    -d, --port_filter_dest <port_destination>
            Keep only data that contains selected port as destination.
            MUST BE A NUMBER!

    -e, --byte_threshold <Threshold>
            Drop all the data with cumulative number of bytes below the inserted threshold.
            MUST BE A NUMBER!

    -f, --protocol_filter <Protocol name>
            Keep only data that contains selected protocol

    -h, --help
            Print help information

    -l, --list

## Documentation

The documenation can be opened running the command:


 `cargo doc --open`

 inside the **NetworkAnalyzer_Library** folder
