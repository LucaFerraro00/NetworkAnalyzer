# Network analyzer (SNIFFER)

## Project’s summary
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

#
## Usage

The application can be run through

 `cargo run [OPTIONS] <nic_id> <file_name> <time_interval>`

  inside the **NetworkAnalyzer_Binary** folder

#
## Documentation
The documantation of the library is available [here](NetworkAnalyzer_Library/target/doc/network_analyzer_lib/index.html).


The documenation can also be opened running the command:


 `cargo doc --open`

 inside the **NetworkAnalyzer_Library** folder
