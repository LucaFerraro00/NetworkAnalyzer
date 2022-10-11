# Network analyzer (SNIFFER)

## Project’s summary
The project aims at building a multiplatform application capable of intercepting incoming and outgoing traffic through the network interfaces of a computer. The application will set the network adapter in promiscuous mode, collect IP address, port and protocol type of observed traffic and will generate a textual report describing a synthesis of the observed events.
Such a report should list for each of the network address/port pairs that have been observed, the protocols that was transported, the cumulated number of bytes transmitted, the timestamp of the first and last occurrence of information exchange.
Command line parameters will be used to specify the network adapter to be inspected, the output file to be generated, the interval after which a new report is to be generated, or a possible filter to apply to captured data.
Required Background and Working Environment
Knowledge of the Rust general abstractions and of the Rust standard library. Knowledge of concurrency, synchronization and background processing. Knowledge of how to interface native libraries.
The system may be developed using third party libraries (e.g., libpcap) in order to support deployment on several platforms.

## Problem Definition
The system to be designed consists of a multi-platform library that supports network data capturing and recording, and a sample application that gives access to it.
The library will be properly documented, providing a clear definition of its intended usage, as well as of any error condition that can be reported.
By using the sample application, the user will be able to:
* define the network adapter to be sniffed
* select a time interval after which an updated version of the report will be generated
* temporarily pause and subsequently resume the sniffing process
* define the file that will contain the report

The application should also take care to properly indicate any failure of the sniffing process, providing meaningful and actionable feedback.
When the sniffing process is active, a suitable indication should be provided to the user.