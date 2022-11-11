//!Contains all the structures definitions and implementations useful to store information sniffed from the network


use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
#[repr(C)] //per far funzionare timeval

///Store the needed information of a sniffed packet
pub struct CustomPacket{
    ///Timestamp of the sniffed packet, retrieved from pcap::PacketHeader
    pub ts : u32,
    ///Number of byte contained in the packet, retrieved from pcap::PacketHeader
    pub len :u32,
    ///List of protocol names, updated every time a new protocol
    pub prtocols_list: Vec<String>,
    ///Source ip address
    pub src_addr: Vec<u8>,
    ///Destination ip address
    pub dest_addr: Vec<u8>,
    ///Source port of the packet
    pub src_port: u16,
    ///Destination port of the packet
    pub dest_port: u16,
}

impl CustomPacket {
    pub(crate) fn new( len:u32) -> CustomPacket {
        CustomPacket{
            ts : 0,
            len :len,
            prtocols_list: Vec::new(), /*Inizialmente un vettore vuoto*/
            src_addr: Vec::from([0,0,0,0]),
            dest_addr: Vec::from([0,0,0,0]),
            src_port:0,
            dest_port: 0,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Hash, Serialize)]
///This struct is used ad key in the HashMap that stores network analisys information
pub struct CustomKey{
    pub ip : Vec<u8>,
    pub port : u16,
}

impl  CustomKey {
    pub fn new (ip : Vec<u8>, port : u16,) -> CustomKey{
        CustomKey{ip, port}
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize)]

///This struct is used as the value in each row of the HashMap that stores network analisys information
pub struct CustomData {
    pub len : u32,
    pub protocols : Vec<String>,
    pub start_timestamp: String,
    pub end_timestamp:String,
}

impl  CustomData {
    pub fn new (len : u32, protocols : Vec<String>, now : String) -> CustomData{
        CustomData {len, protocols, start_timestamp: String::new(), end_timestamp: String::new()}
    }
}

