use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
#[repr(C)] //per far funzionare timeval
pub struct CustomPacket{
    pub ts : u32, /*L'orario in cui il pacchetto è catturato; può essere preso dalla struct pcap::PacketHeader*/
    pub len :u32, /* I byte contenuti nel pacchetto; può essere preso dalla struct pcap::PacketHeader*/
    pub prtocols_list: Vec<String>, /*Per ogni protocollo trovato all'interno del pacchetto si fa push in questo vec*/
    pub src_addr: Vec<u8>,
    pub dest_addr: Vec<u8>,
    pub src_port: u16,
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
pub struct CustomData {
    pub len : u32,
    pub protocols : Vec<String>,
}

impl  CustomData {
    pub fn new (len : u32, protocols : Vec<String>,) -> CustomData{
        CustomData {len, protocols}
    }
}

