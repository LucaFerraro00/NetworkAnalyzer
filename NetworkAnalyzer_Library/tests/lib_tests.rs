use std::collections::HashMap;
use pdu::IpProto::TCP;
use network_analyzer_lib::network_features::{filter_ip_address_dest, filter_ip_address_source, filter_port_source, filter_port_dest, filter_len, filter_protocol};
use network_analyzer_lib::structures::{CustomData, CustomKey};

#[test]
fn source_ip_filter_test(){
    let key = CustomKey::new(vec![192,168,1,245], 57621, vec![192,168,1,255], 57621);
    let data = CustomData::new(82, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key1 = CustomKey::new(vec![192,168,1,254], 35424, vec![239,255,255,250], 1900);
    let data1 = CustomData::new(403, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key2 = CustomKey::new(vec![18,158,137,188],  443, vec![192,168,1,124],  60159);
    let data2 = CustomData::new(392, vec!["ethernet".to_string(),"ipv4".to_string(),"TCP".to_string()]);


    let mut map: HashMap<CustomKey, CustomData> = HashMap::new();
    map.insert(key.clone(),data.clone());
    map.insert(key1.clone(),data1.clone());
    map.insert(key2.clone(),data2.clone());

    let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
    filtered_map.insert(key.clone(), data.clone());
    assert_eq!(filter_ip_address_source(map,vec![192,168,1,245]), filtered_map);
}

#[test]
fn dest_ip_filter_test(){
    let key = CustomKey::new(vec![192,168,1,245], 57621, vec![192,168,1,255], 57621);
    let data = CustomData::new(82, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key1 = CustomKey::new(vec![192,168,1,254], 35424, vec![239,255,255,250], 1900);
    let data1 = CustomData::new(403, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key2 = CustomKey::new(vec![18,158,137,188],  443, vec![192,168,1,124],  60159);
    let data2 = CustomData::new(392, vec!["ethernet".to_string(),"ipv4".to_string(),"TCP".to_string()]);


    let mut map: HashMap<CustomKey, CustomData> = HashMap::new();
    map.insert(key.clone(),data.clone());
    map.insert(key1.clone(),data1.clone());
    map.insert(key2.clone(),data2.clone());

    let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
    filtered_map.insert(key1.clone(), data1.clone());
    assert_eq!(filter_ip_address_dest(map,vec![239,255,255,250]), filtered_map);
}

#[test]
fn source_port_filter_test(){
    let key = CustomKey::new(vec![192,168,1,245], 57621, vec![192,168,1,255], 57621);
    let data = CustomData::new(82, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key1 = CustomKey::new(vec![192,168,1,254], 35424, vec![239,255,255,250], 1900);
    let data1 = CustomData::new(403, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key2 = CustomKey::new(vec![18,158,137,188],  443, vec![192,168,1,124],  60159);
    let data2 = CustomData::new(392, vec!["ethernet".to_string(),"ipv4".to_string(),"TCP".to_string()]);


    let mut map: HashMap<CustomKey, CustomData> = HashMap::new();
    map.insert(key.clone(),data.clone());
    map.insert(key1.clone(),data1.clone());
    map.insert(key2.clone(),data2.clone());

    let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
    filtered_map.insert(key1.clone(), data1.clone());
    assert_eq!(filter_port_source(map,35424), filtered_map);
}

#[test]
fn dest_port_filter_test(){
    let key = CustomKey::new(vec![192,168,1,245], 57621, vec![192,168,1,255], 57621);
    let data = CustomData::new(82, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key1 = CustomKey::new(vec![192,168,1,254], 35424, vec![239,255,255,250], 1900);
    let data1 = CustomData::new(403, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key2 = CustomKey::new(vec![18,158,137,188],  443, vec![192,168,1,124],  60159);
    let data2 = CustomData::new(392, vec!["ethernet".to_string(),"ipv4".to_string(),"TCP".to_string()]);


    let mut map: HashMap<CustomKey, CustomData> = HashMap::new();
    map.insert(key.clone(),data.clone());
    map.insert(key1.clone(),data1.clone());
    map.insert(key2.clone(),data2.clone());

    let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
    filtered_map.insert(key1.clone(), data1.clone());
    assert_eq!(filter_port_dest(map,1900), filtered_map);
}

#[test]
fn len_filter_test(){
    let key = CustomKey::new(vec![192,168,1,245], 57621, vec![192,168,1,255], 57621);
    let data = CustomData::new(82, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key1 = CustomKey::new(vec![192,168,1,254], 35424, vec![239,255,255,250], 1900);
    let data1 = CustomData::new(403, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key2 = CustomKey::new(vec![18,158,137,188],  443, vec![192,168,1,124],  60159);
    let data2 = CustomData::new(392, vec!["ethernet".to_string(),"ipv4".to_string(),"TCP".to_string()]);


    let mut map: HashMap<CustomKey, CustomData> = HashMap::new();
    map.insert(key.clone(),data.clone());
    map.insert(key1.clone(),data1.clone());
    map.insert(key2.clone(),data2.clone());

    let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
    filtered_map.insert(key1.clone(), data1.clone());
    assert_eq!(filter_len(map,402), filtered_map);
}

#[test]
fn protocol_filter_test(){
    let key = CustomKey::new(vec![192,168,1,245], 57621, vec![192,168,1,255], 57621);
    let data = CustomData::new(82, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key1 = CustomKey::new(vec![192,168,1,254], 35424, vec![239,255,255,250], 1900);
    let data1 = CustomData::new(403, vec!["ethernet".to_string(),"ipv4".to_string(),"UDP".to_string()]);
    let key2 = CustomKey::new(vec![18,158,137,188],  443, vec![192,168,1,124],  60159);
    let data2 = CustomData::new(392, vec!["ethernet".to_string(),"ipv4".to_string(),"TCP".to_string()]);


    let mut map: HashMap<CustomKey, CustomData> = HashMap::new();
    map.insert(key.clone(),data.clone());
    map.insert(key1.clone(),data1.clone());
    map.insert(key2.clone(),data2.clone());

    let mut filtered_map: HashMap<CustomKey, CustomData> = HashMap::new();
    filtered_map.insert(key2.clone(), data2.clone());
    assert_eq!(filter_protocol(map,"TCP".to_string()), filtered_map);
}