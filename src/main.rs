extern crate rosc;

use rosc::address::{Matcher, OscAddress};
use rosc::encoder;
use rosc::{OscError, OscMessage, OscPacket};
use serde::de::{self, Deserializer, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::net::{AddrParseError, SocketAddr, UdpSocket};
use std::str;
use std::str::FromStr;

fn main() {
    // Parse arguments
    let args: Vec<String> = env::args().collect();
    let usage = format!("Usage: {} [CONFIG FILE]", &args[0]);
    if args.is_empty() {
        panic!("{}", usage);
    }

    // Load JSON from the config file
    let path = &args[1];
    let data = fs::read_to_string(path).expect("Unable to read file");

    // Parse config
    let config: AppConfig = serde_json::from_str(&data).unwrap();

    let mut connections: HashMap<String, OscConnection> = HashMap::new();

    // Set up devices
    for device in &config.devices {
        connections.insert(device.id.clone(), OscConnection::from_device(device));
    }

    // Create a buffer to store recieved packets
    let mut buf = [0u8; rosc::decoder::MTU];

    // Main loop
    loop {
        // Iterate over connections and check if data has been recieved.
        for (_id, connection) in connections.iter() {
            // If it has, do things with it.
            let socket = &connection.socket;
            match &socket.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    // Debug info
                    println!("Received packet with size {} from: {}", size, addr);

                    // Decode packet
                    let (_, packet) = rosc::decoder::decode_udp(&buf[..size.to_owned()]).unwrap();

                    // Parse the packet and send a response.
                    for (send_id, packet) in handle_packet(packet, &config) {
                        let address = &connections
                            .get(send_id)
                            .unwrap()
                            .device
                            .client_address
                            .address;
                        socket
                            .send_to(&encoder::encode(&packet).unwrap(), address)
                            .unwrap();
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => {
                    println!("Error receiving from socket: {}", e);
                }
            }
        }
    }
}

/// Takes an OscPacket and acts on the data within it, returning a vector of OscPackets that should
/// be sent in response and the IDs they should be sent to.
fn handle_packet(packet: OscPacket, forwarders: &AppConfig) -> Vec<(&str, OscPacket)> {
    match packet {
        OscPacket::Message(msg) => {
            println!("OSC address: {}", msg.addr);
            println!("OSC arguments: {:?}", msg.args);

            let mut messages: Vec<(&str, OscPacket)> = vec![];

            let address = &OscAddress::new(msg.addr).unwrap();

            for forwarder in &forwarders.forwarders {
                println!(
                    "Matched address {}? {}",
                    forwarder.recieve_pattern.get_pattern(),
                    forwarder.recieve_pattern.match_address(address),
                );

                if forwarder.recieve_pattern.match_address(address) {
                    messages.push((
                        &forwarder.send_device,
                        OscPacket::Message(OscMessage {
                            addr: forwarder.send_address.clone(),
                            args: msg.args.clone(),
                        }),
                    ));
                }
            }

            messages
        }
        OscPacket::Bundle(bundle) => {
            println!("OSC Bundle: {:?}", bundle);
            vec![]
        }
    }
}

//////////

/// Struct that defines a connection between a recieve and send address through which messages
/// should be forwarded.
#[derive(Serialize, Deserialize)]
pub struct OscForwarder {
    recieve_device: String,
    recieve_pattern: OscAddressMatcher,
    send_device: String,
    send_address: String,
}

//////////

#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    devices: Vec<OscDevice>,
    forwarders: Vec<OscForwarder>,
}

//////////

#[derive(Serialize, Deserialize, Clone)]
pub struct OscDevice {
    id: String,
    host_address: SocketAddress,
    client_address: SocketAddress,
}

//////////

pub struct OscConnection {
    device: OscDevice,
    socket: UdpSocket,
}

impl OscConnection {
    pub fn from_device(device: &OscDevice) -> Self {
        let socket = UdpSocket::bind(device.host_address.address).unwrap();
        socket.set_nonblocking(true).unwrap();

        OscConnection {
            device: device.clone(),
            socket,
        }
    }
}

//////////

/// SocketAddr that can be (de)serialized through serde.
#[derive(Clone)]
pub struct SocketAddress {
    address: SocketAddr,
}

impl FromStr for SocketAddress {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<SocketAddress, AddrParseError> {
        let address = SocketAddr::from_str(s);

        match address {
            Ok(a) => Ok(SocketAddress { address: a }),
            Err(e) => Err(e),
        }
    }
}

impl Serialize for SocketAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.address.to_string())
    }
}

impl<'de> Deserialize<'de> for SocketAddress {
    fn deserialize<D>(deserializer: D) -> Result<SocketAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        let ip_address =
            SocketAddress::from_str(&deserializer.deserialize_str(StringVisitor).unwrap());

        match ip_address {
            Ok(a) => Ok(a),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}

//////////

pub struct OscAddressMatcher {
    matcher: Matcher,
}

impl OscAddressMatcher {
    pub fn new(pattern: &str) -> Result<Self, OscError> {
        let matcher: Result<Matcher, OscError> = Matcher::new(pattern);

        match matcher {
            Ok(m) => Ok(Self { matcher: m }),
            Err(e) => Err(e),
        }
    }

    pub fn match_address(&self, address: &OscAddress) -> bool {
        self.matcher.match_address(address)
    }

    pub fn get_pattern(&self) -> &String {
        &self.matcher.pattern
    }
}

impl Serialize for OscAddressMatcher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.get_pattern())
    }
}

impl<'de> Deserialize<'de> for OscAddressMatcher {
    fn deserialize<D>(deserializer: D) -> Result<OscAddressMatcher, D::Error>
    where
        D: Deserializer<'de>,
    {
        let matcher = OscAddressMatcher::new(&deserializer.deserialize_str(StringVisitor).unwrap());

        match matcher {
            Ok(m) => Ok(m),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}

//////////

struct StringVisitor;

impl<'de> Visitor<'de> for StringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v.to_owned())
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(v)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match str::from_utf8(v) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Err(de::Error::invalid_value(de::Unexpected::Bytes(v), &self)),
        }
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match String::from_utf8(v) {
            Ok(s) => Ok(s),
            Err(e) => Err(de::Error::invalid_value(
                de::Unexpected::Bytes(&e.into_bytes()),
                &self,
            )),
        }
    }
}
