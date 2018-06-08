// Copyright 2017 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate grpcio;
extern crate grpcio_proto;
#[macro_use]
extern crate log;

#[path = "../log_util.rs"]
mod log_util;

use std::sync::Arc;

use grpcio::{ChannelCredentialsBuilder, ChannelBuilder, EnvBuilder};
use grpcio_proto::example::helloworld::HelloRequest;
use grpcio_proto::example::helloworld_grpc::GreeterClient;

use std::path::Path;
use std::fs::File;
use std::io::Read;

fn read_path_to_end<P: AsRef<Path>>(
    path: P,
    mut buf: &mut Vec<u8>,
) -> Result<usize, std::io::Error> {
    let mut f = File::open(path)?;
    f.read_to_end(&mut buf)
}

fn main() -> Result<(), Box<std::error::Error>> {
    let _guard = log_util::init_log(None);
    let env = Arc::new(EnvBuilder::new().build());

    let mut root_cert = Vec::with_capacity(8096);
    let mut client_cert = Vec::with_capacity(8096);
    let mut client_key = Vec::with_capacity(8096);

    read_path_to_end("ca.cert", &mut root_cert)?;
    read_path_to_end("client.fullchain", &mut client_cert)?;
    read_path_to_end("client.key", &mut client_key)?;

    let creds = ChannelCredentialsBuilder::new()
        .root_cert(root_cert)
        .cert(client_cert, client_key)
        .build();
    let ch = ChannelBuilder::new(env).secure_connect("localhost:50051", creds);
    let client = GreeterClient::new(ch);

    let mut req = HelloRequest::new();
    req.set_name("world".to_owned());
    let reply = client.say_hello(&req).expect("rpc");
    info!("Greeter received: {}", reply.get_message());

    Ok(())
}
