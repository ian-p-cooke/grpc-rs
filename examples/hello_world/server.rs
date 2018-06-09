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

#![allow(unknown_lints)]
#![allow(unreadable_literal)]

extern crate futures;
extern crate grpcio;
extern crate grpcio_proto;
#[macro_use]
extern crate log;

#[path = "../log_util.rs"]
mod log_util;

use std::io::Read;
use std::sync::Arc;
use std::{io, thread};

use futures::Future;
use futures::sync::oneshot;
use grpcio::{Environment, RpcContext, ServerBuilder, UnarySink, ServerCredentialsBuilder};

use grpcio_proto::example::helloworld::{HelloReply, HelloRequest};
use grpcio_proto::example::helloworld_grpc::{self, Greeter};

use std::path::Path;
use std::fs::File;

fn read_path_to_end<P: AsRef<Path>>(
    path: P,
    mut buf: &mut Vec<u8>,
) -> Result<usize, std::io::Error> {
    let mut f = File::open(path)?;
    f.read_to_end(&mut buf)
}

#[derive(Clone)]
struct GreeterService;

impl Greeter for GreeterService {
    fn say_hello(&self, ctx: RpcContext, req: HelloRequest, sink: UnarySink<HelloReply>) {
        let auth_context = ctx.auth_context();
        let authenticated = auth_context.peer_is_authenticated();
        println!("authenticated: {}", authenticated);
        let property_name = auth_context.peer_identity_property_name();
        println!("peer_identity_property_name: {}", property_name);
        let peer_identity = auth_context.peer_identity();
        let mut count = 0;
        let mut name = "no name".to_owned();
        let mut value = "no value".to_owned();
        for prop in peer_identity {
            name = prop.name();
            value = prop.value();
            println!("{} = {}", name, value);
            count += 1;
        }
        let msg = format!(
            "Hello {}! props: {}, last {{ name: {}, value: {} }}.",
            req.get_name(),
            count,
            name, 
            value
        );
        let mut resp = HelloReply::new();
        resp.set_message(msg);
        let f = sink
            .success(resp)
            .map_err(move |e| error!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}

fn main() -> Result<(), Box<std::error::Error>> {
    let _guard = log_util::init_log(None);

    let mut root_cert = Vec::with_capacity(8096);
    let mut end_cert = Vec::with_capacity(8096);
    let mut private_key = Vec::with_capacity(8096);

    read_path_to_end("ca.cert", &mut root_cert)?;
    read_path_to_end("end.fullchain", &mut end_cert)?;
    read_path_to_end("end.key", &mut private_key)?;

    let creds = ServerCredentialsBuilder::new()
        .root_cert(root_cert, true)
        .add_cert(end_cert, private_key)
        .build();

    let env = Arc::new(Environment::new(1));
    let service = helloworld_grpc::create_greeter(GreeterService);
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind_secure("127.0.0.1", 50051, creds)
        .build()
        .unwrap();
    server.start();
    for &(ref host, port) in server.bind_addrs() {
        info!("listening on {}:{}", host, port);
    }
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        info!("Press ENTER to exit...");
        let _ = io::stdin().read(&mut [0]).unwrap();
        tx.send(())
    });
    let _ = rx.wait();
    let _ = server.shutdown().wait();

    Ok(())
}
