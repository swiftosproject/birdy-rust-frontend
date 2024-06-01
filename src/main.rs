use clap::{App, Arg, SubCommand};
use tokio::fs::File;
use tokio::fs;
use reqwest::header::SET_COOKIE;
use reqwest::Client;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;

#[derive(Serialize)]
struct User {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() {
    let matches = App::new("BirdyCLI")
        .version("1.0")
        .author("SwiftOS")
        .about("Package Manager for SwiftOS")
        .subcommand(
            SubCommand::with_name("register")
                .about("Registers a new user")
                .arg(Arg::with_name("username").help("The username for the new user").required(true).index(1))
                .arg(Arg::with_name("password").help("The password for the new user").required(true).index(2)),
        )
        .subcommand(
            SubCommand::with_name("login")
                .about("Login to an existing account")
                .arg(Arg::with_name("username").help("The username for the account").required(true).index(1))
                .arg(Arg::with_name("password").help("The password for the account").required(true).index(2)),
        )
        .subcommand(
            SubCommand::with_name("publish")
                .about("Publish a package")
                .arg(Arg::with_name("filename").help("The filename of the package").required(true).index(1))
                .arg(Arg::with_name("name").help("The name of the package").required(true).index(2))
                .arg(Arg::with_name("version").help("The version of the package").required(true).index(3))
                .arg(Arg::with_name("description").help("The description of the package").required(true).index(4)),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("register") {
        let username = matches.value_of("username").unwrap();
        let password = matches.value_of("password").unwrap();
        register(username, password).await;
    } else if let Some(matches) = matches.subcommand_matches("login") {
        let username = matches.value_of("username").unwrap();
        let password = matches.value_of("password").unwrap();
        login(username, password).await;
    } else if let Some(matches) = matches.subcommand_matches("publish") {
        let filename = matches.value_of("filename").unwrap();
        let name = matches.value_of("name").unwrap();
        let version = matches.value_of("version").unwrap();
        let description = matches.value_of("description").unwrap();
        publish(filename, name, version, description).await;
    } else if let Some(_) = matches.subcommand_matches("install") {
        println!("Install command not implemented yet");
    } else {
        eprintln!("No valid subcommand was provided");
    }
}

async fn register(username: &str, password: &str) {
    let client = Client::new();
    let user = User {
        username: username.to_string(),
        password: password.to_string(),
    };

    let response = client
        .post("http://localhost:5000/register")
        .json(&user)
        .send()
        .await
        .expect("Failed to send request");

    let response_text = response.text().await.expect("Failed to read response text");
    println!("{}", response_text);
}

async fn login(username: &str, password: &str) {
    let client = Client::new();
    let login = User {
        username: username.to_string(),
        password: password.to_string(),
    };

    let response = client
        .post("http://localhost:5000/login")
        .json(&login)
        .send()
        .await
        .expect("Failed to send request");

    if response.status().is_success() {
        let cookies = response.headers().get(SET_COOKIE);
        match cookies {
            Some(cookie) => {
                println!("Login successful, session: {:?}", cookie);
                let session_id = cookie.to_str().unwrap().to_string();
                fs::write("session_id", &session_id).await.expect("Unable to write file");
                fs::write("username", &username).await.expect("Unable to write file");
            },
            None => {
                println!("No session cookie found");
            },
        }
        } else {
        println!("\x1b[31mLogin failed\x1b[0m");
    }
}

async fn publish(filename: &str, name: &str, version: &str, description: &str) {
    let username = fs::read_to_string("username").await.expect("Unable to read file");

    let package_data = json!({
        "name": name,
        "version": version,
        "description": description
    });

    let mut data = HashMap::new();
    data.insert("json", package_data.to_string());

    let client = Client::new();
    let session_id = fs::read_to_string("session_id").await.expect("Unable to read file");
    
    match File::open(&filename).await {
        Ok(_) => {
            let cookie_string = format!("session={}", session_id);
            let file_bytes = fs::read(&filename).await.expect("Unable to read file");
            let part = reqwest::multipart::Part::bytes(file_bytes).file_name(filename.to_string());
            let form = reqwest::multipart::Form::new()
                .text("json", package_data.to_string())
                .part("file", part);
            
            let response = client.post("http://localhost:5000/publish")
                .multipart(form)
                .header("Cookie", cookie_string)
                .send()
                .await
                .expect("Failed to send request");
            println!("{}", response.text().await.unwrap());
        },
        Err(_) => {
            println!("\x1b[31mFile {} not found!\x1b[0m", filename);
        },
    }
}