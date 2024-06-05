use clap::{App, Arg, SubCommand};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use reqwest::header::SET_COOKIE;
use reqwest::Client;
use serde::Serialize;
use std::path::Path;
use std::fs::File;
use tar;

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
            SubCommand::with_name("install")
                .about("Install a package")
                .arg(Arg::with_name("name").help("The name of the package").required(true).index(1))
                .arg(Arg::with_name("version").help("The version of the package").required(false).index(2)),
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
    } else if let Some(matches) = matches.subcommand_matches("install") {
        let name = matches.value_of("name").unwrap();
        let version = matches.value_of("version").unwrap();
        install(name, Some(version)).await;
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

async fn install(name: &str, version: Option<&str>) {
    let client = Client::new();

    let version = match version {
        Some(v) => v.to_string(),
        None => {
            match get_latest_version(name).await {
                Some(v) => v,
                None => {
                    println!("Unable to determine the latest version for {}", name);
                    return;
                }
            }
        }
    };

    println!("Installing {} version {}", name, version);

    let url = format!("http://localhost:5000/packages/{}-{}", name, version);
    let response = client.get(&url).send().await.expect("Failed to send request");
    let file_path = format!("{}-{}.xz", name, version);

    if response.status().is_success() {
        let response_bytes = response.bytes().await.expect("Failed to read response bytes");
        let package_data = response_bytes.clone();
        
        // Save the package data to a file
        let mut file = tokio::fs::File::create(&file_path)
            .await
            .expect("Unable to create file");

        file.write_all(&package_data)
            .await
            .expect("Unable to write file");

        println!("Package downloaded successfully and saved to {}", file_path);
    } else {
        println!("\x1b[31mError downloading package {}: {}\x1b[0m", name, response.status());
    }

    // Extract the downloaded file to "/"
    let extract_path = Path::new("/");
    let extract_result = tar::Archive::new(File::open(&file_path).expect("Unable to open file")).unpack(extract_path);

    match extract_result {
        Ok(_) => {
            println!("Package extracted successfully to {}", extract_path.display());
        }
        Err(e) => {
            println!("Failed to extract package: {}", e);
        }
    }

    println!("{}-{} Package downloaded successfully and Installed to {}", name, version, file_path);
}
    

async fn get_latest_version(name: &str) -> Option<String> {
    let client = Client::new();
    let url = format!("http://localhost:5000/versions/{}", name);
    let response = client.get(&url).send().await;

    match response {
        Ok(response) => {
            if response.status().is_success() {
                let versions: Vec<String> = response.json().await.expect("Failed to parse JSON");
                if !versions.is_empty() {
                    let latest_version = versions.iter().max().unwrap().to_owned();
                    return Some(latest_version);
                }
            } else {
                println!("\x1b[31mError fetching latest version for {}: {}\x1b[0m", name, response.status());
            }
        }
        Err(e) => {
            println!("\x1b[31mError fetching latest version for {}: {}\x1b[0m", name, e);
        }
    }

    None
}