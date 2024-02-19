extern crate reqwest;
extern crate chrono;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::Path;
use chrono::{Utc, Duration};

const PROCESSED_FILE_PATH: &str = "processed_offenses.txt";
const QRADAR_URL: &str = "https://IP/api/siem/offenses";
const NEXTCLOUD_URL: &str = "http://IP/index.php/apps/deck/api/v1.0/boards/2";
const NEXTCLOUD_DECK_URL: &str = "http://IP/index.php/apps/deck/api/v1.0/boards/2/stacks/4/cards";

fn get_label_id(board_id: u32, label_title: &str, nextcloud_username: &str, nextcloud_password: &str) -> Option<u32> {
    let label_url = format!("http://IP/index.php/apps/deck/api/v1.0/boards/{}", board_id);
    let client = reqwest::blocking::Client::new();
    let response = client.get(&label_url)
        .basic_auth(nextcloud_username, Some(nextcloud_password))
        .header("OCS-APIRequest", "true")
        .header("Content-Type", "application/json;charset=utf-8")
        .send()
        .expect("Failed to fetch labels from board");

    if response.status().is_success() {
        let labels: Vec<HashMap<String, serde_json::Value>> = response.json().unwrap();
        for label in labels {
            if let Some(title) = label.get("title") {
                if title == label_title {
                    if let Some(id) = label.get("id") {
                        return Some(id.as_u64().unwrap() as u32);
                    }
                }
            }
        }
    }
    None
}

fn read_processed_offenses() -> HashMap<u32, u32> {
    let path = Path::new(PROCESSED_FILE_PATH);
    let mut processed = HashMap::new();
    if let Ok(file) = File::open(&path) {
        let reader = io::BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.trim().split(',').collect();
                if let Some((offense_id, card_id)) = parts.split_first() {
                    if !card_id.is_empty() {
                        processed.insert(offense_id.parse().unwrap(), card_id.parse().unwrap());
                    }
                }
            }
        }
    }
    processed
}

fn write_processed_offenses(offense_id: u32, card_id: u32) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(PROCESSED_FILE_PATH)
        .expect("Failed to open processed offenses file");

    writeln!(file, "{},{}", offense_id, card_id).expect("Failed to write to processed offenses file");
}

fn remove_processed_offense(offense_id: u32) {
    let path = Path::new(PROCESSED_FILE_PATH);
    let lines: Vec<String> = match fs::read_to_string(&path) {
        Ok(content) => content.lines().map(|s| s.to_string()).collect(),
        Err(_) => Vec::new(),
    };

    let mut file = File::create(&path).expect("Failed to open processed offenses file");
    for line in lines {
        if !line.starts_with(&format!("{},", offense_id)) {
            writeln!(file, "{}", line).expect("Failed to write to processed offenses file");
        }
    }
}

fn move_card(card_id: u32, offense_id: u32, nextcloud_username: &str, nextcloud_password: &str) {
    let processed_offenses = read_processed_offenses();
    if let Some(&existing_card_id) = processed_offenses.get(&offense_id) {
        // Fetch the details of the card to be moved
        let card_url = format!("http://IP/index.php/apps/deck/api/v1.0/boards/2/stacks/4/cards/{}", card_id);
        let client = reqwest::blocking::Client::new();
        let response = client.get(&card_url)
            .basic_auth(nextcloud_username, Some(nextcloud_password))
            .send()
            .expect("Failed to fetch card details");

        if response.status().is_success() {
            let card_data: serde_json::Value = response.json().unwrap();

            // Prepare data for creating a new card
            let mut new_card_data = card_data.clone().as_object().unwrap().clone();
            let new_card_labels = new_card_data.get_mut("labels").unwrap().as_array_mut().unwrap();
            new_card_labels.push(serde_json::json!(get_label_id(2, "Finished", nextcloud_username, nextcloud_password)));

            // Fetch notes for the offense_id
            let notes_url = format!("https://IP/api/siem/offenses/{}/notes", offense_id);
            let notes_response = client.get(&notes_url)
                .basic_auth("Username", Some("password"))
                .send()
                .expect("Failed to fetch notes for offense");

            if notes_response.status().is_success() {
                let notes_data: Vec<HashMap<String, serde_json::Value>> = notes_response.json().unwrap();
                let comments: String = notes_data.iter()
                    .map(|note| note.get("note_text").unwrap().as_str().unwrap())
                    .collect::<Vec<&str>>()
                    .join("\n");
                let description = new_card_data.get_mut("description").unwrap().as_str_mut().unwrap();
                description.push_str(&format!("\n\nNotes:\n{}", comments));

                // Create a new card in stack_id 5
                let new_card_url = format!("http://IP/index.php/apps/deck/api/v1.0/boards/2/stacks/5/cards");
                let new_card_response = client.post(&new_card_url)
                    .basic_auth(nextcloud_username, Some(nextcloud_password))
                    .json(&new_card_data)
                    .header("OCS-APIRequest", "true")
                    .header("Content-Type", "application/json;charset=utf-8")
                    .send()
                    .expect("Failed to create new card");

                if new_card_response.status().is_success() {
                    println!("Card {} moved to stack 5 successfully.", card_id);

                    // Remove offense from processed offenses
                    remove_processed_offense(offense_id);

                    // Delete the card from the board
                    let delete_card_url = format!("http://IP/index.php/apps/deck/api/v1.0/boards/2/stacks/4/cards/{}", card_id);
                    let delete_response = client.delete(&delete_card_url)
                        .basic_auth(nextcloud_username, Some(nextcloud_password))
                        .send()
                        .expect("Failed to delete card from the board");

                    if delete_response.status().is_success() {
                        println!("Card {} deleted successfully from the board.", card_id);
                    } else {
                        println!("Failed to delete card {} from the board. Error: {}", card_id, delete_response.text().unwrap_or_default());
                    }
                } else {
                    println!("Failed to move card {}. Error: {}", card_id, new_card_response.text().unwrap_or_default());
                }
            } else {
                println!("Failed to fetch notes for offense {}. Error: {}", offense_id, notes_response.text().unwrap_or_default());
            }
        } else {
            println!("Failed to fetch card {}. Error: {}", card_id, response.text().unwrap_or_default());
        }
    } else {
        println!("Offense ID {} not found in processed offenses.", offense_id);
    }
}

fn create_deck_card(offense: serde_json::Value, nextcloud_username: &str, nextcloud_password: &str) {
    let current_time = Utc::now();
    let due_date = (current_time + Duration::hours(5)).to_rfc3339();

    let mut description = format!("This event has been triggered: {}\n", offense["event_count"]);
    description += &format!("The user who handles this offense: {}\n", offense["assigned_to"]);
    description += &format!("Offense Source: {}\n", offense["offense_source"]);
    description += &format!("Status: {}\n", offense["status"]);
    description += &format!("Categories: {}\n", offense["categories"]);
    description += &format!("Description: {}\n", offense["description"]);
    description += &format!("Severity: {}\n", offense["severity"]);
    description += &format!("Magnitude: {}", offense["magnitude"]);

    let action_needed_label_id = get_label_id(2, "Action needed", nextcloud_username, nextcloud_password);
    let finished_label_id = get_label_id(2, "Finished", nextcloud_username, nextcloud_password);

    if let (Some(action_needed_label_id), Some(finished_label_id)) = (action_needed_label_id, finished_label_id) {
        let mut card_data = json!({
            "title": format!("Offense ID {}", offense["id"]),
            "description": description,
            "type": "plain",
            "order": 999,
            "duedate": due_date,
            "owner": offense["assigned_to"],
            "labels": [action_needed_label_id, finished_label_id]
        });

        let client = reqwest::blocking::Client::new();
        let response = client.post(NEXTCLOUD_DECK_URL)
            .basic_auth(nextcloud_username, Some(nextcloud_password))
            .json(&card_data)
            .header("OCS-APIRequest", "true")
            .header("Content-Type", "application/json;charset=utf-8")
            .send()
            .expect("Failed to create Nextcloud Deck card");

        if response.status().is_success() {
            let card_id = response.json::<HashMap<String, serde_json::Value>>().unwrap()["id"].as_u64().unwrap() as u32;
            println!("Nextcloud Deck card created successfully for Offense ID {} with Card ID {}", offense["id"], card_id);
            write_processed_offenses(offense["id"].as_u64().unwrap() as u32, card_id);

            // Add a comment
            let comment_data = json!({
                "message": "Working on progress... Will update you with the results",
                "parentId": null
            });
            let comment_url = format!("http://IP/ocs/v2.php/apps/deck/api/v1.0/cards/{}/comments", card_id);
            let comment_response = client.post(&comment_url)
                .basic_auth(nextcloud_username, Some(nextcloud_password))
                .json(&comment_data)
                .header("OCS-APIRequest", "true")
                .header("Content-Type", "application/json;charset=utf-8")
                .send()
                .expect("Failed to add comment to the board");

            if comment_response.status().is_success() {
                println!("Comment added successfully to the board for Offense ID {}", offense["id"]);
            } else {
                println!("Failed to add comment to the board for Offense ID {}. Error: {}", offense["id"], comment_response.text().unwrap_or_default());
            }

            // Assign user to the board
            let assign_user_url = format!("http://IP/index.php/apps/deck/api/v1.2/boards/2/stacks/4/cards/{}/assignUser", card_id);
            let assign_user_data = json!({
                "userId": offense["assigned_to"]
            });
            let assign_user_response = client.put(&assign_user_url)
                .basic_auth(nextcloud_username, Some(nextcloud_password))
                .json(&assign_user_data)
                .header("OCS-APIRequest", "true")
                .header("Content-Type", "application/json;charset=utf-8")
                .send()
                .expect("Failed to assign user to the board");

            if assign_user_response.status().is_success() {
                println!("User assigned successfully to the board for Offense ID {}", offense["id"]);
            } else {
                println!("Failed to assign user to the board for Offense ID {}. Error: {}", offense["id"], assign_user_response.text().unwrap_or_default());
            }
        } else {
            println!("Failed to create Nextcloud Deck card for Offense ID {}. Error: {}", offense["id"], response.text().unwrap_or_default());
        }
    } else {
        println!("One or both labels not found on the board.");
    }
}

fn process_qradar_offenses(nextcloud_username: &str, nextcloud_password: &str) {
    let client = reqwest::blocking::Client::new();
    let qradar_response = client.get(QRADAR_URL)
        .basic_auth("Username", Some("password"))
        .header("Range", "items=0-49")
        .header("Version", "12.0")
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("SEC", "API-KEY")
        .send()
        .expect("Failed to fetch Qradar offenses");

    if qradar_response.status().is_success() {
        let offenses_data: Vec<serde_json::Value> = qradar_response.json().unwrap();
        let processed_offenses = read_processed_offenses();

        if processed_offenses.is_empty() {
            for offense in &offenses_data {
                create_deck_card(offense.clone(), nextcloud_username, nextcloud_password);
            }
        } else {
            for (offense_id, card_id) in processed_offenses {
                if let Some(offense) = offenses_data.iter().find(|o| o["id"].as_u64().unwrap() as u32 == offense_id) {
                    if offense["status"] != "OPEN" {
                        move_card(card_id, offense_id, nextcloud_username, nextcloud_password);
                    } else {
                        println!("All the data are up and running");
                    }
                }
            }
        }
    } else {
        println!("Failed to fetch Qradar offenses. Error: {}", qradar_response.text().unwrap_or_default());
    }
}

fn main() {
    let nextcloud_username = "Username";
    let nextcloud_password = "Password";

    loop {
        process_qradar_offenses(nextcloud_username, nextcloud_password);
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
}
