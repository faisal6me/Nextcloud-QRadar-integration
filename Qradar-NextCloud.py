import requests
from datetime import datetime, timedelta
import time
import urllib3
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Configuration for QRadar and Nextcloud
qradar_url = 'https://IP/api/siem/offenses'
qradar_username = 'Username'
qradar_password = 'password'
qradar_headers = {
    'Range': 'items=0-49',
    'Version': '12.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'SEC': 'API-KEY'
}

nextcloud_url = 'http://IP/index.php/apps/deck/api/v1.0/boards/2'
nextcloud_username = 'Username'
nextcloud_password = 'Password'
board_id = 2
stack_id = 4
processed_file_path = 'processed_offenses.txt'

def get_label_id(board_id, label_title):
    label_url = f'http://IP/index.php/apps/deck/api/v1.0/boards/{board_id}'
    response = requests.get(label_url, auth=(nextcloud_username, nextcloud_password),
                            headers={'OCS-APIRequest': 'true',
                                     'Content-Type': 'application/json;charset=utf-8'},
                            verify=False)

    if response.status_code == 200:
        labels = response.json().get('labels')
        for label in labels:
            if label.get('title') == label_title:
                return label.get('id')
    else:
        print(f"Failed to fetch labels from board {board_id}")
        print(response.text)
        return None

action_needed_label_id = get_label_id(board_id, "Action needed")
finished_label_id = get_label_id(board_id, "Finished")

def read_processed_offenses():
    try:
        with open(processed_file_path, 'r') as file:
            processed = {}
            for line in file:
                offense_id, card_id = line.strip().split(',')
                if card_id:  # Check if card_id is not an empty string
                    processed[int(offense_id)] = int(card_id)
            return processed
    except FileNotFoundError:
        return {}


def write_processed_offenses(offense_id, card_id):
    with open(processed_file_path, 'a') as file:
        file.write(f"{offense_id},{card_id}\n")

def remove_processed_offense(offense_id):
    with open(processed_file_path, 'r') as file:
        lines = file.readlines()
    

    with open(processed_file_path, 'w') as file:
        for line in lines:
            if not line.startswith(f"{offense_id},"):
                file.write(line)

def MoveCard(card_id, offense_id):
    processed_offenses = read_processed_offenses()  # Retrieve processed offenses
    if offense_id in processed_offenses:  # Check if offense_id is in the processed offenses
        # Fetch the details of the card to be moved
        card_url = f'http://IP/index.php/apps/deck/api/v1.0/boards/{board_id}/stacks/{stack_id}/cards/{card_id}'
        response = requests.get(card_url, auth=(nextcloud_username, nextcloud_password), verify=False)

        if response.status_code == 200:
            card_data = response.json()

            # Prepare data for creating a new card
            new_card_data = {
                "title": card_data["title"],
                "description": card_data["description"],
                "type": card_data["type"],
                "order": card_data["order"],
                "duedate": card_data["duedate"],
                "owner": card_data["owner"],
                "labels": [finished_label_id]
            }

            # Fetch notes for the offense_id
            notes_url = f'https://IP/api/siem/offenses/{offense_id}/notes'
            notes_response = requests.get(notes_url, auth=(qradar_username, qradar_password), verify=False)
            if notes_response.status_code == 200:
                notes_data = notes_response.json()
                # Extract note text from notes_data and add as comments to the card
                comments = "\n".join([note["note_text"] for note in notes_data])
                new_card_data["description"] += f"\n\nNotes:\n{comments}"

                # Create a new card in stack_id 5
                new_card_url = f'http://IP/index.php/apps/deck/api/v1.0/boards/{board_id}/stacks/5/cards'
                new_card_response = requests.post(new_card_url, auth=(nextcloud_username, nextcloud_password),
                                                   json=new_card_data,
                                                   headers={'OCS-APIRequest': 'true',
                                                            'Content-Type': 'application/json;charset=utf-8'}, verify=False)

                if new_card_response.status_code == 200:
                    print(f"Card {card_id} moved to stack 5 successfully.")

                    # Remove offense from processed offenses
                    del processed_offenses[offense_id]
                    write_processed_offenses(offense_id, "")  

                    # Delete the card from the board
                    delete_card_url = f'http://IP/index.php/apps/deck/api/v1.0/boards/{board_id}/stacks/{stack_id}/cards/{card_id}'
                    delete_response = requests.delete(delete_card_url, auth=(nextcloud_username, nextcloud_password), verify=False)
                    if delete_response.status_code == 204:
                        print(f"Card {card_id} deleted successfully from the board.")
                    else:
                        print(f"Failed to delete card {card_id} from the board. Error: {delete_response.text}")

                else:
                    print(f"Failed to move card {card_id}. Error: {new_card_response.text}")
            elif notes_response.status_code == 403 and notes_response.json().get("message") == "Card is deleted":
                print(f"Card {card_id} is deleted. Skipping move card operation for this offense.")
            else:
                print(f"Failed to fetch notes for offense {offense_id}. Error: {notes_response.text}")
        else:
            print(f"Failed to fetch card {card_id}. Error: {response.text}")
    else:
        print(f"Offense ID {offense_id} not found in processed offenses.")


def create_deck_card(offense):
    nextcloud_deck_url = 'http://IP/index.php/apps/deck/api/v1.0/boards/{}/stacks/{}/cards'.format(
        board_id, stack_id)

    current_time = datetime.utcnow()
    due_date = (current_time + timedelta(hours=5)).isoformat()

    description = f"This event has been triggered: {offense['event_count']}\n"
    description += f"The user who handles this offense: {offense['assigned_to']}\n"
    description += f"Offense Source: {offense['offense_source']}\n"
    description += f"Status: {offense['status']}\n"
    description += f"Categories: {offense['categories']}\n"
    description += f"Description: {offense['description']}\n"
    description += f"Severity: {offense['severity']}\n"
    description += f"Magnitude: {offense['magnitude']}"

    # Fetch label ID for "Action needed"
    action_needed_label_id = get_label_id(board_id, "Action needed")

    if action_needed_label_id is not None and finished_label_id is not None:
        card_data = {
            "title": f"Offense ID {offense['id']}",
            "description": description,
            "type": "plain",
            "order": 999,
            "duedate": due_date,
            "owner": offense['assigned_to'],
            "labels": [action_needed_label_id, finished_label_id]  # Add both label IDs to the card data
        }
    else:
        print("One or both labels not found on the board.")
        return

    response = requests.post(nextcloud_deck_url, auth=(nextcloud_username, nextcloud_password), json=card_data,
                             headers={'OCS-APIRequest': 'true',
                                      'Content-Type': 'application/json;charset=utf-8'}, verify=False)
    if response.status_code == 200:
        card_id = response.json().get('id')
        print(f"Nextcloud Deck card created successfully for Offense ID {offense['id']} with Card ID {card_id}")
        write_processed_offenses(offense['id'], card_id)

        # Add a comment
        comment_data = {
            "message": "Working on progress... Will update you with the results",
            "parentId": None,
        }
        comment_url = f'http://IP/ocs/v2.php/apps/deck/api/v1.0/cards/{card_id}/comments'
        comment_response = requests.post(comment_url, auth=(nextcloud_username, nextcloud_password),
                                         json=comment_data,
                                         headers={'OCS-APIRequest': 'true',
                                                  'Content-Type': 'application/json;charset=utf-8'}, verify=False)

        if comment_response.status_code == 200:
            print(f"Comment added successfully to the board for Offense ID {offense['id']}")
        else:
            print(f"Failed to add comment to the board for Offense ID {offense['id']}")
            print(comment_response.text)

        # Assign user to the board
        assign_user_url = f'http://IP/index.php/apps/deck/api/v1.2/boards/2/stacks/4/cards/{card_id}/assignUser'
        assign_user_data = {
            "userId": offense['assigned_to'],
        }
        assign_user_response = requests.put(assign_user_url, auth=(nextcloud_username, nextcloud_password),
                                            json=assign_user_data,
                                            headers={'OCS-APIRequest': 'true',
                                                     'Content-Type': 'application/json;charset=utf-8'},
                                            verify=False)

        if assign_user_response.status_code == 200:
            print(f"User assigned successfully to the board for Offense ID {offense['id']}")
        else:
            print(f"Failed to assign user to the board for Offense ID {offense['id']}")
            print(assign_user_response.text)
    else:
        print(f"Failed to create Nextcloud Deck card for Offense ID {offense['id']}")
        print(response.text)

def process_qradar_offenses():
    qradar_response = requests.get(qradar_url, auth=(qradar_username, qradar_password), headers=qradar_headers,
                                   verify=False)

    if qradar_response.status_code == 200:
        offenses_data = qradar_response.json()
        processed_offenses = read_processed_offenses()

        if not processed_offenses:  # If there are no processed offenses yet
            for offense in offenses_data:
                create_deck_card(offense)
        else:
            for offense_id, card_id in processed_offenses.items():
                # Find the corresponding offense in the retrieved data
                offense = next((o for o in offenses_data if o.get('id') == offense_id), None)
                if offense and offense.get('status') != 'OPEN':
                    MoveCard(card_id, offense_id)  # Move the card to stack 5
                else:
                    print("All the data are up and rungin")
    else:
        print("Failed to fetch Qradar offenses.")
        print(qradar_response.text)

while True:
    process_qradar_offenses()
    time.sleep(20)
