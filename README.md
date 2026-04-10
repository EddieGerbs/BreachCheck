# BreachCheck

A Python-based monitoring tool that checks for exposed credentials using the **DeHashed API** and sends alerts directly to Microsoft Teams via a webhook.

## 🚀 Features
- Queries the DeHashed API for breached credentials
- Monitors specific domains, emails, or usernames
- Sends real-time alerts to Microsoft Teams
- Lightweight and easy to automate
- Ideal for continuous breach monitoring

## 📦 Requirements
- Python 3
- Required libraries:
  - `pip install requests python-dotenv`
- `assets.txt`

## 🔐 Configuration
Before running the script, you must create a `.env` file in the project directory with the following variables:

- DEHASHED_API_KEY=your_dehashed_api_key
- TEAMS_WEBHOOK_URL=your_teams_webhook_url

## ⚙️ Usage
`python breach_monitor.py`

You can modify the script to define what data you want to monitor (e.g., domain, email, keyword).

## 🔍 How It Works
1. Loads environment variables from the .env file
2. Sends a query to the DeHashed API
3. Parses the response for relevant breach data
4. Sends formatted alerts to Microsoft Teams via webhook

## 📁 Project Structure
BreachCheck\
│── breach_monitor.py\
│── assets.txt\
│── .env (not included)\
│── /data (auto created)

## ⚠️ Disclaimer
This tool is intended for authorized security monitoring and defensive purposes only.
Ensure you have permission before querying or monitoring any data.

## 🛠️ Future Improvements
- Add scheduling/automation (cron jobs)
- Support for additional alerting platforms (Slack, Email, etc.)
