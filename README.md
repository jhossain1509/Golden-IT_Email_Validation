# Golden-IT_Email_Validation

An email validation tool that uses Google Sheets and browser automation to validate email addresses in bulk with real-time server synchronization.

## Features

- **Batch Email Validation**: Validate large lists of emails efficiently
- **Google Sheets Integration**: Leverages Google Sheets for validation
- **Multi-Account Support**: Rotate through multiple Gmail accounts
- **Real-time Server Sync**: Push valid emails to a remote endpoint in real-time
- **GUI Interface**: Easy-to-use graphical interface built with Tkinter
- **Headless Mode**: Option to run browser in headless mode
- **Proxy Support**: Configure proxy for browser automation

## Requirements

- Python 3.8 or higher
- Required Python packages (see requirements.txt):
  - requests
  - DrissionPage

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jhossain1509/Golden-IT_Email_Validation.git
   cd Golden-IT_Email_Validation
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python Golden-IT_Email_Validation_v2.1.py
   ```

2. Enter your license key when prompted

3. Configure the application:
   - Load Gmail accounts file (format: email:password:recovery)
   - Load email list files to validate
   - Set batch size and checks per account
   - Configure Google Sheet URL

4. Click "Start" to begin validation

## File Formats

### Gmail Accounts File
```
email@gmail.com:password:recovery_email@example.com
another@gmail.com:password:recovery@example.com
```

### Email List Files
```
email1@example.com
email2@example.com
email3@example.com
```

## Output Files

- `valid_mail.txt` - List of validated email addresses
- `invalid_mail.txt` - List of invalid email addresses
- `failed_gmails.txt` - List of Gmail accounts that failed during validation
- `*_cleaned.txt` - Cleaned versions of input email files

## License

This software requires a valid license key. Contact via WhatsApp: +8801948241312

## Version

Current version: v2.1
