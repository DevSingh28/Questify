# Questify - Online Learning Platform

Questify is a modern and intuitive online learning platform built using Flask. It offers a wide range of features to enhance the learning experience for users.

## Features

- **User Registration and Authentication**: Users can easily register an account and securely log in to access the platform's features.
- **Course Management**: Admins can upload, edit, and delete courses, providing a diverse range of learning materials.
- **Note-taking**: Users can take notes while watching course videos, facilitating better retention and comprehension.
- **Password Reset**: Forgot your password? No problem! Users can reset their passwords securely.
- **Email Verification**: Questify ensures account security with email verification for registration and password reset functionalities.
- **Admin Panel**: Admins have access to special functionalities such as course management and user moderation.
- **Responsive Design**: The platform is designed to be responsive and mobile-friendly, ensuring a seamless experience across devices.

## Technologies Used

- **Flask**: Python-based web framework for building the application.
- **Bootstrap**: Frontend framework for designing responsive and attractive UI.
- **SQLAlchemy**: ORM for working with databases.
- **Flask-Login**: Provides user session management.
- **Flask-CKEditor**: Integration for rich text editing capabilities.
- **Flask-Gravatar**: Integration for displaying user avatars.
- **SMTP (Simple Mail Transfer Protocol)**: Used for sending email notifications.
- **ItsDangerous**: Library for generating and verifying tokens for email verification and password reset.
- **Werkzeug**: Library for password hashing and verification.

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/DevSingh28/Questify.git


2. Install Requirements

   ```bash
   pip install -r requirements.txt


3. Set up environment variables:

   ```bash
   coffee_key: Secret key for Flask application.
   myemail: Email address for sending notifications.
   gm_pass: Password for the email account.
   DB_URI3: URI for the database (optional, defaults to SQLite).
   

4. Contributing:
   ```bash
   Contributions are welcome! If you have any suggestions, feature requests, or bug reports, please open an issue or create a pull request.