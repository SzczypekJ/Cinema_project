# Full project with dockerization you can find on the backup_2106 branch. There are also readme describing how to run the project. If you want to test the program itself, we recommend using the version without dockerization, which can be found in this branch (branch main)  
  
# Cinema Booking System

## Overview

The Cinema Booking System is a web-based application built using Flask and SQLAlchemy. It allows users to browse movies, view showtimes, book seats, and manage their bookings. The system includes user authentication, an admin panel for managing movies and showtimes, and automated seat release for expired bookings.

## Features

- **User Authentication:** Users can register, log in, and manage their accounts.
- **Movie Management:** Admins can add, edit, and delete movies from the database.
- **Showtime Management:** Admins can schedule showtimes for movies in various rooms.
- **Room and Seat Management:** Admins can manage rooms and their respective sections, including seats.
- **Booking System:** Users can book seats for specific showtimes and make payments for their bookings.
- **Automated Expired Booking Release:** Periodic checking and release of expired bookings to make seats available again.
- **Admin Dashboard:** Admins have access to a dashboard for managing users, rooms, movies, and showtimes.

## Technologies
- Backend: Python, Flask
- Frontend: HTML, CSS, JavaScript, Bootstrap
- Database: SQLite3, SQLAlchemy

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SzczypekJ/Cinema_project.git
   cd Cinema_project
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required packages:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   flask run
   ```

## Usage

### User Authentication

- **Register:** Users can create a new account.
- **Login:** Registered users can log in to their accounts.
- **Logout:** Users can log out from their accounts.

### Booking Flow

1. **Browse Movies and Showtimes:** Users can view the list of movies and their showtimes.
2. **Book Seats:** Users can select a movie, choose a showtime, and book available seats.
3. **Payment:** Users can complete their booking by making a payment.

### Admin Functions

- **Manage Movies:** Add, edit, and delete movies.
- **Manage Showtimes:** Schedule new showtimes, edit existing ones, and delete showtimes.
- **Manage Rooms and Sections:** Add new rooms, define sections within rooms, and manage seat arrangements.
- **User Management:** Admins can view all users, change user statuses, and delete users.

### Automated Tasks

- **Release Expired Bookings:** A background thread periodically checks and releases expired bookings to free up seats.

## Project Structure

- **app.py:** Main application file containing routes, application logic and database models.
- **templates/:** HTML templates for rendering web pages.
- **static/:** Static files like photos.
- **config.cfg:** Configuration file for application settings.

## Security

- **Password Hashing:** User passwords are securely hashed using PBKDF2 with SHA-512.
- **Session Management:** User sessions are managed using Flask's session management with a secret key.

## Contributing

Contributions are welcome! Please create a pull request with a detailed description of your changes.

## Admin Credentials

For initial setup, an admin user is created automatically. The credentials are:

- **Username:** dhg
- **Password:** hYk

It is recommended to change these credentials after the initial setup.

## Contact

For any questions or support, please contact jakub.szczypek@tlen.pl.
