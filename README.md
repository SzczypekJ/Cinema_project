# Cinema Seat Reservation System
## Project Description
The cinema seat reservation system consists of three main services:

1. Authorization Service (auth_service) - manages the user login and registration process.
2. Admin Service (admin_service) - allows administrators to manage the repertoire, cinema halls, and reservations.
3. User Service (user_service) - allows users to browse the repertoire, select seats, and make reservations.

The services communicate with each other through a shared database located on the AGH server. User switching between different services during system usage is handled through appropriate redirects on the frontend.

## Technologies
- Backend: Python, Flask
- Frontend: HTML, CSS, JavaScript
- Database: MySQL
- Containerization: Docker
- Server: AGH Server

## Setup Instructions
### Prerequisites
- Docker
- requirements from requirements.txt files for each service

### Installation
1. Clone the repository:

```
    git clone https://github.com/your-username/cinema-seat-reservation-system.git
    cd cinema-seat-reservation-system
```
2. Connect to AGH VPN.

3. Build and start Docker containers :

```
    docker-compose up --build
```
## Usage
1. Registration and Login: Users and administrators register and log in using the authorization service (auth_service).
2. System Management by Administrator: If logged-in user is an admin he gets access to the admin service (admin_service) to manage the repertoire, rooms and reservations.
3. Seat Reservation by Users: Logged-in users navigate to the user service (user_service) to browse the repertoire, select a show, and reserve seats.