# Contacts System

## Project Description
The Contacts System is a web-based application designed to manage personal or business contact information effectively. It provides a user-friendly interface to create, view, update, and delete contact records. This system is ideal for individuals and organizations looking to maintain and organize their contact data seamlessly.

### Key Features:
- Add new contacts with name and email information.
- Search for specific contacts by their unique ID.
- Update existing contact information.
- Delete contacts when no longer needed.
- View a comprehensive list of all stored contacts.

## Project Members
- Serik Nurtas

## Screenshot
![Screenshot of Main Page](screenshot.png)

## Getting Started
Follow the steps below to set up and run the Contacts System project:

### Prerequisites
- [Go](https://go.dev/) installed on your machine.
- PostgreSQL database configured.
- Basic knowledge of running a web server.

### Installation Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/seriknurtas/ap1.git
   cd contacts-system
   ```

2. **Set up the database:**
   - Configure a PostgreSQL database.
   - Update the database connection string in the `initDB` function inside the `main.go` file.
   - Ensure the database table is created using the migration script provided in the `initDB` function.

3. **Run the server:**
   ```bash
   go run main.go
   ```
   The server will start at `http://localhost:8080`.

4. **Open the web page:**
   - Open the `index.html` file in any modern web browser or host it on a local web server.
   - Ensure the frontend is able to connect to the backend server running on port `8080`.

### API Endpoints
- `GET /contacts`: Fetch all contacts.
- `GET /contacts/{id}`: Fetch a specific contact by ID.
- `POST /contacts`: Create a new contact.
- `PUT /contacts/{id}`: Update an existing contact.
- `DELETE /contacts?id={id}`: Delete a contact by ID.

## Tools and Resources Used
- **Programming Language:** Go (Golang)
- **Frontend:** HTML, CSS, JavaScript
- **Database:** PostgreSQL
- **Frameworks/Libraries:**
  - `lib/pq` for PostgreSQL integration
  - Gorm (planned for future enhancements)
- **Other Tools:**
  - Postman for API testing
  - Git for version control
  - Web browser for frontend testing

---
Feel free to contribute or provide feedback to improve this project!

