# SMTP-Server
A custom-built SMTP server with web-based front-end for viewing emails, integrated with SQLite for email storage.

## Features

- **SMTP Server**: Built using the `smtp-server` package to handle incoming emails.
- **Web-based UI**: Express-based front-end to view and search through received emails.
- **SQLite Integration**: Stores emails in an SQLite database for persistence.
- **Encryption**: Emails stored in the database are encrypted to ensure data privacy.
- **Authentication**: Secured web front-end with basic authentication.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/CitroenGames/SMTP-Server.git
   ```

2. Navigate to the project directory:
   ```
   cd SMTP-Server
   ```

3. Install the dependencies:
   ```
   npm install
   ```

4. Generate the `.env` file by running:
   ```
   node create-encrypt-file.js
   ```
   This will generate a unique encryption key for your server.

5. Set up your `config.json` for other configuration settings like basic authentication. For more information on this, refer to the Configuration section.

6. Start the server:
   ```
   npm start
   ```

## Configuration

To configure the SMTP server and web front-end:

- **.env**: Contains sensitive configurations like the encryption key generated by the `create-encrypt-file.js` script.

- **config.json**: Contains configurations like basic authentication settings.
   Example:
   ```json
   {
      "basicAuth": {
          "users": {
              "user": "pass"
          },
          "challenge": true,
          "realm": "My SMTP Web Server"
      }
   }
   ```

## Security

Ensure to change the default authentication credentials before deploying to a production environment. Keep the `.env` and `config.json` files secured.

## Contribute

Want to contribute to the development of SMTP-Server? Check out our [CONTRIBUTING.md](path-to-your-contributing.md-if-you-have-one) or simply create an issue or a pull request.

## License

[MIT License](path-to-your-license-file-if-you-have-one)

---

This should better match the setup process for your project. Again, adjust any placeholder values to suit your actual project details.
