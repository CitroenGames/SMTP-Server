// CitroenGames 2023

const express = require('express');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const sqlite3 = require('sqlite3').verbose();
const https = require('https');
const fs = require('fs');       
const expressBasicAuth = require('express-basic-auth');
const crypto = require('crypto');
require('dotenv').config();
const app = express();
const sanitizeHtml = require('sanitize-html');

const config = JSON.parse(fs.readFileSync('config.json', 'utf8'));

// Basic Authentication
app.use(expressBasicAuth(config.basicAuth));

// Read HTTPS related files
const httpsOptions = { 
    key: fs.readFileSync('./private.key'),
    cert: fs.readFileSync('./certificate.crt'),
    ca: fs.readFileSync('./ca_bundle.crt')
};

const ALGORITHM = 'aes-256-cbc';
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

function encrypt(text) {
    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// Setup SQLite database
const db = new sqlite3.Database('./emails.db', (err) => {
    if (err) {
        console.error('Could not connect to SQLite database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');

        // Create the emails table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_text TEXT,
            subject TEXT,
            text TEXT,
            date TEXT,
            received_at TEXT
        )`);
    }
});

const server = new SMTPServer({
    onData(stream, session, callback) {
        simpleParser(stream, {}, (err, parsed) => {
            if (err) {
                console.error('Error parsing email:', err);
            } else {
                console.log(`Received email from: ${parsed.from.text}`);
                console.log(`Received email for: ${parsed.to.text}`);
                
                // Get the current date and time
                const receivedAt = new Date().toISOString();

                // Save to SQLite3
                db.run('INSERT INTO emails (from_text, subject, text, date, received_at) VALUES (?, ?, ?, ?, ?)', 
                    [parsed.from.text, encrypt(parsed.subject), encrypt(parsed.text), parsed.date, receivedAt], 
                    (err) => {
                        if (err) {
                            console.error('Error saving email to database:', err.message);
                        } else {
                            console.log('Email saved to database.');
                            callback(null, "Email accepted");
                        }
                    }
                );
            }
            stream.on('end', callback);
        });
    },
    disabledCommands: ['AUTH'], // Disable authentication
});

server.on('error', (err) => {
    if (err.code === 'ECONNRESET') {
        console.log('Connection reset by peer');
    } else {
        console.error('SMTP Server Error:', err);
    }
    if (err.response) {
        console.error('SMTP Server Response:', err.response);
    }
    if (err.stack) {
        console.error('SMTP Server Stack:', err.stack);
    }
    if (err.command) {
        console.error('SMTP Server Command:', err.command);
    }
});

server.listen(25, '0.0.0.0', () => {
    console.log('SMTP server listening on port 25');
});

// front end web server
app.get('/', (req, res) => {
    // Set a limit on the number of emails to fetch (e.g., 100)
    const limit = 100;

    // Fetch the latest 'limit' emails from the database
    db.all("SELECT id, subject FROM emails ORDER BY received_at DESC LIMIT ?", [limit], (err, rows) => {
        if (err) {
            res.status(500).send("Error fetching emails from database");
            return;
        }

        // Generate the HTML for each email using the 'map' function
        const emailsHtml = rows.map(email => `
        <div>
            <a href="/email/${email.id}">${decrypt(email.subject)}</a>
            <hr>
        </div>
        `).join(''); // Join the array into a single string

        const html = `
            <h1>Emails</h1>
            
            <form action="/search" method="get">
                <input type="text" name="query" placeholder="Search by subject or content...">
                <button type="submit">Search</button>
            </form>

            ${emailsHtml}
        `;

        res.send(html);
    });
});

app.get('/search', (req, res) => {
    const query = req.query.query;

    // Use SQLite's LIKE clause for a case-insensitive search for both subject and email text
    db.all("SELECT id, subject FROM emails WHERE subject LIKE ? OR text LIKE ? ORDER BY received_at DESC", [`%${query}%`, `%${query}%`], (err, rows) => {
        if (err) {
            res.status(500).send("Error searching emails");
            return;
        }

        const emailsHtml = rows.map(email => `
            <div>
                <a href="/email/${email.id}">${email.subject}</a>
                <hr>
            </div>
        `).join('');

        const html = `
            <h1>Search Results for "${query}"</h1>
            
            <form action="/search" method="get">
                <input type="text" name="query" value="${query}" placeholder="Search by subject or content...">
                <button type="submit">Search</button>
            </form>
            
            ${emailsHtml}
            <a href="/">Back to emails list</a>
        `;

        res.send(html);
    });
});

app.get('/email/:id', (req, res) => {
    const emailId = req.params.id;

    db.get("SELECT * FROM emails WHERE id = ?", [emailId], (err, email) => {
        if (err) {
            res.status(500).send("Error fetching email from database");
            return;
        }

        if (!email) {
            res.status(404).send("Email not found");
            return;
        }

        // Sanitize the email text before rendering it as HTML
        const sanitizedText = sanitizeHtml(email.text, {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
            allowedAttributes: {
                'a': ['href', 'title', 'target'],
                'img': ['src', 'alt', 'title', 'width', 'height']
            }
        });

        const html = `
        <h1>${decrypt(email.subject)}</h1>
        <p>From: ${email.from_text}</p>
        <p>Date: ${email.date}</p>
        <p>Received at: ${email.received_at}</p>
        <div>${sanitizeHtml(decrypt(email.text), {
            allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
            allowedAttributes: {
                'a': ['href', 'title', 'target'],
                'img': ['src', 'alt', 'title', 'width', 'height']
            }
        })}</div>
        <hr>
        <a href="/">Back to emails list</a>
    `;
    
        res.send(html);
    });
});

const httpsServer = https.createServer(httpsOptions, app);

// Start Express server on port 400
httpsServer.listen(400, () => {  
    console.log('HTTPS web server started on port 400');  
});