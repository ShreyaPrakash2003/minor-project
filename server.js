const express = require('express');
const axios = require('axios');
const path = require('path');
const session = require('express-session');
const FormData = require('form-data');
const multer = require('multer');
const http = require('http');

const app = express();
const port = 8000;

const server = http.createServer(app);

// Set up multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// Middleware to normalize Content-Type header
app.use((req, res, next) => {
    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
        req.headers['content-type'] = 'application/json';
    }
    next();
});

// Middleware to log all requests
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} from ${req.ip}`);
    next();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session setup
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// In-memory store for request tracking (IP -> [timestamps])
const requestTracker = {};
const DDOS_THRESHOLD = 100;
const DDOS_WINDOW_SECONDS = 60;

// Middleware to track request rate
app.use((req, res, next) => {
    const sourceIp = req.ip;
    const currentTime = Date.now() / 1000; // Convert to seconds

    if (!requestTracker[sourceIp]) {
        requestTracker[sourceIp] = [];
    }

    // Add the current request timestamp
    requestTracker[sourceIp].push(currentTime);

    // Remove requests older than the window
    requestTracker[sourceIp] = requestTracker[sourceIp].filter(t => currentTime - t <= DDOS_WINDOW_SECONDS);

    // Log the request rate
    const requestCount = requestTracker[sourceIp].length;
    console.log(`Request from ${sourceIp}: ${requestCount} requests in the last ${DDOS_WINDOW_SECONDS} seconds`);

    if (requestCount > DDOS_THRESHOLD) {
        console.log(`Potential DDoS detected from ${sourceIp}: ${requestCount} requests in ${DDOS_WINDOW_SECONDS} seconds`);
    }

    next();
});

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session.isAuthenticated) {
        return next();
    }
    res.redirect('/login');
};

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Handle login by proxying to Flask
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const flaskResponse = await axios.post('http://localhost:5001/login', {
            username,
            password
        }, {
            headers: {
                'Content-Type': 'application/json'
            },
            withCredentials: true
        });

        if (flaskResponse.data.status === "success") {
            req.session.isAuthenticated = true;
            if (flaskResponse.headers['set-cookie']) {
                res.set('Set-Cookie', flaskResponse.headers['set-cookie']);
            }
            res.json({ status: "success", message: "Logged in successfully" });
        } else {
            res.status(401).json({ status: "error", message: "Invalid username or password" });
        }
    } catch (error) {
        console.error('Error during login:', error.message);
        res.status(500).json({ status: "error", message: "Server error during login" });
    }
});

// Handle logout
app.get('/logout', (req, res) => {
    try {
        axios.post('http://localhost:5001/logout', {}, {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': req.headers.cookie || ''
            },
            withCredentials: true
        })
        .then((flaskResponse) => {
            req.session.destroy();
            if (flaskResponse.headers['set-cookie']) {
                res.set('Set-Cookie', flaskResponse.headers['set-cookie']);
            }
            res.redirect('/login');
        })
        .catch(error => {
            console.error('Error during logout:', error.message);
            req.session.destroy();
            res.redirect('/login');
        });
    } catch (error) {
        console.error('Error during logout:', error.message);
        req.session.destroy();
        res.redirect('/login');
    }
});

// Serve public page
app.get('/', (req, res) => {
    console.log('Received request for /');
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve chatbot page (protected)
app.get('/chatbot', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chatbot.html'));
});

// Debug route to test Flask connectivity
app.get('/debug-flask', async (req, res) => {
    try {
        console.log('Cookies received from client for /debug-flask:', req.headers.cookie);
        const flaskResponse = await axios.get('http://localhost:5001/debug', {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': req.headers.cookie || ''
            },
            withCredentials: true
        });
        console.log('Response from Flask /debug:', flaskResponse.data);
        res.json(flaskResponse.data);
    } catch (error) {
        console.error('Error contacting Flask /debug:', error.response ? error.response.data : error.message);
        res.status(500).json({ 
            message: 'Error contacting Flask /debug', 
            details: error.response ? error.response.data : error.message 
        });
    }
});

// Handle text input submissions from public page
app.post('/submit', async (req, res) => {
    console.log(`Received /submit request - req.body: ${JSON.stringify(req.body)}`); // Log the parsed body

    const requestData = req.body.input || req.query.input || '';
    const sourceIp = req.ip;

    console.log(`Received /submit request - req.body.input: ${req.body.input}, requestData: ${requestData}`);

    if (!requestData) {
        return res.status(400).json({ message: 'No input provided' });
    }

    try {
        console.log('Cookies received from client for /submit:', req.headers.cookie);
        const chatbotResponse = await axios.post('http://localhost:5001/analyze', {
            request_data: requestData,
            source_ip: sourceIp
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': req.headers.cookie || ''
            },
            withCredentials: true,
            timeout: 60000  // Increased timeout to 60 seconds
        });
        console.log('Response from Flask /analyze:', chatbotResponse.data);
        res.json({ message: 'Request processed', status: chatbotResponse.data.status, type: chatbotResponse.data.type, details: chatbotResponse.data.details });
    } catch (error) {
        console.error('Error contacting chatbot:', error.response ? error.response.data : error.message);
        res.status(500).json({ message: 'Error processing request', details: error.response ? error.response.data : error.message });
    } 
});

// Handle file uploads from public page
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        console.log(`Received /upload request`);
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const formData = new FormData();
        formData.append('file', req.file.buffer, req.file.originalname);

        const response = await axios.post('http://localhost:5001/upload', formData, {
            headers: {
                ...formData.getHeaders()
            }
        });
        console.log(`Flask response for /upload: ${JSON.stringify(response.data)}`);
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error(`Error in /upload: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
        res.status(error.response?.status || 500).json(error.response?.data || { message: 'Server error' });
    }
});

// Serve report (protected)
app.get('/report', isAuthenticated, async (req, res) => {
    try {
        console.log('Cookies received from client for /report:', req.headers.cookie);
        const reportResponse = await axios.get('http://localhost:5001/report', {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': req.headers.cookie || ''
            },
            withCredentials: true,
            timeout: 60000  // Increased timeout to 60 seconds
        });
        console.log('Response from Flask /report:', reportResponse.data);
        res.json(reportResponse.data);
    } catch (error) {
        console.error('Error fetching report from Flask:', error.response ? error.response.data : error.message);
        res.status(500).json({ 
            message: 'Error fetching report', 
            details: error.response ? error.response.data : error.message 
        });
    }
});

// Proxy to get blocked IPs
app.get('/blocked-ips', isAuthenticated, async (req, res) => {
    try {
        console.log('Cookies received from client for /blocked-ips:', req.headers.cookie);
        const flaskResponse = await axios.get('http://localhost:5001/blocked-ips', {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': req.headers.cookie || ''
            },
            withCredentials: true,
            timeout: 60000
        });
        console.log('Response from Flask /blocked-ips:', flaskResponse.data);
        res.json(flaskResponse.data);
    } catch (error) {
        console.error('Error fetching blocked IPs from Flask:', error.response ? error.response.data : error.message);
        res.status(500).json({ 
            message: 'Error fetching blocked IPs', 
            details: error.response ? error.response.data : error.message 
        });
    }
});

// Proxy to unblock an IP
app.post('/unblock-ip', isAuthenticated, async (req, res) => {
    try {
        console.log('Cookies received from client for /unblock-ip:', req.headers.cookie);
        const flaskResponse = await axios.post('http://localhost:5001/unblock-ip', req.body, {
            headers: {
                'Content-Type': 'application/json',
                'Cookie': req.headers.cookie || ''
            },
            withCredentials: true,
            timeout: 60000
        });
        console.log('Response from Flask /unblock-ip:', flaskResponse.data);
        res.json(flaskResponse.data);
    } catch (error) {
        console.error('Error unblocking IP from Flask:', error.response ? error.response.data : error.message);
        res.status(500).json({ 
            message: 'Error unblocking IP', 
            details: error.response ? error.response.data : error.message 
        });
    }
});

// New route to proxy JMeter traffic to Flask
app.get('/traffic', async (req, res) => {
    try {
        console.log(`Received /traffic request from ${req.ip}`);
        const response = await axios.get('http://localhost:5001/traffic', {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log(`Flask response for /traffic: ${JSON.stringify(response.data)}`);
        res.status(response.status).json(response.data);
    } catch (error) {
        console.error(`Error in /traffic: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
        res.status(error.response?.status || 500).json(error.response?.data || { message: 'Server error' });
    }
});

// Configure server timeouts and keep-alive
server.setTimeout(120000);  // Increased server timeout to 120 seconds
server.keepAliveTimeout = 60000;  // Increased keep-alive timeout to 60 seconds
server.headersTimeout = 60000;  // Increased headers timeout to 60 seconds

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('Received SIGINT. Closing server...');
    server.close(() => {
        console.log('Server closed.');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('Received SIGTERM. Closing server...');
    server.close(() => {
        console.log('Server closed.');
        process.exit(0);
    });
});

// Start server
server.listen(port, () => {
    console.log(`Website backend running on http://localhost:${port}`);
});