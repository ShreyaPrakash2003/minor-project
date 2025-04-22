document.getElementById("myForm").addEventListener("submit", function(event) {
    event.preventDefault(); // Prevent the default form submission

    const requestData = document.getElementById("request-data").value;
    const fileInput = document.getElementById("file-upload");
    const messageDiv = document.getElementById("message");

    // Clear previous messages
    messageDiv.innerHTML = "";

    // Handle text input (send to /analyze endpoint)
    if (requestData) {
        fetch('http://localhost:5001/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                request_data: requestData
            }),
            credentials: 'include'
        })
        .then(response => {
            if (response.status === 429) {
                throw new Error("Too many requests. Your IP has been temporarily blocked.");
            }
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.status === "attack_detected") {
                messageDiv.innerHTML += `Attack Detected: ${data.type} - ${data.details}<br>`;
            } else {
                messageDiv.innerHTML += "Request is clean.<br>";
            }
        })
        .catch(error => {
            messageDiv.innerHTML += `Error analyzing request: ${error.message}<br>`;
        });
    }

    // Handle file upload (send to /upload endpoint)
    if (fileInput.files[0]) {
        const formData = new FormData();
        formData.append("file", fileInput.files[0]);

        fetch('http://localhost:5001/upload', {
            method: 'POST',
            body: formData,
            credentials: 'include'
        })
        .then(response => {
            if (response.status === 429) {
                throw new Error("Too many requests. Your IP has been temporarily blocked.");
            }
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Display a generic success message instead of the scan result
            messageDiv.innerHTML += "File uploaded successfully.<br>";
        })
        .catch(error => {
            messageDiv.innerHTML += `Error uploading file: ${error.message}<br>`;
        });
    }

    // If neither input is provided, show an error
    if (!requestData && !fileInput.files[0]) {
        messageDiv.innerHTML = "Please enter request data or select a file to upload.";
    }
});