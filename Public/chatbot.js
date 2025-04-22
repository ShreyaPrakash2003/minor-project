function sendMessage(inputValue) {
  const chatInput =
    inputValue || document.getElementById("chatInput").value.toLowerCase();
  const chatbox = document.getElementById("chatbox");
  const loading = document.getElementById("loading");

  if (!inputValue) {
    chatbox.innerHTML += `<div class="message user"><p>You: ${chatInput}</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
    document.getElementById("chatInput").value = "";
  }

  if (chatInput === "report") {
    loading.style.display = "block";
    fetch("http://localhost:8000/report", {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
    })
      .then((response) => {
        if (response.status === 401 || response.redirected) {
          window.location.href = "/login";
          return;
        }
        if (!response.ok)
          throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then((data) => {
        loading.style.display = "none";
        const attacks = data.attacks;
        if (attacks && attacks.length > 0) {
          attacks.forEach((a) => {
            const confidenceText = a.ml_confidence
              ? ` (ML Confidence: ${a.ml_confidence.toFixed(2)})`
              : "";
            chatbox.innerHTML += `<div class="message bot"><p>Attack: ${
              a.type
            } from ${a.ip} at ${a.time} - ${
              a.details || "No details"
            }${confidenceText}</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
          });
        } else {
          chatbox.innerHTML += `<div class="message bot"><p>No attacks detected.</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
        }
        chatbox.scrollTop = chatbox.scrollHeight;
        updateMap(attacks); // Update map with latest report data
      })
      .catch((error) => {
        loading.style.display = "none";
        console.error("Error fetching report:", error);
        chatbox.innerHTML += `<div class="message bot"><p>Error fetching report: ${
          error.message
        }</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
        chatbox.scrollTop = chatbox.scrollHeight;
      });
  } else if (chatInput === "exit") {
    chatbox.innerHTML += `<div class="message bot"><p>Goodbye.</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
    chatbox.scrollTop = chatbox.scrollHeight;
  } else if (chatInput === "blocked") {
    fetchBlockedIPs();
  } else {
    chatbox.innerHTML += `<div class="message bot"><p>Type 'report', 'exit', or 'blocked'.</p><span class="timestamp">${new Date().toLocaleTimeString()}</span></div>`;
    chatbox.scrollTop = chatbox.scrollHeight;
  }
}

function fetchBlockedIPs() {
  const blockedIpsDiv = document.getElementById("blocked-ips-list");
  const loading = document.getElementById("loading");
  loading.style.display = "block";
  fetch("http://localhost:8000/blocked-ips", {
    method: "GET",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  })
    .then((response) => {
      if (response.status === 401 || response.redirected) {
        window.location.href = "/login";
        return;
      }
      if (!response.ok)
        throw new Error(`HTTP error! Status: ${response.status}`);
      return response.json();
    })
    .then((data) => {
      loading.style.display = "none";
      if (
        data.status === "success" &&
        data.blocked_ips &&
        data.blocked_ips.length > 0
      ) {
        blockedIpsDiv.innerHTML = data.blocked_ips
          .map(
            (ip) => `
                <div class="blocked-ip">
                    <span>${ip.ip} (${ip.reason}, Expires: ${new Date(
              ip.expires * 1000
            ).toLocaleString()})</span>
                    <button onclick="unblockIP('${ip.ip}')">Unblock</button>
                </div>
            `
          )
          .join("");
      } else {
        blockedIpsDiv.innerHTML = "<p>No blocked IPs.</p>";
      }
    })
    .catch((error) => {
      loading.style.display = "none";
      console.error("Error fetching blocked IPs:", error);
      blockedIpsDiv.innerHTML = `<p>Error fetching blocked IPs: ${error.message}</p>`;
    });
}

function unblockIP(ip) {
  const loading = document.getElementById("loading");
  loading.style.display = "block";
  fetch("http://localhost:8000/unblock-ip", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip: ip }),
    credentials: "include",
  })
    .then((response) => {
      if (!response.ok)
        throw new Error(`HTTP error! Status: ${response.status}`);
      return response.json();
    })
    .then((data) => {
      loading.style.display = "none";
      if (data.status === "success") {
        fetchBlockedIPs();
      } else {
        alert(`Error unblocking IP: ${data.message}`);
      }
    })
    .catch((error) => {
      loading.style.display = "none";
      console.error("Error unblocking IP:", error);
      alert(`Error unblocking IP: ${error.message}`);
    });
}

function logout() {
  fetch("http://localhost:8000/logout", {
    method: "GET",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  })
    .then((response) => {
      if (!response.ok)
        throw new Error(`HTTP error! Status: ${response.status}`);
      window.location.href = "/login";
    })
    .catch((error) => {
      console.error("Error during logout:", error);
      alert("Error during logout: " + error.message);
    });
}

document
  .getElementById("modelUploadForm")
  .addEventListener("submit", function (event) {
    event.preventDefault();
    const formData = new FormData();
    const fileInput = document.querySelector('input[name="model"]');
    formData.append("model", fileInput.files[0]);
    const loading = document.getElementById("loading");
    loading.style.display = "block";
    fetch("http://localhost:5001/upload-model", {
      method: "POST",
      body: formData,
      credentials: "include",
    })
      .then((response) => {
        if (!response.ok)
          throw new Error(`HTTP error! Status: ${response.status}`);
        return response.json();
      })
      .then((data) => {
        loading.style.display = "none";
        alert(data.message);
        if (data.status === "success") {
          fileInput.value = "";
        }
      })
      .catch((error) => {
        loading.style.display = "none";
        console.error("Error uploading model:", error);
        alert(`Error uploading model: ${error.message}`);
      });
  });

function fetchModelMetrics() {
  fetch("http://localhost:5001/model-metrics", {
    method: "GET",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  })
    .then((response) => {
      if (!response.ok)
        throw new Error(`HTTP error! Status: ${response.status}`);
      return response.json();
    })
    .then((data) => {
      if (data.status === "success") {
        document.getElementById(
          "metrics"
        ).innerHTML = `Accuracy: ${data.metrics.accuracy}, F1-Score: ${data.metrics.f1_score}`;
      } else {
        document.getElementById("metrics").innerHTML = `Error: ${data.message}`;
      }
    })
    .catch((error) => {
      console.error("Error fetching model metrics:", error);
      document.getElementById("metrics").innerHTML = `Error: ${error.message}`;
    });
}

function retrainModel() {
  const loading = document.getElementById("loading");
  loading.style.display = "block";
  fetch("http://localhost:5001/retrain-model", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  })
    .then((response) => {
      if (!response.ok)
        throw new Error(`HTTP error! Status: ${response.status}`);
      return response.json();
    })
    .then((data) => {
      loading.style.display = "none";
      alert(data.message);
    })
    .catch((error) => {
      loading.style.display = "none";
      console.error("Error retraining model:", error);
      alert(`Error retraining model: ${error.message}`);
    });
}

function updateMap(attacks) {
  if (window.map) {
    window.map.eachLayer((layer) => {
      if (layer instanceof L.Marker) window.map.removeLayer(layer);
    });
    attacks.forEach((a) => {
      if (a.latitude && a.longitude) {
        L.marker([a.latitude, a.longitude])
          .addTo(window.map)
          .bindPopup(
            `IP: ${a.ip}<br>Type: ${a.type}<br>Time: ${a.time}<br>Details: ${
              a.details || "N/A"
            }`
          );
      }
    });
  }
}

window.onload = function () {
  fetchModelMetrics();
  fetch("http://localhost:8000/report", {
    method: "GET",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  })
    .then((response) => response.json())
    .then((data) => {
      updateMap(data.attacks);
    });
};
