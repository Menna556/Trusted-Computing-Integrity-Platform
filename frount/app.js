const API_URL = "http://127.0.0.1:8000";


// ==========================================
// Verify System
// ==========================================

async function verifySystem() {

    try {

        const response = await fetch(
            `${API_URL}/verify`,
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Verification failed.");
        }

        updateDashboard(data);

        await loadLogs();

    } catch (error) {

        alert(error.message);

    }
}


// ==========================================
// Check Access
// ==========================================

async function checkAccess() {

    try {

        const response = await fetch(
           `${API_URL}/access/check`,
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Access check failed.");
        }

        updateAccessStatus(data);

        await loadLogs();

        alert(
           `Access Decision: ${data.access_decision}`
        );

    } catch (error) {

        alert(error.message);

    }
}


// ==========================================
// Recover System
// ==========================================

async function recoverSystem() {

    const confirmed = confirm(
        "Restore the system to the trusted state?"
    );

    if (!confirmed) {
        return;
    }

    try {

        const response = await fetch(
            `${API_URL}/recover`,
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Recovery failed.");
        }

        alert(
            `Recovery completed.\nRestored files: ${data.restored_count}`
        );

        await verifySystem();

    } catch (error) {

        alert(error.message);

    }
}


// ==========================================
// Update Dashboard
// ==========================================

function updateDashboard(data) {

    document.getElementById("totalFiles").textContent =
        data.trusted_files +
        data.modified_files +
        data.missing_files;

    document.getElementById("trustedFiles").textContent =
        data.trusted_files;

    document.getElementById("modifiedFiles").textContent =
        data.modified_files;

    document.getElementById("missingFiles").textContent =
        data.missing_files;


    const statusBadge =
        document.getElementById("statusBadge");


    statusBadge.textContent =
        data.system_status;


    if (data.system_status === "TRUSTED") {

        statusBadge.className =
            "status trusted";

    } else {

        statusBadge.className =
            "status compromised";
    }


    updateFileTable(data.results);
}


// ==========================================
// Update Access Status
// ==========================================

function updateAccessStatus(data) {

    const statusBadge =
        document.getElementById("statusBadge");


    statusBadge.textContent =
        data.access_decision;


    if (data.access_decision === "GRANTED") {

        statusBadge.className =
            "status trusted";

    } else {

        statusBadge.className =
            "status compromised";
    }
}


// ==========================================
// Protected Files Table
// ==========================================

function updateFileTable(results) {

    const table =
        document.getElementById("fileTable");

    table.innerHTML = "";


    results.forEach(file => {

        const row =
            document.createElement("tr");


        let statusClass = "file-trusted";


        if (file.status === "MODIFIED") {

            statusClass = "file-modified";

        } else if (file.status === "MISSING") {

            statusClass = "file-missing";
        }
        row.innerHTML = `
            <td>${file.file_name}</td>
            <td class="${statusClass}">
                ${file.status}
            </td>
        `;


        table.appendChild(row);

    });
}


// ==========================================
// Load Security Logs
// ==========================================

async function loadLogs() {

    try {

        const response =
            await fetch(`${API_URL}/logs`);

        const data =
            await response.json();


        const logsContainer =
            document.getElementById("logs");


        if (data.logs.length === 0) {

            logsContainer.textContent =
                "No security events loaded.";

            return;
        }


        logsContainer.innerHTML = "";


        data.logs
            .slice()
            .reverse()
            .forEach(log => {

                const entry =
                    document.createElement("div");

                entry.className =
                    "log-entry";


                entry.innerHTML = `
                    <div class="log-event">
                        ${log.event}
                    </div>

                    <div>
                        ${log.message}
                    </div>

                    <div class="log-time">
                        ${log.timestamp}
                    </div>`
                ;


                logsContainer.appendChild(entry);

            });

    } catch (error) {

        console.error(
            "Could not load security logs:",
            error
        );

    }
}


// ==========================================
// Initial Dashboard Load
// ==========================================

window.addEventListener(
    "load",
    async () => {

        await verifySystem();

        await loadLogs();

    }
);