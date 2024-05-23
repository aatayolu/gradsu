document.addEventListener("DOMContentLoaded", function() {
    const hoursContainer = document.querySelector(".hours");

    // Generate hours
    const hours = [
        "8:40 - 9:30", "9:40 - 10:30", "10:40 - 11:30", "11:40 - 12:30",
        "12:40 - 13:30", "13:40 - 14:30", "14:40 - 15:30", "15:40 - 16:30",
        "16:40 - 17:30", "17:40 - 18:30", "18:40 - 19:30", "19:40 - 20:30"
    ];

    const days = ["monday", "tuesday", "wednesday", "thursday", "friday"];

    // Populate hours column
    hours.forEach(hour => {
        const hourDiv = document.createElement("div");
        hourDiv.classList.add("hour");
        hourDiv.textContent = hour;
        hoursContainer.appendChild(hourDiv);
    });

    // Generate schedule cells
    const scheduleGrid = document.querySelector(".schedule-grid");
    hours.forEach((hour, hourIndex) => {
        days.forEach(day => {
            const cellDiv = document.createElement("div");
            cellDiv.classList.add("cell");
            cellDiv.id = `${day}-${hour.replace(/:/g, '').replace(' ', '')}`;
            scheduleGrid.appendChild(cellDiv);
        });
    });

    // Function to add content to a specific cell
    function addToCell(day, time, content) {
        const timeId = time.replace(/:/g, '').replace(' ', '');
        const cellId = `${day}-${timeId}`;
        const cell = document.getElementById(cellId);
        if (cell) {
            cell.innerHTML = content;
            cell.style.display = 'flex';
            cell.style.alignItems = 'center';
            cell.style.justifyContent = 'center';
            cell.style.backgroundColor = "green";
        } else {
            console.error(`Cell with ID ${cellId} not found`);
        }
    }

    // Example: Adding content to thursday-15:40
    addToCell('thursday', '15:40 - 16:30', 'Meeting with Team');

    // Fetch user data and set variables
    getUserData().then(data => setVars(data));
});

function showToast(msg) {
    const toast = document.createElement('div');
    toast.classList.add('toast');
    toast.textContent = msg;

    document.body.appendChild(toast);

    // Automatically remove the toast after a certain duration (e.g., 3 seconds)
    setTimeout(function() {
        toast.remove();
    }, 3000);
}


function openbanner() {
    window.open('https://bannerweb.sabanciuniv.edu/', '_blank');
}

var access_token = sessionStorage.getItem("accessToken");
console.log(access_token);

async function getUserData() {
    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Authorization': `Bearer ${access_token}`
        }
    };

    try {
        const response = await fetch('http://95.214.177.119/user/getAll', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();
        console.log('Response Data:', data);
        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    }
}

function setVars(userData) {
    var major = document.getElementById('major');
    var admissionYear = document.getElementById('admYear');
    var username = document.getElementById('username');
    major.textContent = "Major: " + userData.degree_program.toString();
    major.style.color = "black";
    admissionYear.textContent = "Admission Year\n" + userData.admission_year.toString().slice(0,4);
    admissionYear.style.color = "black";
    username.textContent = userData.username;
    username.style.color = "black";

    sessionStorage.setItem("username", userData.username.toString());
}

function openSettings(){
    window.location.href = 'settings.html';
}