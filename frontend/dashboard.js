// Function to add content to a specific cell
function addToCell(day, time, content, color) {
    const cellId = `${day}-${time}`;
    const cell = document.getElementById(cellId);
    if (cell) {
        cell.innerHTML = content;
        cell.style.display = 'flex';
        cell.style.alignItems = 'center';
        cell.style.justifyContent = 'center';
        cell.style.backgroundColor = color;
    } else {
        console.error(`Cell with ID ${cellId} not found`);
    }
}

// Helper function to add an hour to a given time string in HH:MM format
function addHour(timeStr) {
    const [hours, minutes] = timeStr.split(':').map(Number);
    const newHours = (hours + 1).toString().padStart(2, '0');
    return `${newHours}:${minutes.toString().padStart(2, '0')}`;
}

// Function to handle the split time slots
function handleCourseTime(day, startTime, endTime, courseCode, color) {
    let currentStartTime = startTime;

    while (currentStartTime < endTime) {
        let nextEndTime = addHour(currentStartTime).split(':')[0] + ':30';
        if (nextEndTime > endTime) {
            nextEndTime = endTime;
        }

        const formattedTime = `${currentStartTime.replace(':', '')}---${nextEndTime.replace(':', '')}`;
        console.log(day, formattedTime);
        addToCell(day, formattedTime, courseCode, color);

        currentStartTime = addHour(currentStartTime.split(':')[0] + ':40');
    }
}

// Function to format time for display
function formatTimeDisplay(timeStr) {
    return timeStr.replace(/---/g, '-').replace(/(\d{2})(\d{2})/g, '$1:$2');
}

document.addEventListener("DOMContentLoaded", function() {
    const hoursContainer = document.querySelector(".hours");

    // Generate hours
    const hours = [
        "0840---0930", "0940---1030", "1040---1130", "1140---1230",
        "1240---1330", "1340---1430", "1440---1530", "1540---1630",
        "1640---1730", "1740---1830", "1840---1930", "1940---2030"
    ];

    const days = ["Mon", "Tue", "Wed", "Thu", "Fr"];

    // Populate hours column with formatted time
    hours.forEach(hour => {
        const hourDiv = document.createElement("div");
        hourDiv.classList.add("hour");
        hourDiv.textContent = formatTimeDisplay(hour);
        hoursContainer.appendChild(hourDiv);
    });

    // Generate schedule cells
    const scheduleGrid = document.querySelector(".schedule-grid");
    hours.forEach(hour => {
        days.forEach(day => {
            const cellDiv = document.createElement("div");
            cellDiv.classList.add("cell");
            cellDiv.id = `${day}-${hour}`;
            scheduleGrid.appendChild(cellDiv);
        });
    });

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

        // Define a list of colors
        const colors = ['red', 'green', 'blue', 'orange', 'grey'];

        // Track the color index
        let colorIndex = 0;

        // TODO for each element in data, get the day, time and content. call addToCell(day, time, content)
        if (data.recommendations.length == 0) {
            console.log("engaging recoms endpoint");
            getRecommended();
        } else {
            data.recommendations.forEach(recommendation => {
                const { course_time, course_code } = recommendation;
                const [day, time, location] = course_time.split(' ');

                const [startTime, endTime] = time.split('-');
                
                // Assign color based on the current index and increment the index
                const courseColor = colors[colorIndex % colors.length];
                colorIndex++;

                handleCourseTime(day, startTime, endTime, course_code, courseColor);
            });
        }
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
    admissionYear.textContent = "Admission Year\n" + userData.admission_year.toString().slice(0, 4);
    admissionYear.style.color = "black";
    username.textContent = userData.username;
    username.style.color = "black";

    sessionStorage.setItem("username", userData.username.toString());
}

function openSettings() {
    window.location.href = 'settings.html';
}

async function getRecommended() {
    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Authorization': `Bearer ${access_token}`
        }
    };

    try {
        const response = await fetch('http://95.214.177.119/recommend/course', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();
        console.log('Response Data:', data);
        console.log("original recommendations!!");
        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    }
}
