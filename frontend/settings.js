const access_token = sessionStorage.getItem("accessToken");
const username = sessionStorage.getItem("username");

document.getElementById('welcomeMessage').textContent = "Welcome " + username.toString();
document.getElementById('welcomeMessage').style.color = "white";

async function changePassword() {

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    const requestBody = {
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
    };

    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Authorization': `Bearer ${access_token}`
        },
        body: JSON.stringify(requestBody)
    };

    console.log('Request Body:', requestBody);
    console.log('Fetch Options:', fetchOptions);

    const spinnerOverlay = document.getElementById('spinnerOverlay');
    spinnerOverlay.style.visibility = 'visible'; // Show spinner

    try {
        const response = await fetch('http://95.214.177.119/user/changePassword', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();

        if (data.success) {
            showToast(data.message.toString());
            document.getElementById('currentPassword').value = "";
            document.getElementById('newPassword').value = "";
            document.getElementById('confirmPassword').value = "";
        } else {
            showToast(data.message || 'Upload failed. Please try again.');
        }

        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    } finally {
        spinnerOverlay.style.visibility = 'hidden'; // Hide spinner
    }
}

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

function goToDashboard(){
    window.location.href = 'dashboard.html';
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
        showToast("Returned back to original recommendations!!");
        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    }
}


async function getSpesificRecoms() {
    var coreNum = parseInt(document.getElementById('core').value, 10) || 0;
    var areaNum = parseInt(document.getElementById('area').value, 10) || 0;
    var freeNum = parseInt(document.getElementById('free').value, 10) || 0;
    var reqNum = parseInt(document.getElementById('required').value, 10) || 0;
    var basicNum = parseInt(document.getElementById('basic_science').value, 10) || 0;
    var uniNum = parseInt(document.getElementById('university').value, 10) || 0;

    const requestBody = {
        selected_courses: [], // Adjust this as needed if there are specific courses to add
        core: coreNum,
        area: areaNum,
        free: freeNum,
        required: reqNum,
        basic_science: basicNum,
        university: uniNum
    };

    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': '*/*',
            'Authorization': `Bearer ${access_token}`
        },
        body: JSON.stringify(requestBody)
    };

    try {
        console.log('Request Body:', JSON.stringify(requestBody)); // Log the request body for debugging

        const response = await fetch('http://95.214.177.119/recommend/specificCourse', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            console.error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();
        console.log('Response Data:', data);
        showToast("Recommended as you wish!!");
        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
    }
}
