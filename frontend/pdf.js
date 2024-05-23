
var access_token = sessionStorage.getItem("accessToken");
console.log(access_token);
var admitYearr = "";
var coursess = [];
var degreeProgramm = "";

document.getElementById('pdf-upload').addEventListener('change', function() {
    var file = this.files[0]; // Get the selected file
    var pdfInfo = document.getElementById('pdf-info');
    var continueBtn = document.getElementById('continue-btn');

    // Check if a file is selected
    if (file) {
        // Display file information and delete button
        pdfInfo.innerHTML = '<a href="' + URL.createObjectURL(file) + '" class="file-link" target="_blank">' + file.name + '</a><button class="delete-btn" onclick="deletePdf()">Delete</button>';
        pdfInfo.style.display = 'block'; // Show the PDF info div

        // Remove previously uploaded file if exists
        var prevFile = pdfInfo.getAttribute('data-file');
        if (prevFile) {
            URL.revokeObjectURL(prevFile); // Revoke previous object URL
        }
        // Store the new file in data attribute
        pdfInfo.setAttribute('data-file', URL.createObjectURL(file));

        continueBtn.style.visibility = 'visible';

        //start reading
        var reader = new FileReader();
        reader.onload = function(event) {
            var pdfContent = event.target.result;
            console.log('PDF content:', pdfContent);

            // Use PDF.js to extract text from the PDF file
            extractTextFromPDF(pdfContent);
        };
        reader.readAsArrayBuffer(file);

    } else {
        // Hide the PDF info div if no file selected
        pdfInfo.innerHTML = '';
        pdfInfo.style.display = 'none';
        pdfInfo.removeAttribute('data-file');
    }
});

function deletePdf() {
    var pdfInfo = document.getElementById('pdf-info');
    var continueBtn = document.getElementById('continue-btn');

    pdfInfo.innerHTML = ''; // Clear the file information
    pdfInfo.style.display = 'none'; // Hide the PDF info div
    pdfInfo.removeAttribute('data-file');
    // Clear the file input field value
    document.getElementById('pdf-upload').value = '';

    continueBtn.style.visibility = 'hidden';
}


// Function to extract text from PDF
function extractTextFromPDF(pdfContent) {
    // Load the PDF document using PDF.js
    pdfjsLib.getDocument({ data: pdfContent }).promise.then(pdf => {
        // Initialize variables to store text content
        let text = '';

        // Loop through each page of the PDF
        const numPages = pdf.numPages;
        const promises = [];
        for (let pageNum = 1; pageNum <= numPages; pageNum++) {
            // Get the text content of the page
            promises.push(pdf.getPage(pageNum).then(page => {
                return page.getTextContent();
            }));
        }

        // Resolve all promises
        Promise.all(promises).then(textContents => {
            // Concatenate text content from all pages
            textContents.forEach(content => {
                content.items.forEach(item => {
                    text += item.str + ' ';
                });
            });

            // Log the extracted text
            console.log('Extracted text:', text);
            extractInfo(text);
            
            // Store the extracted text or perform other operations as needed
            sessionStorage.setItem('pdfTextContent', text);
        }).catch(error => {
            console.error('Error extracting text:', error);
        });
    }).catch(error => {
        console.error('Error loading PDF:', error);
    });
}


function continueToDashboard() {
    var pdfInput = document.getElementById('pdf-upload');
    var pdfFile = pdfInput.files[0]; // Access the selected file from the input

    if (pdfFile) {
        submitUser();
    } else {
        alert('Please upload a PDF file before continuing.');
    }
}

function extractInfo(info){

    const admitRegex = /Admit Semester\s+:\s+(Fall|Spring)\s+(\d{4})-\d{4}/;

    // Match the regular expression against the provided text
    const match = info.match(admitRegex);

    // If a match is found, adjust the admit year based on the semester
    if (match && match.length >= 3) {
        const semester = match[1];
        let year = match[2];
        
        // Adjust the year based on the semester
        if (semester === 'Fall') {
            year += '01'; // If fall, add '01' to the end of the year
        } else if (semester === 'Spring') {
            year += '02'; // If spring, add '02' to the end of the year
        }
        console.log(year);
        admitYearr = year;

        const programRegex = /Program\(s\)\s*:\s*(.*?)\s*Admit Semester/;
        const match2 = info.match(programRegex);

        if (match2 && match2.length >= 2) {
            let program = match2[1].trim();
            

            const lowercaseProgram = program.toLowerCase();

            // Define a mapping of majors to abbreviations
            const programAbbreviations = {
                "computer": "cs",
                "biology": "bio",
                "economics": "econ",
                "electric": "ee",
                "management": "man",
                "material": "mat",
                "psychology": "psy",
                // Add more majors and their abbreviations as needed
            };

            var shortProgram = "PNF";
            // Split the program name into words
            // Iterate through the program abbreviations mapping
            console.log(lowercaseProgram);
            for (const [major, abbreviation] of Object.entries(programAbbreviations)) {
                // Check if any word in the program name matches the lowercase major
                if (lowercaseProgram.includes(major)) {
                    shortProgram = abbreviation; // Return the abbreviation if found
                    break; // Exit the loop once a match is found
                }
            }
            console.log(shortProgram);
            degreeProgramm = program;

        } else {
            console.log("Program not found");
        }
    } else {
        console.log("Admit year not found");
    }

    const extractedCourses = extractCourses(info);
    coursess = extractedCourses;
    console.log(coursess);
}

function extractCourses(info) {
    // Define a regular expression to match course names and codes
    const courseRegex = /(CIP|HIST|IF|MATH|NS|PROJ|SPS|TLL|AL|CS|ECON|HUM|PSY|MAT|ORG|ENS|MGMT|CHEM|CULT|ENRG|FIN|GEN|HART|IE|LAW|LIT|ME|MFG|MKTG|OPIM|PHIL|PHYS|POLS|PSIR)\s+(\d{3,})/g;

    // Array to store extracted courses
    const courses = [];

    // Iterate over matches found in the text
    let match;
    while ((match = courseRegex.exec(info)) !== null) {
        // Extract course name and code
        const courseName = match[1];
        const courseCode = match[2];

        // Concatenate course name and code
        const course = courseName + courseCode;

        // Add course to the array
        courses.push(course);
    }

    // Return the extracted courses
    return courses;
}


async function submitUser() {

    const requestBody = {
        courses : coursess,
        admission_year: admitYearr,
        degree_program: degreeProgramm,
        double_major: "empty",
        minor : "empty"
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

    try {
        const response = await fetch('http://95.214.177.119/user/addInfo', fetchOptions);

        if (!response.ok) {
            const errorText = await response.text(); // Get the error response text
            throw new Error(`HTTP error! Status: ${response.status} Response: ${errorText}`);
        }

        const data = await response.json();

        if (data.success) {
            // Store the token in session storage
            sessionStorage.setItem('accessToken', data.access_token);
            // Redirect to the PDF page on successful login
            
            window.location.href = 'dashboard.html';
            
        } else {
            // Handle login failure
            showToast(data.message || 'upload failed. Please try again.');
        }

        return data;
    } catch (error) {
        console.error('Error:', error);
        showToast('An error occurred. Please try again.');
        throw error; // Rethrow the error to be caught by the caller if needed
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
