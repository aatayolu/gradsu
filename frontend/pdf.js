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
        window.location.href = 'dashboard.html'; 
    } else {
        alert('Please upload a PDF file before continuing.');
    }
}

