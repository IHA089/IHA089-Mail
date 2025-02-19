window.onload = function() {
	const errorMessage = document.getElementById('error-message');
        if (errorMessage.textContent.trim() !== "") {
        	errorMessage.style.display = 'block'; // Show the error message
                setTimeout(() => {
                    errorMessage.style.display = 'none'; // Hide after 5 seconds
                }, 2000); // 5000 milliseconds = 5 seconds
        }
};
