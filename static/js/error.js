window.onload = function() {
	const errorMessage = document.getElementById('error-message');
        if (errorMessage.textContent.trim() !== "") {
        	errorMessage.style.display = 'block'; 
                setTimeout(() => {
                    errorMessage.style.display = 'none'; 
                }, 2000); 
        }
};
