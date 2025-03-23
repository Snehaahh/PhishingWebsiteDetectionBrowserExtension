// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'checkURL') {
    const currentUrl = window.location.href;
    
    // Send URL to Flask API
    fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: currentUrl })
    })
    .then(response => response.json())
    .then(data => {
      if (data.prediction === 'Phishing') {
        // Add warning banner to the page
        const banner = document.createElement('div');
        banner.style.cssText = `
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          background-color: #f8d7da;
          color: #721c24;
          padding: 10px;
          text-align: center;
          z-index: 9999;
          font-family: Arial, sans-serif;
        `;
        banner.textContent = '⚠️ Warning: This website might be a phishing site! Proceed with caution.';
        document.body.insertBefore(banner, document.body.firstChild);
      }
    })
    .catch(error => console.error('Error:', error));
  }
}); 