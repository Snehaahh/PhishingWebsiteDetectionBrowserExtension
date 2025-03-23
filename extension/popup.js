document.addEventListener('DOMContentLoaded', function() {
  // Get the current tab URL
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const currentUrl = tabs[0].url;
    
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
      const statusDiv = document.getElementById('status');
      const confidenceDiv = document.getElementById('confidence');
      
      // Log detailed information for debugging
      console.log('API Response:', data);
      
      // Update status based on prediction and confidence
      if (data.prediction === 'Phishing' || (data.confidence && data.confidence > 0.5)) {
        statusDiv.innerHTML = '&#9888; Warning: This website might be a phishing site!';
        statusDiv.className = 'status danger';
      } else {
        statusDiv.innerHTML = '&#10003; This website appears to be legitimate';
        statusDiv.className = 'status safe';
      }
      
      // Update confidence with improved logic
      if (data.confidence !== undefined && data.confidence !== null) {
        const confidence = (data.confidence * 100).toFixed(2);
        confidenceDiv.textContent = `Phishing Probability: ${confidence}%`;
        
        // Add color coding based on confidence
        if (confidence >= 80) {
          confidenceDiv.className = 'confidence high';
        } else if (confidence >= 60) {
          confidenceDiv.className = 'confidence medium';
        } else {
          confidenceDiv.className = 'confidence low';
        }
      } else {
        confidenceDiv.textContent = 'Confidence: Not available';
      }
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('status').innerHTML = '&#9888; Error analyzing website';
      document.getElementById('status').className = 'status danger';
    });
  });
}); 