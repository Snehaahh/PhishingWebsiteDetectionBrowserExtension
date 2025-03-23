// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Send URL to Flask API
    fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: tab.url })
    })
    .then(response => response.json())
    .then(data => {
      if (data.prediction === 'Phishing') {
        // Show notification for phishing sites
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: '⚠️ Phishing Warning',
          message: 'This website might be a phishing site! Proceed with caution.'
        });
      }
    })
    .catch(error => console.error('Error:', error));
  }
}); 