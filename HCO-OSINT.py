<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HCO OSINT Tool</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Courier New', monospace;
        }
        body {
            background-color: #0c0c0c;
            color: #00ff00;
            padding: 10px;
            line-height: 1.6;
            overflow-x: hidden;
        }
        .container {
            max-width: 100%;
            margin: 0 auto;
            padding: 10px;
        }
        .header {
            text-align: center;
            padding: 15px 0;
            border-bottom: 1px solid #333;
            margin-bottom: 20px;
        }
        h1 {
            color: #ff0000;
            font-size: 24px;
            text-shadow: 0 0 5px #ff0000;
            margin-bottom: 5px;
        }
        .subtitle {
            color: #00ffff;
            font-size: 14px;
            margin-bottom: 15px;
        }
        .countdown {
            font-size: 28px;
            color: #ff9900;
            text-align: center;
            margin: 20px 0;
            font-weight: bold;
        }
        .locked {
            background-color: #220000;
            border: 1px solid #ff0000;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            margin: 20px 0;
        }
        .options {
            display: none;
            flex-direction: column;
            gap: 10px;
            margin-top: 20px;
        }
        .option {
            padding: 12px;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            text-align: center;
            transition: all 0.3s;
        }
        .option:hover {
            transform: scale(1.02);
        }
        .option-1 { background: linear-gradient(to right, #ff0000, #990000); color: white; }
        .option-2 { background: linear-gradient(to right, #00ff00, #009900); color: black; }
        .option-3 { background: linear-gradient(to right, #0000ff, #000099); color: white; }
        .option-4 { background: linear-gradient(to right, #ffff00, #999900); color: black; }
        .option-5 { background: linear-gradient(to right, #ff00ff, #990099); color: white; }
        .option-6 { background: linear-gradient(to right, #00ffff, #009999); color: black; }
        .option-7 { background: linear-gradient(to right, #ff9900, #996600); color: black; }
        .option-8 { background: linear-gradient(to right, #9900ff, #660099); color: white; }
        .result {
            display: none;
            margin-top: 20px;
            padding: 15px;
            background-color: #001100;
            border: 1px solid #00ff00;
            border-radius: 5px;
            color: #00ff00;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }
        .typewriter {
            overflow: hidden;
            border-right: .15em solid orange;
            white-space: nowrap;
            margin: 0 auto;
            letter-spacing: .15em;
            animation: typing 3.5s steps(40, end), blink-caret .75s step-end infinite;
        }
        @keyframes typing {
            from { width: 0 }
            to { width: 100% }
        }
        @keyframes blink-caret {
            from, to { border-color: transparent }
            50% { border-color: orange; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 HCO OSINT TOOL 🔒</h1>
            <div class="subtitle">Advanced Information Gathering Tool</div>
        </div>

        <div class="locked">
            <p>⚠️ This tool is locked 🔐</p>
            <p>Subscribe to Hackers Colony Tech and click the bell icon 🔔 to unlock the tool</p>
            <p>Redirecting in <span id="countdown">10</span> seconds...</p>
        </div>

        <div class="countdown" id="countdown-display"></div>

        <div class="options" id="options">
            <div class="option option-1">📧 Email Information Gathering</div>
            <div class="option option-2">📞 Phone Number Analysis</div>
            <div class="option option-3">👤 Username Search</div>
            <div class="option option-4">🌐 Domain Information</div>
            <div class="option option-5">📱 Social Media Investigation</div>
            <div class="option option-6">📡 IP Address Tracking</div>
            <div class="option option-7">📷 Image Metadata Analysis</div>
            <div class="option option-8">🔐 Password Strength Audit</div>
        </div>

        <div class="result" id="result">
            <!-- Results will be displayed here -->
        </div>

        <div class="footer">
            HCO OSINT Tool | By Azhar | Hackers Colony
        </div>
    </div>

    <script>
        // Countdown and redirect logic
        let count = 10;
        const countdownElement = document.getElementById('countdown');
        const countdownDisplay = document.getElementById('countdown-display');
        const optionsSection = document.getElementById('options');
        const resultSection = document.getElementById('result');
        
        function updateCountdown() {
            countdownElement.textContent = count;
            countdownDisplay.textContent = count;
            
            if (count === 0) {
                // Simulate YouTube redirect
                document.body.innerHTML = `
                    <div style="background: #000; height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center;">
                        <div style="color: #f00; font-size: 24px; text-align: center; margin-bottom: 20px;">
                            Redirecting to YouTube...
                        </div>
                        <div style="color: #fff; font-size: 18px; text-align: center;">
                            Please subscribe to Hackers Colony Tech and enable notifications!
                        </div>
                    </div>
                `;
                
                // Simulate returning from YouTube after 3 seconds
                setTimeout(() => {
                    document.body.innerHTML = '';
                    document.body.style.background = '#0c0c0c';
                    document.body.innerHTML = `
                    <div class="container">
                        <div class="header">
                            <h1 class="typewriter">HCO OSINT</h1>
                            <div class="subtitle">An information gathering tool by Azhar</div>
                        </div>
                        <div class="options" id="options" style="display: flex;">
                            <div class="option option-1">📧 Email Information Gathering</div>
                            <div class="option option-2">📞 Phone Number Analysis</div>
                            <div class="option option-3">👤 Username Search</div>
                            <div class="option option-4">🌐 Domain Information</div>
                            <div class="option option-5">📱 Social Media Investigation</div>
                            <div class="option option-6">📡 IP Address Tracking</div>
                            <div class="option option-7">📷 Image Metadata Analysis</div>
                            <div class="option option-8">🔐 Password Strength Audit</div>
                        </div>
                        <div class="result" id="result"></div>
                        <div class="footer">HCO OSINT Tool | By Azhar | Hackers Colony</div>
                    </div>
                    `;
                    
                    // Reattach event listeners
                    setTimeout(attachOptionEvents, 500);
                }, 3000);
            } else {
                count--;
                setTimeout(updateCountdown, 1000);
            }
        }
        
        function attachOptionEvents() {
            const options = document.querySelectorAll('.option');
            const resultSection = document.getElementById('result');
            
            options.forEach(option => {
                option.addEventListener('click', function() {
                    resultSection.style.display = 'block';
                    
                    // Display different information based on the option selected
                    if (this.classList.contains('option-1')) {
                        resultSection.innerHTML = `<h3>📧 Email Information Gathering</h3>
                        <p>🔍 Searching for: example@email.com</p>
                        <p>✅ Breach status: Email found in 3 data breaches</p>
                        <p>📧 Service provider: Gmail</p>
                        <p>👤 Associated accounts: Twitter, Facebook, LinkedIn</p>
                        <p>📅 Creation date: Estimated 2018</p>
                        <p>📊 Reputation score: 78/100</p>
                        <p>🌍 Geo-location: United States</p>
                        <p>📨 Last activity: 3 days ago</p>`;
                    } else if (this.classList.contains('option-2')) {
                        resultSection.innerHTML = `<h3>📞 Phone Number Analysis</h3>
                        <p>🔍 Analyzing: +1 555-123-4567</p>
                        <p>📍 Carrier: Verizon Wireless</p>
                        <p>🌍 Region: California, USA</p>
                        <p>📱 Device type: Mobile</p>
                        <p>⚠️ Spam risk: Low</p>
                        <p>👤 Associated names: John Smith</p>
                        <p>📅 Number age: 4 years</p>
                        <p>📞 Call frequency: 12 calls/day average</p>`;
                    } else if (this.classList.contains('option-3')) {
                        resultSection.innerHTML = `<h3>👤 Username Search</h3>
                        <p>🔍 Investigating: hacker123</p>
                        <p>📱 Platforms found: Twitter, Instagram, GitHub</p>
                        <p>📅 Account creation: Various dates 2019-2021</p>
                        <p>🔗 Connected emails: hacker123@protonmail.com</p>
                        <p>📊 Digital footprint: Medium</p>
                        <p>👥 Relationships: 5 connected profiles</p>
                        <p>🌍 Locations: USA, UK, Canada</p>
                        <p>🛡️ Privacy score: 45/100 (Low)</p>`;
                    } else if (this.classList.contains('option-4')) {
                        resultSection.innerHTML = `<h3>🌐 Domain Information</h3>
                        <p>🔍 Analyzing: example.com</p>
                        <p>📅 Registration date: January 15, 2015</p>
                        <p>📆 Expiration date: January 15, 2025</p>
                        <p>👤 Registrant: Privacy protection service</p>
                        <p>📍 IP Address: 192.0.2.1</p>
                        <p>📊 Hosting provider: Amazon Web Services</p>
                        <p>🔒 SSL Certificate: Valid (Let's Encrypt)</p>
                        <p>🌍 Nameservers: ns1.cloudflare.com, ns2.cloudflare.com</p>
                        <p>📈 Traffic rank: 12,345 globally</p>`;
                    } else if (this.classList.contains('option-5')) {
                        resultSection.innerHTML = `<h3>📱 Social Media Investigation</h3>
                        <p>🔍 Searching across platforms</p>
                        <p>✅ Twitter: @username (1,243 tweets)</p>
                        <p>✅ Instagram: @username (587 posts)</p>
                        <p>✅ Facebook: John Smith (234 friends)</p>
                        <p>✅ LinkedIn: John Smith (Tech Industry)</p>
                        <p>📅 Account activity: High (daily posts)</p>
                        <p>📊 Sentiment analysis: Mostly positive</p>
                        <p>👥 Followers: 12.4K across platforms</p>
                        <p>📷 Most used tags: #tech, #coding, #security</p>`;
                    } else if (this.classList.contains('option-6')) {
                        resultSection.innerHTML = `<h3>📡 IP Address Tracking</h3>
                        <p>🔍 Tracking: 192.0.2.1</p>
                        <p>📍 Location: Los Angeles, California</p>
                        <p>🏢 ISP: Spectrum Business</p>
                        <p>📌 Coordinates: 34.0522° N, 118.2437° W</p>
                        <p>⚠️ Threat level: Low</p>
                        <p>📱 Device type: Router</p>
                        <p>🔗 Connected services: HTTP, HTTPS, SSH</p>
                        <p>🌐 Reverse DNS: pool-192-0-2-1.lax.example.com</p>
                        <p>📊 Abuse reports: 0 in last 90 days</p>`;
                    } else if (this.classList.contains('option-7')) {
                        resultSection.innerHTML = `<h3>📷 Image Metadata Analysis</h3>
                        <p>🔍 Analyzing: profile.jpg</p>
                        <p>📷 Camera: iPhone 12 Pro</p>
                        <p>📅 Date taken: June 15, 2022 14:32:15</p>
                        <p>📍 Location: 40.7128° N, 74.0060° W (New York)</p>
                        <p>📏 Dimensions: 4032 × 3024 pixels</p>
                        <p>📊 File size: 4.2 MB</p>
                        <p>🔍 Editing history: No modifications detected</p>
                        <p>☀️ Exposure: 1/120 sec at f/1.6, ISO 32</p>
                        <p>📸 Focal length: 5.1mm</p>`;
                    } else if (this.classList.contains('option-8')) {
                        resultSection.innerHTML = `<h3>🔐 Password Strength Audit</h3>
                        <p>🔍 Analyzing password strength</p>
                        <p>📊 Entropy: 78 bits</p>
                        <p>⏰ Crack time: 3 centuries</p>
                        <p>⚠️ Common patterns: None detected</p>
                        <p>✅ Unique characters: 14/14</p>
                        <p>🔑 Recommended: No change needed</p>
                        <p>📈 Strength: Excellent</p>
                        <p>🔓 Hash type: bcrypt</p>
                        <p>📋 Previous breaches: 0</p>`;
                    }
                });
            });
        }
        
        // Start the countdown
        updateCountdown();
    </script>
</body>
</html>
