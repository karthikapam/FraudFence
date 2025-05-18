# FraudFence
This project is an ML based system to effectively detect malicious links and messages. Unlike traditional blacklisting based systems, this project uses URL feature extraction and ML algorithms to detect phishing URLs. The project uses an integrated system of XGBoost classifier, A VirusTotal API check, NLP based textual analysis and also text extraction from images. This project effectively detects Phishing links and messages acheiving an accuracy above 90%.  
We have 3 main components:
1. URL detection: We can simply input a URL and check if it is legitimate or suspicious. In the backend, the URL is processed to extract key features and a prediction is made using XGBoost algorithm and The virustotal api check.
2. Message analysis: User can input a potentially spam message and the system uses NLP techniques to analyse the content and extract the embedded links and pushes it into the link detection module. 
3. Image detection: Instead of message or link input, user can directly paste a screenshot of the message that has been received. The OCR proccess is carried out to extract text and links and push it to the respective modules for analysis. 
The image dectection module is the key and unique enhancement in this project, that allows users to easily and effectively check for malicious links and messages. The system is a web interface made using React and Flask API. The user interface provides a simple yet effective way to collect input from user and show the status of the associated content.
What sets this project apart is its multi-modal detection capability, combining traditional input forms with image-based analysis, which is rarely seen in similar tools. By integrating OCR-based screenshot analysis, it bridges the gap where links and messages are shared as images, a common tactic used by attackers to evade detection. Moreover, the system’s use of hybrid verification—merging machine learning prediction with real-time VirusTotal API checks—adds a robust layer of validation. The modular architecture, built on React and Flask, ensures scalability and easy maintenance, while the high accuracy (above 90%) underlines the system’s reliability. This holistic approach makes the solution well-suited for real-world deployment, especially in messaging and social media environments where phishing is rampant. 





