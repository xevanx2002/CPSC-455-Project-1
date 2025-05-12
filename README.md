# Secure Chat WebSocket Server

## Live App  
Access the application here:  
**https://securechatproject.onrender.com**

## Overview  
Secure Chat is a real-time, WebSocket-based messaging application that allows users to sign up, log in, and communicate securely through a web interface. The project is fully deployed and hosted, requiring no setup or local configuration from users.

- Backend: Node.js with Express and WebSocket  
- Frontend: HTML, CSS, JavaScript  
- Database: AWS-hosted MySQL  
- Hosting: Render

## Features  
- Secure user registration and login  
- Token-based authentication system  
- Real-time WebSocket communication  
- Hosted on the cloud with no local setup required  

## Usage  
1. Visit [https://securechatproject.onrender.com](https://securechatproject.onrender.com)  
2. Create an account or log in  
3. Begin chatting securely with other users in real time  

## Troubleshooting  
If the app does not load or takes time to connect:  
- The server may be waking from idle due to Render’s free tier cold start  
- Refresh the page after a few seconds  
- Ensure that WebSockets are not being blocked by your network or browser  
