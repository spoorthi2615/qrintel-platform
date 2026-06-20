# QRIntel Deployment Guide

This guide details the steps to compile, configure, and run the **QRIntel** platform in development and unified production single-URL deployment modes.

---

## 📋 Prerequisites

Ensure you have the following installed on your system:
* **Python 3.8+** (with `pip`)
* **Node.js 16+** (with `npm`)

---

## 🛠️ Build Instructions

Before running the application in production mode, compile the React frontend assets into a static production bundle.

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install dependencies (if not already installed):
   ```bash
   npm install
   ```
3. Run the production build command:
   ```bash
   npm run build
   ```
   *This compiles the React application and places the static assets inside `frontend/dist/`.*

---

## 🌐 Single-URL Production Deployment (Recommended)

In this mode, Flask serves both the API endpoints and the frontend production bundle as static assets from a single port (`5000`). This eliminates cross-origin request issues (CORS) and removes the dependency on the Vite development server.

### Start the Unified Application

Run the startup script from the project root:

```bash
python run_qrintel.py
```

* **Access the Application**: [http://localhost:5000](http://localhost:5000)
* **API Health Check**: [http://localhost:5000/api/health](http://localhost:5000/api/health)
* **Single Port**: Only port `5000` is used.

---

## 🧪 Development Mode (Dual URL)

For active development, run the frontend and backend servers separately to leverage Vite's hot-module replacement (HMR) and Flask's auto-reload debugging.

### 1. Start the Flask Backend
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Start the Flask development server:
   ```bash
   python app.py
   ```
   *The API will be running at [http://localhost:5000](http://localhost:5000).*

### 2. Start the Vite Frontend
1. Navigate to the frontend directory in a separate terminal:
   ```bash
   cd frontend
   ```
2. Start the Vite dev server:
   ```bash
   npm run dev
   ```
   *The frontend dashboard will be accessible at [http://localhost:5173](http://localhost:5173).*

---

## ⚙️ Configuration Notes

* **Dynamic API Paths**: The React application dynamically targets the API. In development mode (loaded via port `5173`), it targets `http://localhost:5000/api`. In production/single-port mode (loaded via port `5000`), it targets relative `/api` paths.
* **SPA Routing**: The Flask app features a catch-all route that handles React Router routing. If the user refreshes on any frontend page (e.g. `/intelligence`), Flask correctly serves the `index.html` fallback, allowing React Router to handle client-side routing.
