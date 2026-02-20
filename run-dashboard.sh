#!/bin/bash

# Kill background processes on exit
trap "kill 0" EXIT

echo "🚀 Starting Skill Scanner Dashboard..."

# Clean up stale processes on required ports
echo "🧹 Cleaning up stale processes..."
for port in 8000 5173; do
    pids=$(lsof -ti :"$port" 2>/dev/null)
    if [ -n "$pids" ]; then
        echo "   Killing processes on port $port: $pids"
        echo "$pids" | xargs kill -9 2>/dev/null
    fi
done
sleep 1

# 1. Start Backend
echo "📡 Starting Backend API (FastAPI)..."
cd dashboard/backend
./venv/bin/python3 server.py &
cd ../..

# 2. Start Frontend
echo "💻 Starting Frontend (Vite)..."
cd dashboard/frontend
npm run dev
